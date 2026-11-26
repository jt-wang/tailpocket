package connecthost

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jt-wang/tailpocket/connectphone"
	"github.com/jt-wang/tailpocket/connectpush"
)

// fakeGateway records /v1/send and answers with status.
type fakeGateway struct {
	mu     sync.Mutex
	sends  []map[string]string
	status int
	ts     *httptest.Server
}

func newFakeGateway(t *testing.T) *fakeGateway {
	g := &fakeGateway{status: http.StatusAccepted}
	g.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]string
		json.Unmarshal(b, &m)
		g.mu.Lock()
		defer g.mu.Unlock()
		if r.URL.Path != "/v1/send" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		g.sends = append(g.sends, m)
		w.WriteHeader(g.status)
		if g.status == http.StatusForbidden {
			io.WriteString(w, `{"error":"revoked"}`)
		}
	}))
	t.Cleanup(g.ts.Close)
	return g
}

func (g *fakeGateway) count() int { g.mu.Lock(); defer g.mu.Unlock(); return len(g.sends) }
func (g *fakeGateway) last() map[string]string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.sends[len(g.sends)-1]
}
func (g *fakeGateway) set(status int) { g.mu.Lock(); g.status = status; g.mu.Unlock() }

var testPushKey = [32]byte{9, 8, 7, 6, 5, 4, 3, 2, 1}

func target(gateway string) connectpush.Target {
	return connectpush.Target{Gateway: gateway, App: "io.example.alpha", Handle: "HANDLE-" + strings.Repeat("h", 30),
		Kid: "kid-1", Key: base64.RawURLEncoding.EncodeToString(testPushKey[:])}
}

// openNote opens what the gateway got, as the phone would; last is the phone's highest seq.
func openNote(t *testing.T, ct string, last uint64) (connectpush.Note, error) {
	t.Helper()
	n, _, err := connectpush.Open(func(kid string) ([32]byte, bool) { return testPushKey, kid == "kid-1" },
		"io.example.alpha", ct, time.Now(), func(string) uint64 { return last })
	return n, err
}

func postPush(t *testing.T, n *fakeNode, phone string, body any) (int, string) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, "http://control.invalid/v2/push", bytes.NewReader(b))
	resp, err := controlClient(n, phone).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

func TestPushOverTailcat(t *testing.T) {
	gw := newFakeGateway(t)
	_, phone := phoneKey(t)
	_, other := phoneKey(t)
	h, f, saved := newTestHost(t, Config{Allowed: []string{phone, other}, PushGateways: []string{gw.ts.URL + "/"}})
	main := f.live(DefaultPort)
	ctx := context.Background()

	if err := h.Push(ctx, phone, connectpush.Note{Body: "x"}, connectpush.SendOptions{}); !errors.Is(err, ErrNoPushTarget) {
		t.Fatalf("no target: %v", err)
	}
	// Refused targets change nothing.
	saves := len(saved.states)
	evil := target("https://evil.example")
	for _, c := range []struct {
		body any
		want string
	}{
		{map[string]any{"target": evil}, "gateway-not-allowed"},
		{map[string]any{"target": target("http://example.com")}, "invalid"},
		{map[string]any{"target": connectpush.Target{Gateway: gw.ts.URL}}, "invalid"},
		{map[string]any{"target": target(gw.ts.URL), "clear": true}, "invalid"},
		{map[string]any{}, "invalid"},
	} {
		if code, body := postPush(t, main, phone, c.body); code != http.StatusBadRequest || !strings.Contains(body, c.want) {
			t.Fatalf("%v: %d %s", c.body, code, body)
		}
	}
	if len(saved.states) != saves || gw.count() != 0 {
		t.Fatal("a refused target was saved or used")
	}
	// A stranger gets nothing.
	_, stranger := phoneKey(t)
	b, _ := json.Marshal(map[string]any{"target": target(gw.ts.URL)})
	req, _ := http.NewRequest(http.MethodPost, "http://control.invalid/v2/push", bytes.NewReader(b))
	if resp, err := controlClient(main, stranger).Do(req); err == nil && resp.StatusCode == http.StatusOK {
		t.Fatal("a phone not paired gave a target")
	}

	if code, body := postPush(t, main, phone, map[string]any{"target": target(gw.ts.URL)}); code != 200 || !strings.Contains(body, `"ok":true`) {
		t.Fatalf("give: %d %s", code, body)
	}
	if st := saved.last(); st.Push[phone].Handle != target(gw.ts.URL).Handle || st.Push[other].Handle != "" {
		t.Fatalf("saved %+v", st.Push)
	}
	for i := 1; i <= 3; i++ {
		if err := h.Push(ctx, phone, connectpush.Note{Title: "T", Body: "secret body"}, connectpush.SendOptions{Collapse: "c"}); err != nil {
			t.Fatal(err)
		}
		m := gw.last()
		if m["handle"] != target(gw.ts.URL).Handle || m["collapse"] != "c" || strings.Contains(m["ct"], "secret") {
			t.Fatalf("send %v", m)
		}
		n, err := openNote(t, m["ct"], uint64(i-1))
		if err != nil || n.Seq != uint64(i) || n.Body != "secret body" || n.Sent == 0 {
			t.Fatalf("push %d opened %+v %v", i, n, err)
		}
		if saved.last().Push[phone].Seq != uint64(i) {
			t.Fatalf("seq %d not saved", i)
		}
	}

	// The seq is saved before the send: a failed save sends nothing.
	saved.mu.Lock()
	saved.fail = true
	saved.mu.Unlock()
	if err := h.Push(ctx, phone, connectpush.Note{Body: "x"}, connectpush.SendOptions{}); err == nil || gw.count() != 3 {
		t.Fatalf("push with a failing save: %v, %d sends", err, gw.count())
	}
	saved.mu.Lock()
	saved.fail = false
	saved.mu.Unlock()

	// A restart keeps the target and the seq.
	h2, _, _ := newTestHost(t, Config{Identity: saved.last().Identity, Allowed: saved.last().Allowed, Push: saved.last().Push,
		PushGateways: []string{gw.ts.URL}})
	if err := h2.Push(ctx, phone, connectpush.Note{Body: "x"}, connectpush.SendOptions{}); err != nil {
		t.Fatal(err)
	}
	if n, err := openNote(t, gw.last()["ct"], 3); err != nil || n.Seq != 4 {
		t.Fatalf("after restart %+v %v", n, err)
	}
	// A restart that no longer lists the gateway drops the target.
	h3, _, _ := newTestHost(t, Config{Identity: saved.last().Identity, Allowed: saved.last().Allowed, Push: saved.last().Push,
		PushGateways: []string{"https://other.example"}})
	if h3.HasPush(phone) {
		t.Fatal("a target for a gateway no longer configured was kept")
	}

	// 410 drops the target.
	gw.set(http.StatusGone)
	if err := h.Push(ctx, phone, connectpush.Note{Body: "x"}, connectpush.SendOptions{}); !errors.Is(err, ErrPushGone) {
		t.Fatalf("410: %v", err)
	}
	if h.HasPush(phone) || saved.last().Push[phone].Handle != "" {
		t.Fatal("target kept after 410")
	}
	if err := h.Push(ctx, phone, connectpush.Note{Body: "x"}, connectpush.SendOptions{}); !errors.Is(err, ErrNoPushTarget) {
		t.Fatalf("after 410: %v", err)
	}
	// 403 (expired, revoked) drops it too; 429 does not.
	postPush(t, main, phone, map[string]any{"target": target(gw.ts.URL)})
	gw.set(http.StatusTooManyRequests)
	var ge *connectpush.Error
	if err := h.Push(ctx, phone, connectpush.Note{Body: "x"}, connectpush.SendOptions{}); !errors.As(err, &ge) || ge.Status != 429 || !h.HasPush(phone) {
		t.Fatalf("429: %v", err)
	}
	gw.set(http.StatusForbidden)
	if err := h.Push(ctx, phone, connectpush.Note{Body: "x"}, connectpush.SendOptions{}); !errors.Is(err, ErrPushGone) || h.HasPush(phone) {
		t.Fatalf("403: %v", err)
	}
	gw.set(http.StatusAccepted)

	// clear, then Revoke and SetAllowed forget it.
	postPush(t, main, phone, map[string]any{"target": target(gw.ts.URL)})
	if code, _ := postPush(t, main, phone, map[string]any{"clear": true}); code != 200 || h.HasPush(phone) {
		t.Fatal("clear")
	}
	postPush(t, main, phone, map[string]any{"target": target(gw.ts.URL)})
	postPush(t, main, other, map[string]any{"target": target(gw.ts.URL)})
	if err := h.Revoke(ctx, phone); err != nil {
		t.Fatal(err)
	}
	if h.HasPush(phone) || saved.last().Push[phone].Handle != "" || !h.HasPush(other) {
		t.Fatalf("after Revoke: %+v", saved.last().Push)
	}
	if err := h.SetAllowed(ctx, []string{}); err != nil {
		t.Fatal(err)
	}
	if h.HasPush(other) || len(saved.last().Push) != 0 {
		t.Fatalf("after SetAllowed: %+v", saved.last().Push)
	}
}

func TestPushOffRefusesTargets(t *testing.T) {
	_, phone := phoneKey(t)
	h, f, _ := newTestHost(t, Config{Allowed: []string{phone}})
	if code, body := postPush(t, f.live(DefaultPort), phone, map[string]any{"target": target("https://push.example.com")}); code != 400 || !strings.Contains(body, "push-off") {
		t.Fatalf("%d %s", code, body)
	}
	if h.HasPush(phone) {
		t.Fatal("kept")
	}
	if _, err := New(Config{Save: func(State) error { return nil }, PushGateways: []string{"http://push.example.com"}}); err == nil {
		t.Fatal("a plain http gateway off loopback was taken")
	}
}

// Over the relay the target goes on the encrypted session's control stream, and the relay never sees it.
func TestPushOverEncryptedSession(t *testing.T) {
	gw := newFakeGateway(t)
	url := startRelay(t)
	h, _, saved := newTestHost(t, Config{Relays: []Relay{{URL: url, Token: relayToken}}, PushGateways: []string{gw.ts.URL}})
	waitRelay(t, h)
	serveApp(t, h)
	w := &wire{}
	s, link := pairOverRelay(t, h, w, "x")
	pub, _ := connectphone.PublicKey(link.Key)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var refused *connectphone.PushRefusedError
	if err := s.GivePush(ctx, target("https://evil.example")); !errors.As(err, &refused) || refused.Code != "gateway-not-allowed" {
		t.Fatalf("other gateway: %v", err)
	}
	tg := target(gw.ts.URL)
	if err := s.GivePush(ctx, tg); err != nil {
		t.Fatal(err)
	}
	if !h.HasPush(pub) || saved.last().Push[pub].Kid != "kid-1" {
		t.Fatal("target not stored")
	}
	if w.has(tg.Key) || w.has(tg.Handle) {
		t.Fatal("the relay saw the push target")
	}
	if err := h.Push(ctx, pub, connectpush.Note{Body: "hello"}, connectpush.SendOptions{}); err != nil {
		t.Fatal(err)
	}
	if n, err := openNote(t, gw.last()["ct"], 0); err != nil || n.Body != "hello" {
		t.Fatalf("%+v %v", n, err)
	}
	if err := s.ClearPush(ctx); err != nil || h.HasPush(pub) {
		t.Fatalf("clear: %v", err)
	}
	// The session still carries the app's streams.
	if _, err := get(t, s); err != nil {
		t.Fatal(err)
	}
}

// The host dials the configured gateway, never the phone's spelling of it: a phone's
// "https://PUSH.Example.TEST/" matches "https://push.example.test" and is stored as that.
func TestPushDialsTheConfiguredGateway(t *testing.T) {
	var mu sync.Mutex
	var dialed []string
	hc := &http.Client{Transport: &http.Transport{DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
		mu.Lock()
		dialed = append(dialed, addr)
		mu.Unlock()
		return nil, errors.New("no network in this test")
	}}}
	_, phone := phoneKey(t)
	h, f, _ := newTestHost(t, Config{Allowed: []string{phone}, PushGateways: []string{"https://push.example.test"}, PushClient: hc})
	if code, body := postPush(t, f.live(DefaultPort), phone, map[string]any{"target": target("https://PUSH.Example.TEST/")}); code != http.StatusOK {
		t.Fatalf("give: %d %s", code, body)
	}
	_ = h.Push(context.Background(), phone, connectpush.Note{Body: "x"}, connectpush.SendOptions{})
	mu.Lock()
	defer mu.Unlock()
	if len(dialed) == 0 || slices.ContainsFunc(dialed, func(a string) bool { return a != "push.example.test:443" }) {
		t.Fatalf("dialed %v, want push.example.test:443 only", dialed)
	}
}
