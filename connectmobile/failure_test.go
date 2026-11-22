package connectmobile

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jt-wang/tailpocket/connecthost"
	"github.com/jt-wang/tailpocket/connectphone"
	"github.com/jt-wang/tailpocket/connectrelay"
	"github.com/jt-wang/tailpocket/internal/testhook"
)

func init() { testhook.LoopbackRoutes = true } // the computer and phone of these tests are one machine

// A LAN-only computer (no Tailcat): Start with the given state on addr, answering "ok" over HTTP.
func lanHost(t *testing.T, addr string, st connecthost.State) (*connecthost.Host, func() connecthost.State) {
	t.Helper()
	var mu sync.Mutex
	last := st
	h, err := connecthost.New(connecthost.Config{Name: "Mac", Routes: []string{connecthost.RouteLAN}, Listen: []string{addr},
		Identity: st.Identity, Allowed: st.Allowed, Keys: st.Keys,
		Save: func(s connecthost.State) error { mu.Lock(); last = s; mu.Unlock(); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") })}
	go srv.Serve(h.Listener())
	t.Cleanup(func() { srv.Close(); _ = h.Close() })
	return h, func() connecthost.State { mu.Lock(); defer mu.Unlock(); return last }
}

type failure struct {
	Code   string `json:"code"`
	Reason string `json:"reason"`
	At     int64  `json:"at"`
	Route  string `json:"route"`
	Routes []struct {
		T string `json:"t"`
		R string `json:"r"`
	} `json:"routes"`
	Error string `json:"error"`
}

func (f failure) routes() string {
	var out []string
	for _, r := range f.Routes {
		out = append(out, r.T+":"+r.R)
	}
	return strings.Join(out, ",")
}

func lastFailure(t *testing.T, handle int64) failure {
	t.Helper()
	var f failure
	if err := json.Unmarshal([]byte(LastFailure(handle)), &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// fetch makes one request through the forward, as an app's HTTP client would.
func fetch(port int, base string) error { return fetchWithin(port, base, 20*time.Second) }

func fetchWithin(port int, base string, timeout time.Duration) error {
	c := &http.Client{Timeout: timeout, Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := c.Get("http://127.0.0.1:" + itoa(port) + base + "/")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, err = io.ReadAll(resp.Body)
	return err
}

// v0.3.4: the forward closes a connection whose dial failed without saying why, so LastFailure says it:
// unreachable while the computer is off, handshake-closed once a computer with a new identity answers
// on the same address (the phone must pair again), and nothing after a connection works again.
func TestLastFailure(t *testing.T) {
	addr := func() string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		return ln.Addr().String()
	}()
	h, _ := lanHost(t, addr, connecthost.State{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p, err := h.Pair(ctx, connecthost.PairOptions{Confirm: func(context.Context, connecthost.PairRequest) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	link, err := connectphone.PairV2(ctx, p.InviteV2(), connectphone.NewKey(), connectphone.Options{OnSAS: func([]string) {}, Routes: []string{"lan"}})
	if err != nil {
		t.Fatal(err)
	}
	_ = h.Close()

	text, _ := link.Encode()
	var opened struct {
		Handle int64  `json:"handle"`
		Port   int    `json:"port"`
		Base   string `json:"base"`
	}
	if err := json.Unmarshal([]byte(Connect(text, "")), &opened); err != nil || opened.Handle == 0 {
		t.Fatalf("connect: %v", err)
	}
	defer Stop(opened.Handle)
	if f := lastFailure(t, opened.Handle); f.Code != "" || f.Routes != nil {
		t.Fatalf("before any dial: %+v", f)
	}

	before := time.Now().UnixMilli()
	if fetch(opened.Port, opened.Base) == nil {
		t.Fatal("fetch worked with the computer off")
	}
	// Only a lan route, refused: the computer is there and not running TailPocket for this phone.
	if f := lastFailure(t, opened.Handle); f.Code != "unreachable" || f.Reason != "refused" || f.Route != "lan" ||
		f.routes() != "lan:refused" || f.At < before {
		t.Fatalf("computer off: %+v, want refused on lan", f)
	}

	_, _ = lanHost(t, addr, connecthost.State{}) // a new identity on the same address, as after a reinstall
	if fetch(opened.Port, opened.Base) == nil {
		t.Fatal("fetch worked against another computer")
	}
	if f := lastFailure(t, opened.Handle); f.Code != "handshake-closed" || f.Reason != "handshake-closed" || f.Route != "lan" {
		t.Fatalf("new identity: %+v, want handshake-closed on lan", f)
	}
	// Only a signal: the link and its pinned key stay as they were.
	if got := Link(opened.Handle); got != text {
		t.Fatalf("the link changed after handshake-closed:\n%s\n%s", got, text)
	}
}

// After a failure, a connection that works clears LastFailure.
func TestLastFailureClearsAfterSuccess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	h, state := lanHost(t, addr, connecthost.State{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p, err := h.Pair(ctx, connecthost.PairOptions{Confirm: func(context.Context, connecthost.PairRequest) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	link, err := connectphone.PairV2(ctx, p.InviteV2(), connectphone.NewKey(), connectphone.Options{OnSAS: func([]string) {}, Routes: []string{"lan"}})
	if err != nil {
		t.Fatal(err)
	}
	paired := state()
	_ = h.Close()
	text, _ := link.Encode()
	var opened struct {
		Handle int64  `json:"handle"`
		Port   int    `json:"port"`
		Base   string `json:"base"`
	}
	_ = json.Unmarshal([]byte(Connect(text, "")), &opened)
	defer Stop(opened.Handle)
	if fetch(opened.Port, opened.Base) == nil || lastFailure(t, opened.Handle).Reason != "refused" {
		t.Fatalf("computer off: %+v", lastFailure(t, opened.Handle))
	}
	lanHost(t, addr, paired) // the same computer again
	if err := fetch(opened.Port, opened.Base); err != nil {
		t.Fatalf("fetch from the computer that came back: %v", err)
	}
	if got := LastFailure(opened.Handle); got != "{}" {
		t.Fatalf("after a working connection: %s, want {}", got)
	}
	Stop(opened.Handle)
	if lastFailure(t, opened.Handle).Error != "unknown-handle" {
		t.Fatal("closed handle")
	}
}

const hostPK = "UCwaJaXCjEDB-rhHW28mR_hKMMwX_PEM5d6GMUMqNCo" // a valid key no computer here holds

// closedAddr is a loopback address nothing listens on: a dial is refused at once.
func closedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// failOnce connects a link with these routes, makes one request through the forward, and returns
// LastFailure.
func failOnce(t *testing.T, via string) failure {
	t.Helper()
	link := `{"name":"Mac","key":"` + NewKey() + `","pk":"` + hostPK + `","via":[` + via + `]}`
	var opened struct {
		Handle int64  `json:"handle"`
		Port   int    `json:"port"`
		Base   string `json:"base"`
	}
	if out := Connect(link, ""); json.Unmarshal([]byte(out), &opened) != nil || opened.Handle == 0 {
		t.Fatalf("connect: %s", out)
	}
	defer Stop(opened.Handle)
	if fetch(opened.Port, opened.Base) == nil {
		t.Fatal("fetch worked")
	}
	return lastFailure(t, opened.Handle)
}

func lanVia(addr string) string { return `{"t":"lan","a":["` + addr + `"]}` }
func relayVia(url string) string {
	return `{"t":"relay","u":"` + url + `","r":"AAAAAAAAAAAAAAAAAAAAAA"}`
}

// A real tailpocket-relay with no computer in the phone's room.
func emptyRelay(t *testing.T) string {
	t.Helper()
	srv, err := connectrelay.NewServer(connectrelay.Config{Token: "relay-token-for-tests-only", PublicHost: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return "ws" + strings.TrimPrefix(ts.URL, "http")
}

// v0.3.4: reason sorts a failure into what the user can do; routes says how each route ended.
func TestLastFailureReasons(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "relay stopping", http.StatusServiceUnavailable)
	}))
	defer down.Close()
	downURL := "ws" + strings.TrimPrefix(down.URL, "http")
	closing, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer closing.Close()
	go func() { // reads the handshake and hangs up, as a computer with another key does
		for {
			c, err := closing.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
				_, _ = io.Copy(io.Discard, c)
				c.Close()
			}()
		}
	}()
	for _, c := range []struct {
		name, via, reason, route, routes string
	}{
		// Your relay says no computer is in the room: off, not running TailPocket, or reset.
		{"relay without a computer", relayVia(emptyRelay(t)), "refused", "relay", "relay:no-host"},
		{"lan refused and relay without a computer", lanVia(closedAddr(t)) + "," + relayVia(emptyRelay(t)), "refused", "relay", "lan:refused,relay:no-host"},
		// On a plane: the relay's name does not resolve, and some device refuses the old lan address.
		// The refusal alone is no evidence about the computer: no-answer.
		{"nothing answers but a lan refusal", lanVia(closedAddr(t)) + "," + relayVia("wss://relay.invalid"), "no-answer", "relay", "lan:refused,relay:no-answer"},
		{"relay down", relayVia(downURL), "relay-down", "relay", "relay:relay-down"},
		{"relay down, lan refused", lanVia(closedAddr(t)) + "," + relayVia(downURL), "refused", "lan", "lan:refused,relay:relay-down"},
		// The route that closed the handshake decides, not the last one tried.
		{"handshake closed, relay unreachable", lanVia(closing.Addr().String()) + "," + relayVia("wss://relay.invalid"), "handshake-closed", "lan", "lan:handshake-closed,relay:no-answer"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := failOnce(t, c.via)
			if f.Reason != c.reason || f.Route != c.route || f.routes() != c.routes {
				t.Fatalf("%+v (routes %s), want %s on %s (routes %s)", f, f.routes(), c.reason, c.route, c.routes)
			}
		})
	}
}

// On a network that drops packets nothing answers and nothing refuses: the Dial must still end
// (lastRoute; before v0.3.4 it hung for as long as the forward lived) and leave no-answer, so the app
// can say the network may block the connection.
func TestLastFailureWhenTheAppGivesUp(t *testing.T) {
	testhook.LastRoute.Store(int64(time.Second))
	defer testhook.LastRoute.Store(0)
	silent, err := net.Listen("tcp", "127.0.0.1:0") // takes the connection and never answers
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	var held []net.Conn
	var mu sync.Mutex
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			c.Close()
		}
	}()
	link := `{"name":"Mac","key":"` + NewKey() + `","pk":"` + hostPK + `","via":[` + lanVia(silent.Addr().String()) + `]}`
	var opened struct {
		Handle int64  `json:"handle"`
		Port   int    `json:"port"`
		Base   string `json:"base"`
	}
	_ = json.Unmarshal([]byte(Connect(link, "")), &opened)
	defer Stop(opened.Handle)
	if fetchWithin(opened.Port, opened.Base, 3*time.Second) == nil {
		t.Fatal("fetch worked")
	}
	var f failure
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if f = lastFailure(t, opened.Handle); f.Reason != "" {
			break
		}
	}
	if f.Reason != "no-answer" || f.routes() != "lan:no-answer" {
		t.Fatalf("%+v, want no-answer on lan", f)
	}
}
