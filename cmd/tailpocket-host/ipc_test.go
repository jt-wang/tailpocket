package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jt-wang/tailpocket/connectinvite"
	"github.com/jt-wang/tailpocket/connectphone"
	"github.com/jt-wang/tailpocket/connectrelay"
	"github.com/jt-wang/tailpocket/internal/testhook"
)

func runWith(t *testing.T, config string) (string, error) {
	t.Helper()
	var out strings.Builder
	err := Run(context.Background(), strings.NewReader(config), &out)
	return out.String(), err
}

func TestConfigErrorsAreOneFixedLine(t *testing.T) {
	cases := map[string]string{
		"":           "invalid-config",
		"not json\n": "invalid-config",
		`{"v":2,"forward":"127.0.0.1:8080"}` + "\n": "unsupported-version",
		`{"v":1}` + "\n":                                                                                                "invalid-forward",
		`{"v":1,"forward":"nowhere"}` + "\n":                                                                            "invalid-forward",
		`{"v":1,"forward":"127.0.0.1:8080","identity":"x"}` + "\n":                                                      "invalid-identity",
		`{"v":1,"forward":"127.0.0.1:8080","allowed":["nodekey:zz"]}` + "\n":                                            "invalid-allowed",
		`{"v":1,"forward":"127.0.0.1:8080","relays":[{"url":"ws://192.0.2.1","token":"t"}]}` + "\n":                     "invalid-config",
		`{"v":1,"forward":"127.0.0.1:8080","listen":["0.0.0.0:7681"]}` + "\n":                                           "invalid-config",
		`{"v":1,"forward":"127.0.0.1:8080","tailcatOnly":true,"relays":[{"url":"wss://r.example","token":"t"}]}` + "\n": "invalid-config",
		`{"v":1,"forward":"127.0.0.1:8080","tailcatOnly":true,"listen":["192.168.1.20:7681"]}` + "\n":                   "invalid-config",
		`{"v":1,"forward":"127.0.0.1:8080","relays":[{"url":"wss://r.example","token":"t","opaque":true}]}` + "\n":      "invalid-config",
		`{"v":1,"forward":"127.0.0.1:8080","routes":[]}` + "\n":                                                         "invalid-config",
		`{"v":1,"forward":"127.0.0.1:8080","routes":["relay"]}` + "\n":                                                  "invalid-config",
		`{"v":1,"forward":"127.0.0.1:8080","routes":["lan"],"tailcatOnly":true}` + "\n":                                 "invalid-config",
	}
	for config, code := range cases {
		out, err := runWith(t, config)
		if err == nil {
			t.Errorf("%q: no error", config)
		}
		if strings.Count(out, "\n") != 1 || !strings.Contains(out, `"event":"error"`) || !strings.Contains(out, `"code":"`+code+`"`) {
			t.Errorf("%q: output %q, want code %s", config, out, code)
		}
	}
}

func TestReadyWithoutPhonesAndUnknownCommand(t *testing.T) {
	in, w := io.Pipe()
	r, out := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- Run(context.Background(), in, out); out.Close() }()
	ev := events(r)
	io.WriteString(w, `{"v":1,"forward":"127.0.0.1:9"}`+"\n")
	if e := ev.next(t, "ready"); e["address"] != "" {
		t.Fatalf("ready %v", e)
	}
	io.WriteString(w, `{"cmd":"dance","id":"x"}`+"\n")
	if e := ev.next(t, "error"); e["code"] != "unknown-command" || e["id"] != "x" {
		t.Fatalf("error %v", e)
	}
	io.WriteString(w, "garbage\n")
	if e := ev.next(t, "error"); e["code"] != "invalid-command" {
		t.Fatalf("error %v", e)
	}
	w.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type eventStream struct{ ch chan map[string]any }

func events(r io.Reader) *eventStream {
	s := &eventStream{ch: make(chan map[string]any, 64)}
	go func() {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			var e map[string]any
			if json.Unmarshal(sc.Bytes(), &e) == nil {
				s.ch <- e
			}
		}
		close(s.ch)
	}()
	return s
}

func (s *eventStream) next(t *testing.T, kind string) map[string]any {
	t.Helper()
	timeout := time.After(90 * time.Second)
	for {
		select {
		case e, ok := <-s.ch:
			if !ok {
				t.Fatalf("stream ended waiting for %s", kind)
			}
			if e["event"] == kind {
				return e
			}
			if e["event"] == "error" && kind != "error" {
				t.Fatalf("error while waiting for %s: %v", kind, e)
			}
		case <-timeout:
			t.Fatalf("timed out waiting for %s", kind)
		}
	}
}

// TestLiveHelperFlow drives the helper the way a Node/Python/Swift host would: pair, save/ack,
// forward a phone's connection to a local server with the phone's key on the first line.
func TestLiveHelperFlow(t *testing.T) {
	if os.Getenv("TAILPOCKET_LIVE") != "1" {
		t.Skip("set TAILPOCKET_LIVE=1 to run over real Tailcat relays")
	}
	app, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	go func() {
		for {
			c, err := app.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	in, w := io.Pipe()
	r, out := io.Pipe()
	go func() { _ = Run(context.Background(), in, out); out.Close() }()
	defer w.Close()
	ev := events(r)
	send := func(v any) { b, _ := json.Marshal(v); _, _ = w.Write(append(b, '\n')) }
	send(map[string]any{"v": 1, "name": "helper host", "forward": app.Addr().String(), "identifyPhone": true})
	ev.next(t, "ready")
	send(map[string]any{"cmd": "pair", "id": "w1", "ttl": 120, "payload": "token-123"})
	pairing := ev.next(t, "pairing")
	inv, err := connectinvite.Decode(pairing["qr"].(string), connectinvite.DefaultPrefix)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	key := connectphone.NewKey()
	pub, _ := connectphone.PublicKey(key)
	linked := make(chan connectphone.Link, 1)
	failed := make(chan error, 1)
	go func() {
		l, err := connectphone.Pair(ctx, inv, key, connectphone.Options{Device: "helper phone"})
		if err != nil {
			failed <- err
			return
		}
		linked <- l
	}()
	save := ev.next(t, "save")
	state := save["state"].(map[string]any)
	if allowed := state["allowed"].([]any); len(allowed) != 1 || allowed[0] != pub || state["identity"] == "" {
		t.Fatalf("save %v", save)
	}
	send(map[string]any{"cmd": "saved", "id": save["id"], "ok": true})
	paired := ev.next(t, "paired")
	if paired["id"] != "w1" || paired["phone"] != pub || paired["device"] != "helper phone" {
		t.Fatalf("paired %v", paired)
	}
	var link connectphone.Link
	select {
	case link = <-linked:
	case err := <-failed:
		t.Fatal(err)
	}
	if link.Payload != "token-123" {
		t.Fatalf("payload %q", link.Payload)
	}
	s, _ := connectphone.Connect(link, connectphone.Options{})
	defer s.Close()
	var c net.Conn
	for c == nil && ctx.Err() == nil {
		dctx, dcancel := context.WithTimeout(ctx, 20*time.Second)
		c, err = s.Dial(dctx)
		dcancel()
	}
	if c == nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	br := bufio.NewReader(c)
	first, err := br.ReadString('\n')
	if err != nil || strings.TrimSpace(first) != pub {
		t.Fatalf("identify line %q %v", first, err)
	}
	io.WriteString(c, "hello\n")
	if echo, _ := br.ReadString('\n'); echo != "hello\n" {
		t.Fatalf("echo %q", echo)
	}
	send(map[string]any{"cmd": "revoke", "phone": pub})
	revSave := ev.next(t, "save")
	send(map[string]any{"cmd": "saved", "id": revSave["id"], "ok": true})
	if e := ev.next(t, "allowed"); len(e["allowed"].([]any)) != 0 || e["address"] != "" {
		t.Fatalf("allowed %v", e)
	}
}

func startRelay(t *testing.T) string {
	t.Helper()
	srv, err := connectrelay.NewServer(connectrelay.Config{Token: "relay-token", PublicHost: "127.0.0.1", Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(func() { srv.Close(); ts.Close() })
	return "ws" + strings.TrimPrefix(ts.URL, "http")
}

// answering passes events on, answering every save with ok and every authorize with allow(phone), and
// records the kinds of audit events seen.
func answering(ev *eventStream, send func(any), allow func(phone string) bool, audits *sync.Map) *eventStream {
	out := &eventStream{ch: make(chan map[string]any, 64)}
	go func() {
		defer close(out.ch)
		for e := range ev.ch {
			switch e["event"] {
			case "save":
				send(map[string]any{"cmd": "saved", "id": e["id"], "ok": true})
			case "authorize":
				phone, _ := e["phone"].(string)
				send(map[string]any{"cmd": "authorized", "id": e["id"], "ok": allow(phone)})
			case "audit":
				audits.Store(e["kind"], true)
			case "pairRequest":
				if em, _ := e["emoji"].([]any); len(em) == 4 { // the computer's user compares them
					send(map[string]any{"cmd": "confirm", "id": e["id"], "approve": true})
				}
			}
			out.ch <- e
		}
	}()
	return out
}

func TestRelayStatusWithoutPhones(t *testing.T) {
	url := startRelay(t)
	in, w := io.Pipe()
	r, out := io.Pipe()
	go func() { _ = Run(context.Background(), in, out); out.Close() }()
	defer w.Close()
	send := func(v any) { b, _ := json.Marshal(v); _, _ = w.Write(append(b, '\n')) }
	ev := answering(events(r), send, func(string) bool { return true }, &sync.Map{})
	// noLan: on a machine with a private address the default lan route would be listed too.
	send(map[string]any{"v": 1, "forward": "127.0.0.1:9", "noLan": true, "relays": []any{map[string]any{"url": url, "token": "relay-token"}}})
	ev.next(t, "ready")
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		send(map[string]any{"cmd": "status", "id": "st"})
		st := ev.next(t, "status")
		if st["relays"].(map[string]any)[url] == "up" {
			routes := st["routes"].([]any)
			if len(routes) != 1 || routes[0].(map[string]any)["t"] != "relay" || routes[0].(map[string]any)["r"] == "" {
				t.Fatalf("routes %v", routes)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("status %v", st)
		}
	}
}

// TestLiveHelperRelay pairs over a local tailpocket-relay through the helper (the pairing window
// itself is a real Tailcat node), then connects over the relay with the app authorizing and auditing.
func TestLiveHelperRelay(t *testing.T) {
	testhook.NoUpgrade.Store(true) // the phone stays on the relay this test checks
	defer testhook.NoUpgrade.Store(false)
	if os.Getenv("TAILPOCKET_LIVE") != "1" {
		t.Skip("set TAILPOCKET_LIVE=1 to run over real Tailcat relays")
	}
	url := startRelay(t)
	app, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	go func() {
		for {
			c, err := app.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	in, w := io.Pipe()
	r, out := io.Pipe()
	go func() { _ = Run(context.Background(), in, out); out.Close() }()
	defer w.Close()
	send := func(v any) { b, _ := json.Marshal(v); _, _ = w.Write(append(b, '\n')) }
	var denied, audits sync.Map
	ev := answering(events(r), send, func(p string) bool { _, no := denied.Load(p); return !no }, &audits)
	send(map[string]any{"v": 1, "name": "helper host", "forward": app.Addr().String(), "identifyPhone": true,
		"relays": []any{map[string]any{"url": url, "token": "relay-token"}}, "authorize": true, "audit": true})
	ev.next(t, "ready")
	send(map[string]any{"cmd": "pair", "id": "w1", "ttl": 120, "payload": "token-123", "emoji": true})
	pairing := ev.next(t, "pairing")
	if pairing["qr"] != nil || pairing["invite"] != nil {
		t.Fatalf("an emoji window handed out a v1 invite: %v", pairing)
	}
	inv, err := connectinvite.DecodeV2(pairing["qr2"].(string), connectinvite.DefaultPrefix2)
	if err != nil {
		t.Fatal(err)
	}
	var via []connectinvite.Route
	for _, rt := range inv.Via {
		if rt.T == connectinvite.RouteRelay {
			via = append(via, rt)
		}
	}
	inv.Via = via // pair over the relay only
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	key := connectphone.NewKey()
	pub, _ := connectphone.PublicKey(key)
	link, err := connectphone.PairV2(ctx, inv, key, connectphone.Options{OnSAS: func([]string) {}, Device: "helper phone"})
	if err != nil {
		t.Fatal(err)
	}
	if e := ev.next(t, "paired"); e["phone"] != pub {
		t.Fatalf("paired %v", e)
	}
	link.Address, link.Port = "", 0
	s, _ := connectphone.Connect(link, connectphone.Options{})
	defer s.Close()
	c, err := s.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	br := bufio.NewReader(c)
	if first, err := br.ReadString('\n'); err != nil || strings.TrimSpace(first) != pub {
		t.Fatalf("identify line %q %v", first, err)
	}
	io.WriteString(c, "hello\n")
	if echo, _ := br.ReadString('\n'); echo != "hello\n" {
		t.Fatalf("echo %q", echo)
	}
	c.Close()
	if route, _, _ := s.Path(ctx); route != "relay" {
		t.Fatalf("path %q", route)
	}
	denied.Store(pub, true)
	send(map[string]any{"cmd": "disconnect", "id": "d1", "phone": pub})
	ev.next(t, "disconnected")
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		dctx, dcancel := context.WithTimeout(ctx, 10*time.Second)
		_, err := s.Dial(dctx)
		dcancel()
		if errors.Is(err, connectphone.ErrUnauthorized) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("denied phone dials: %v", err)
		}
	}
	send(map[string]any{"cmd": "revoke", "id": "r1", "phone": pub})
	ev.next(t, "allowed")
	time.Sleep(100 * time.Millisecond)
	for _, k := range []string{"paired", "conn-open", "denied", "revoked"} {
		if _, ok := audits.Load(k); !ok {
			t.Errorf("no %s audit event", k)
		}
	}
}

// routes (v0.3.2): a helper with only a relay starts no Tailcat. Its status and invite list only the
// relay, a v1 window is refused with emoji-required, and a bad set says why in the error message.
func TestRoutesWithoutTailcat(t *testing.T) {
	out, _ := runWith(t, `{"v":1,"forward":"127.0.0.1:8080","routes":[]}`+"\n")
	if !strings.Contains(out, "Routes is empty") {
		t.Fatalf("empty routes: %s", out)
	}
	url := startRelay(t)
	in, w := io.Pipe()
	r, o := io.Pipe()
	go func() { _ = Run(context.Background(), in, o); o.Close() }()
	defer w.Close()
	send := func(v any) { b, _ := json.Marshal(v); _, _ = w.Write(append(b, '\n')) }
	ev := answering(events(r), send, func(string) bool { return true }, &sync.Map{})
	send(map[string]any{"v": 1, "forward": "127.0.0.1:9", "routes": []string{"relay"},
		"relays": []any{map[string]any{"url": url, "token": "relay-token"}}})
	if e := ev.next(t, "ready"); e["address"] != "" {
		t.Fatalf("ready %v", e)
	}
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		send(map[string]any{"cmd": "status", "id": "st"})
		st := ev.next(t, "status")
		if st["relays"].(map[string]any)[url] == "up" {
			if routes := st["routes"].([]any); len(routes) != 1 || routes[0].(map[string]any)["t"] != "relay" {
				t.Fatalf("routes %v", routes)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("status %v", st)
		}
	}
	send(map[string]any{"cmd": "pair", "id": "v1"})
	if e := ev.next(t, "error"); e["code"] != "emoji-required" || e["id"] != "v1" {
		t.Fatalf("v1 window without Tailcat: %v", e)
	}
	send(map[string]any{"cmd": "pair", "id": "v2", "emoji": true})
	e := ev.next(t, "pairing")
	via := e["invite2"].(map[string]any)["via"].([]any)
	if len(via) != 1 || via[0].(map[string]any)["t"] != "relay" {
		t.Fatalf("invite routes %v", via)
	}
}
