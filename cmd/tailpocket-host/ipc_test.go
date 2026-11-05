package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jt-wang/tailpocket/connectinvite"
	"github.com/jt-wang/tailpocket/connectphone"
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
		`{"v":1}` + "\n":                                                     "invalid-forward",
		`{"v":1,"forward":"nowhere"}` + "\n":                                 "invalid-forward",
		`{"v":1,"forward":"127.0.0.1:8080","identity":"x"}` + "\n":           "invalid-identity",
		`{"v":1,"forward":"127.0.0.1:8080","allowed":["nodekey:zz"]}` + "\n": "invalid-allowed",
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
