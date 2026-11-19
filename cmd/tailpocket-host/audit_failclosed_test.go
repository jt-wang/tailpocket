package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/jt-wang/tailpocket/connectrelay"
)

// Audit (fail closed), O1 through the helper: with an opaque relay, "authorize": true and
// "identifyPhone": true, a stranger who knows only the relay URL and the room is forwarded to the
// app's port. The helper asks the app nothing (no authorize event) and the identity line it writes
// first is empty. An app that reads that line as "which paired phone is this" gets "" for someone
// who never paired.
func TestAuditHelperForwardsStrangerOnOpaqueRelay(t *testing.T) {
	t.Run("denied", func(t *testing.T) { opaqueThroughHelper(t, false) })
	t.Run("allowed says opaque", func(t *testing.T) { opaqueThroughHelper(t, true) })
}

func opaqueThroughHelper(t *testing.T, allow bool) {
	url := startRelay(t)
	app, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	type seen struct{ identity, first string }
	got := make(chan seen, 1)
	go func() {
		c, err := app.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		br := bufio.NewReader(c)
		id, _ := br.ReadString('\n')
		line, _ := br.ReadString('\n')
		got <- seen{id, line}
	}()
	in, w := io.Pipe()
	r, out := io.Pipe()
	go func() { _ = Run(context.Background(), in, out); out.Close() }()
	defer w.Close()
	send := func(v any) { b, _ := json.Marshal(v); _, _ = w.Write(append(b, '\n')) }
	var asked sync.Map
	ev := answering(events(r), send, func(p string) bool { asked.Store(p, true); return allow }, &sync.Map{})
	send(map[string]any{"v": 1, "forward": app.Addr().String(), "identifyPhone": true, "authorize": true, "audit": true,
		"relays": []any{map[string]any{"url": url, "token": "relay-token", "opaque": true, "appAuth": true}}})
	ev.next(t, "ready")
	room := ""
	for deadline := time.Now().Add(10 * time.Second); room == ""; time.Sleep(50 * time.Millisecond) {
		send(map[string]any{"cmd": "status", "id": "st"})
		st := ev.next(t, "status")
		if st["relays"].(map[string]any)[url] == "up" {
			room, _ = st["routes"].([]any)[0].(map[string]any)["r"].(string)
		}
		if time.Now().After(deadline) {
			t.Fatalf("status %v", st)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := connectrelay.DialPhone(ctx, url, room, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "DELETE /everything\n")
	select {
	case s := <-got:
		if allow {
			if s.identity != "opaque\n" || s.first != "DELETE /everything\n" {
				t.Fatalf("identity %q, first %q", s.identity, s.first)
			}
			return
		}
		n := 0
		asked.Range(func(_, _ any) bool { n++; return true })
		t.Fatalf("the app's port got identity line %q, then %q, from a stranger; the helper sent %d authorize events", s.identity, s.first, n)
	case <-time.After(2 * time.Second):
		if allow {
			t.Fatal("control: an allowed opaque connection never reached the app")
		}
	}
	if _, ok := asked.Load("opaque"); !ok {
		t.Fatal("the helper never asked the app about the opaque connection (as phone \"opaque\")")
	}
}
