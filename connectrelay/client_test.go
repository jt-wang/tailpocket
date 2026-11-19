package connectrelay_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log"
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jt-wang/tailpocket/connectrelay"
)

func startClientRelay(t *testing.T) *httptest.Server {
	t.Helper()
	srv, err := connectrelay.NewServer(connectrelay.Config{Token: testToken, PublicHost: "127.0.0.1", Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(func() { srv.Close(); ts.Close() })
	return ts
}

func relayURL(ts *httptest.Server) string { return "ws" + ts.URL[len("http"):] }

func waitUp(t *testing.T, l *connectrelay.HostListener) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if up, _ := l.Status(); up {
			return
		}
	}
	_, err := l.Status()
	t.Fatalf("not registered: %v", err)
}

func TestHostListenerAndPhone(t *testing.T) {
	ts := startClientRelay(t)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	l, err := connectrelay.Listen(connectrelay.HostConfig{URL: relayURL(ts), Token: testToken, Key: key})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if l.Room() != connectrelay.RoomFor(key.Public().(ed25519.PublicKey)) {
		t.Fatal("room is not the key's")
	}
	waitUp(t, l)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	phone, err := connectrelay.DialPhone(ctx, relayURL(ts), l.Room(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer phone.Close()
	host, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()

	// More than one relay message each way, in both directions, arrives whole and in order.
	big := make([]byte, 3*connectrelay.MaxMessage+5)
	rand.Read(big)
	go phone.Write(big)
	got := make([]byte, len(big))
	if _, err := io.ReadFull(host, got); err != nil || !bytes.Equal(got, big) {
		t.Fatalf("host read: %v", err)
	}
	go host.Write([]byte("back"))
	back := make([]byte, 4)
	if _, err := io.ReadFull(phone, back); err != nil || string(back) != "back" {
		t.Fatalf("phone read %q %v", back, err)
	}

	// The phone leaving ends the computer's side too.
	phone.Close()
	host.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := host.Read(make([]byte, 1)); err == nil {
		t.Fatal("host side still open after the phone left")
	}
}

func TestHostListenerRegistersAgain(t *testing.T) {
	ts := startClientRelay(t)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	registered := make(chan struct{}, 4)
	logf := func(format string, _ ...any) {
		if strings.HasPrefix(format, "connectrelay: registered") {
			registered <- struct{}{}
		}
	}
	cut := cuttable(t, ts.Listener.Addr().String())
	url := "ws://" + cut.addr
	l, _ := connectrelay.Listen(connectrelay.HostConfig{URL: url, Token: testToken, Key: key, Logf: logf})
	defer l.Close()
	for i := 0; i < 2; i++ {
		select {
		case <-registered:
		case <-time.After(10 * time.Second):
			t.Fatalf("registration %d did not happen", i+1)
		}
		if i == 0 {
			cut.cutAll() // the registration drops, as a relay restart or a network change would
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	phone, err := connectrelay.DialPhone(ctx, url, l.Room(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer phone.Close()
	if c, err := l.Accept(); err != nil {
		t.Fatal(err)
	} else {
		c.Close()
	}
}

func TestHostListenerWrongToken(t *testing.T) {
	ts := startClientRelay(t)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	l, _ := connectrelay.Listen(connectrelay.HostConfig{URL: relayURL(ts), Token: "not-the-token-at-all", Key: key})
	defer l.Close()
	time.Sleep(500 * time.Millisecond)
	if up, err := l.Status(); up || !errors.Is(err, connectrelay.ErrBadToken) {
		t.Fatalf("registered with a wrong token, or did not say why (up %v, err %v)", up, err)
	}
}

func TestHostListenerRoomTaken(t *testing.T) {
	ts := startClientRelay(t)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	first, _ := connectrelay.Listen(connectrelay.HostConfig{URL: relayURL(ts), Token: testToken, Key: key})
	defer first.Close()
	waitUp(t, first)
	second, _ := connectrelay.Listen(connectrelay.HostConfig{URL: relayURL(ts), Token: testToken, Key: key})
	defer second.Close()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if _, err := second.Status(); errors.Is(err, connectrelay.ErrRoomTaken) {
			if up, _ := first.Status(); !up {
				t.Fatal("the first computer lost its room")
			}
			return
		}
	}
	_, err := second.Status()
	t.Fatalf("second computer with the same key: %v, want room-taken", err)
}

func TestPhoneNoHostIsUnreachable(t *testing.T) {
	ts := startClientRelay(t)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := connectrelay.DialPhone(ctx, relayURL(ts), connectrelay.RoomFor(key.Public().(ed25519.PublicKey)), nil)
	if err == nil {
		_, err = c.Read(make([]byte, 1)) // 4404 arrives as a close
		c.Close()
	}
	if !errors.Is(err, connectrelay.ErrUnreachable) {
		t.Fatalf("no computer in the room: %v, want unreachable", err)
	}
}

func TestRelayURLs(t *testing.T) {
	for s, ok := range map[string]bool{
		"wss://relay.example.com": true, "wss://relay.example.com:8443/": true, "ws://127.0.0.1:9": true, "ws://localhost:9": true,
		"ws://relay.example.com": false, "https://relay.example.com": false, "wss://u:p@relay.example.com": false,
		"wss://relay.example.com/x": false, "wss://": false,
	} {
		if connectrelay.ValidURL(s) != ok {
			t.Errorf("ValidURL(%q) = %v", s, !ok)
		}
	}
}

// proxy forwards TCP to a relay and can cut every connection through it.
type proxy struct {
	addr  string
	mu    sync.Mutex
	conns []net.Conn
}

func cuttable(t *testing.T, target string) *proxy {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	p := &proxy{addr: ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			d, err := net.Dial("tcp", target)
			if err != nil {
				c.Close()
				continue
			}
			p.mu.Lock()
			p.conns = append(p.conns, c, d)
			p.mu.Unlock()
			go func() { io.Copy(d, c); d.Close() }()
			go func() { io.Copy(c, d); c.Close() }()
		}
	}()
	return p
}

func (p *proxy) cutAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		c.Close()
	}
	p.conns = nil
}
