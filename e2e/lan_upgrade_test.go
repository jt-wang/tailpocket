package e2e

// A phone on the computer's network that first reaches it over Tailcat moves to the host's lan
// listener for its next connections (connectphone Session.upgrade, v0.3.1), and Route names each
// kind exactly. Before v0.3.1 the route that worked last was always tried first, so a Tailcat
// success through DERP kept the phone off lan for good.

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/jt-wang/tailpocket/connecthost"
	"github.com/jt-wang/tailpocket/connectphone"
)

func TestLiveTailcatMovesToLAN(t *testing.T) {
	live(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	lanAddr := ln.Addr().String()
	ln.Close()
	var mu sync.Mutex
	var routes []string
	st := &store{}
	h, err := connecthost.New(connecthost.Config{Name: "lan upgrade", Save: st.save, Listen: []string{lanAddr}})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if err := h.Start(ctx); err != nil {
		t.Fatal(err)
	}
	go func() { // serveEcho that records the route of every connection
		for {
			c, err := h.Listener().Accept()
			if err != nil {
				return
			}
			if pc, ok := c.(*connecthost.Conn); ok {
				mu.Lock()
				routes = append(routes, pc.Route)
				mu.Unlock()
			}
			go func() {
				defer c.Close()
				_, _ = io.WriteString(c, connecthost.PhoneOf(c)+"\n")
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	p, err := h.Pair(ctx, connecthost.PairOptions{Confirm: func(context.Context, connecthost.PairRequest) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	phoneKey := connectphone.NewKey()
	phonePub, _ := connectphone.PublicKey(phoneKey)
	// Pair over Tailcat only, so the session's first route is Tailcat.
	link, err := connectphone.PairV2(ctx, p.InviteV2(), phoneKey, connectphone.Options{Device: "lan upgrade", TailcatOnly: true, OnSAS: func([]string) {}})
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	p.Close()
	if s, err := connectphone.Connect(link, connectphone.Options{}); err != nil {
		t.Fatal(err)
	} else {
		if _, err := s.Sync(ctx); err != nil { // registers the Noise key and takes the lan route
			t.Fatalf("sync: %v", err)
		}
		link = s.Link()
		s.Close()
	}

	s, err := connectphone.Connect(link, connectphone.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	roundTrip(t, ctx, s.Dial, phonePub)
	first, err := s.Route(ctx)
	t.Logf("first connection: %+v %v", first, err)
	if first.Kind != connectphone.KindDirect && first.Kind != connectphone.KindDERP && first.Kind != connectphone.KindLAN {
		t.Fatalf("first route %+v %v", first, err)
	}
	if first.Kind == connectphone.KindDERP && first.DERPRegion == 0 {
		t.Errorf("derp route without its region: %+v", first)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		roundTrip(t, ctx, s.Dial, phonePub)
		r, err := s.Route(ctx)
		if err == nil && r.Kind == connectphone.KindLAN {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("still on %+v %v 15 s after Tailcat worked, with the lan listener up", r, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
	roundTrip(t, ctx, s.Dial, phonePub)
	mu.Lock()
	got := append([]string(nil), routes...)
	mu.Unlock()
	t.Logf("host saw connections over %v", got)
	if len(got) < 2 || got[0] != connecthost.RouteTailcat || got[len(got)-1] != connecthost.RouteLAN {
		t.Fatalf("host saw %v, want Tailcat first and lan last", got)
	}
}
