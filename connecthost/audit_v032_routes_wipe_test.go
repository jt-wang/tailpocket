package connecthost

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jt-wang/tailpocket/connectphone"
)

// Audit v0.3.2 (42d9679), finding 1. A host without Tailcat can have no route at all for a moment: the
// automatic lan route while the computer's Wi-Fi address is gone, with no relay configured. It then
// tells its phones "routes: []". A phone paired without Tailcat has nothing but those routes, so
// taking the empty list leaves it a Link that no longer validates (Encode fails, ParseLink refuses
// it) and a Session with nothing to dial: when the address comes back a moment later the phone has
// forgotten it and must pair again. Before v0.3.2 the list always had the Tailcat route.
//
// The phone must keep the routes it has when the host sends a list that would leave it none.
func TestAuditV032EmptyRoutesDoNotWipeTheLink(t *testing.T) {
	var up atomic.Bool
	up.Store(true)
	withLANAddrs(t, func() []netip.Addr {
		if up.Load() {
			return []netip.Addr{loopback}
		}
		return nil
	})
	h, f, _ := newTestHost(t, Config{Routes: []string{RouteLAN}})
	serveApp(t, h)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p, err := h.Pair(ctx, PairOptions{Confirm: confirmAll})
	if err != nil {
		t.Fatal(err)
	}
	links := make(chan connectphone.Link, 16)
	opts := connectphone.Options{OnSAS: func([]string) {}, Routes: []string{RouteLAN}, OnLink: func(l connectphone.Link) { links <- l }}
	link, err := connectphone.PairV2(ctx, p.InviteV2(), connectphone.NewKey(), opts)
	if err != nil {
		t.Fatalf("pair over the automatic lan route: %v", err)
	}
	if len(link.Via) != 1 || link.Address != "" {
		t.Fatalf("link %+v", link)
	}
	s, err := connectphone.Connect(link, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := get(t, s); err != nil {
		t.Fatalf("over lan: %v", err)
	}

	// The computer's address goes away: the host closes its listener and pushes its routes, now none.
	// The open session (a TCP connection that outlives the listener) still delivers them.
	up.Store(false)
	for deadline := time.Now().Add(5 * time.Second); len(h.Routes()) != 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("host still lists %v", h.Routes())
		}
	}
	time.Sleep(300 * time.Millisecond) // the push reaches the phone
	for done := false; !done; {
		select {
		case l := <-links:
			if _, err := l.Encode(); err != nil {
				t.Errorf("OnLink handed the app a link that cannot be stored: %v (via %v)", err, l.Via)
			}
		default:
			done = true
		}
	}
	if got := s.Link(); len(got.Via) == 0 {
		t.Errorf("the phone forgot its only route: link %+v", got)
	}
	if _, err := s.Link().Encode(); err != nil {
		t.Errorf("Session.Link no longer encodes: %v", err)
	}

	// The address is back (same Wi-Fi, same port): a phone that kept its route connects again, also
	// from what it stored. One that took the empty list is locked out until it pairs again.
	up.Store(true)
	for deadline := time.Now().Add(5 * time.Second); len(h.Routes()) != 1; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("host lists %v", h.Routes())
		}
	}
	stored, err := s.Link().Encode()
	if err != nil {
		t.Fatalf("nothing to store: %v", err)
	}
	s.Close()
	again, err := connectphone.ParseLink(stored)
	if err != nil {
		t.Fatalf("the stored link: %v", err)
	}
	s2, err := connectphone.Connect(again, connectphone.Options{Routes: []string{RouteLAN}})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if _, err := get(t, s2); err != nil {
		t.Fatalf("after the address came back: %v", err)
	}
	if len(f.nodes) != 0 {
		t.Fatalf("%d Tailcat nodes", len(f.nodes))
	}
}
