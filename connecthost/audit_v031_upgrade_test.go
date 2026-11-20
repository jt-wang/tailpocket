package connecthost

// Audit, v0.3.1 review (6a032a7). After a Dial over the relay, connectphone's Session.upgrade probes
// the lan route in the background by starting its Noise session (Session.secure). secure holds
// secMu for the whole dial and handshake, and a Dial over the relay takes secMu before it looks for
// the live relay session. So while the lan probe waits on an address that does not answer as the
// host (the phone is away from home and something else, or nothing, is at 192.168.x.y), the next
// connection over the relay waits with it: up to upgradeTry (5 s), once per upgradeRetry (30 s).
// With v0.3.0 the second connection took milliseconds.
//
// The fix: in secure, return the live session for route r before taking secMu.

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/jt-wang/tailpocket/connectinvite"
	"github.com/jt-wang/tailpocket/connectphone"
)

func TestAuditRelayConnectionWaitsBehindTheLANProbe(t *testing.T) {
	h, _, _ := newTestHost(t, Config{Relays: []Relay{{URL: startRelay(t), Token: relayToken}}, NoLAN: true})
	waitRelay(t, h)
	serveApp(t, h)
	_, link := pairOverRelay(t, h, &wire{}, "x")

	// Where the phone is now, the host's lan address belongs to something that accepts TCP and says
	// nothing (a dropped SYN costs the same wait).
	hole, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			c, err := hole.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		hole.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			c.Close()
		}
	})
	link.Via = append(link.Via, connectinvite.Route{T: connectinvite.RouteLAN, A: []string{hole.Addr().String()}})
	s, err := connectphone.Connect(link, connectphone.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	first := time.Now()
	if _, err := get(t, s); err != nil {
		t.Fatalf("first connection: %v", err)
	}
	t.Logf("first connection over the relay: %v", time.Since(first).Round(time.Millisecond))
	if r, _ := s.Route(context.Background()); r.Kind != connectphone.KindRelay {
		t.Fatalf("control: on %+v, want the relay", r)
	}
	second := time.Now()
	if _, err := get(t, s); err != nil {
		t.Fatalf("second connection: %v", err)
	}
	if d := time.Since(second); d > time.Second {
		t.Errorf("the second connection over the relay took %v: it waited for the background lan probe", d.Round(100*time.Millisecond))
	}
}
