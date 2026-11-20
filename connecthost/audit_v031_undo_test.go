package connecthost

// Audit, v0.3.1 review (6a032a7). connectphone's Session.upgrade moves the phone to lan by setting
// s.last when its background probe answers. A Dial that was under way when the probe answered undoes
// the move:
//
//   - over any route, Dial ends with s.last = routeKey(r), the route it took from a list made before
//     the probe answered (this is what makes TestLiveTailcatMovesToLAN fail about one run in four);
//   - over the relay, the Dial also waits on secMu behind the probe, then finds the lan session as
//     the current one, starts a second relay session in its place, and the new lan session, which
//     has no connection yet, drains at once and closes.
//
// upgrade then does nothing for upgradeRetry (30 s), so the phone stays on the relay with lan up. Any
// app that opens a second connection soon after its first (a page with several requests) is in that
// window, which is as long as the lan handshake.
//
// The fix: Dial keeps s.last when it changed since the Dial listed its routes, and secure returns
// the live session of route r before it takes secMu.

import (
	"context"
	"testing"
	"time"

	"github.com/jt-wang/tailpocket/connectphone"
)

func TestAuditConnectionDuringTheLANProbeUndoesTheMove(t *testing.T) {
	for _, tc := range []struct {
		name   string
		during bool
	}{
		{"control: no connection during the probe", false},
		{"a connection during the probe", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probing := make(chan struct{}, 4)
			h, _, _ := newTestHost(t, Config{Relays: []Relay{{URL: startRelay(t), Token: relayToken}}, Listen: []string{freeAddr(t)},
				// The lan handshake takes 300 ms here, as it can on a real Wi-Fi.
				Authorize: func(phone, route string) error {
					if route == RouteLAN {
						probing <- struct{}{}
						time.Sleep(300 * time.Millisecond)
					}
					return nil
				}})
			waitRelay(t, h)
			serveApp(t, h)
			s, _ := pairOverRelay(t, h, &wire{}, "x")
			if _, err := get(t, s); err != nil { // the first connection goes over the relay and starts the probe
				t.Fatal(err)
			}
			select {
			case <-probing:
			case <-time.After(5 * time.Second):
				t.Fatal("control: no lan probe 5 s after the first connection")
			}
			if tc.during {
				if _, err := get(t, s); err != nil {
					t.Fatalf("second connection: %v", err)
				}
			}
			for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(50 * time.Millisecond) {
				r, err := s.Route(context.Background())
				if err == nil && r.Kind == connectphone.KindLAN {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("still on %+v %v 5 s after the lan probe answered", r, err)
				}
			}
			if _, err := get(t, s); err != nil {
				t.Fatal(err)
			}
			if r, _ := s.Route(context.Background()); r.Kind != connectphone.KindLAN {
				t.Fatalf("next connection over %+v, want lan", r)
			}
		})
	}
}
