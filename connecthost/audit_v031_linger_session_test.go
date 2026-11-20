package connecthost

// Audit, v0.3.1 re-review (df39694). The fix for the lingering node (restartMain drops the removed
// phones from byIP before it sleeps byeLinger) covers Tailcat only. The removed phone's Noise key
// stays in h.noise and its encrypted sessions stay in h.sessions until after the sleep and the node
// restart, so for those 3 s the removed phone still reaches the app over tailpocket-relay or lan: on
// the session it has, and on a new one. SetAllowed has closed its connections by then, and
// docs/SECURITY.md (section 5, added in df39694) says revoking "ends its access at once".
//
// Before b8b0274 (v0.3.0) restartMain did not sleep, so this window was only as long as the node's
// restart; with the fake node of these tests that is nothing, and the test passes on eb2af73.
//
// The fix: in the h.mu section that takes the removed phones' connections, also delete their keys
// from h.noise and take their sessions (revokeSessions after the unlock), and put the keys back on
// the paths that restore byIP.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jt-wang/tailpocket/connectphone"
)

func TestAuditRemovedPhoneKeepsItsRelaySessionWhileTheNodeLingers(t *testing.T) {
	_, b := phoneKey(t)
	h, f, _ := newTestHost(t, Config{Allowed: []string{b}, Relays: []Relay{{URL: startRelay(t), Token: relayToken}}, NoLAN: true})
	waitRelay(t, h)
	serveApp(t, h)
	w := &wire{}
	s, link := pairOverRelay(t, h, w, "x")
	a, _ := connectphone.PublicKey(link.Key)
	if body, err := get(t, s); err != nil || !strings.Contains(body, a) {
		t.Fatalf("control: before the removal: %q %v", body, err)
	}
	// The phone also holds a Tailcat connection, which is what makes restartMain linger.
	tailcat := f.live(DefaultPort).dial(t, a)
	if tailcat == nil {
		t.Fatal("control: no Tailcat connection for the paired phone")
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		h.mu.Lock()
		n := 0
		for c := range h.conns {
			if c.Phone == a && c.Route == RouteTailcat {
				n++
			}
		}
		h.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("control: the host does not hold the phone's Tailcat connection")
		}
	}

	start := time.Now()
	done := make(chan error, 1)
	go func() { done <- h.SetAllowed(context.Background(), []string{b}) }()
	if !closedByHost(tailcat) {
		t.Fatal("control: the removed phone's Tailcat connection was not closed")
	}
	// Removed, and its connections closed. Half a second later (v0.3.0 revoked the sessions right
	// after it closed the connections), its next requests over the relay.
	time.Sleep(500 * time.Millisecond)
	for _, what := range []string{"on the session it has", "on a new session"} {
		if what == "on a new session" {
			s2, err := connectphone.Connect(link2(link), connectphone.Options{HTTPClient: w.client()})
			if err != nil {
				t.Fatal(err)
			}
			defer s2.Close()
			s = s2
		}
		if body, err := get(t, s); err == nil && strings.Contains(body, a) {
			t.Errorf("%v after SetAllowed closed the removed phone's connections, the app answered it over the relay %s",
				time.Since(start).Round(100*time.Millisecond), what)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := get(t, s); err == nil {
		t.Fatal("control: the removed phone still connects after SetAllowed returned")
	}
}

// link2 is link without its Tailcat address, as pairOverRelay's session uses it.
func link2(link connectphone.Link) connectphone.Link {
	link.Address, link.Port = "", 0
	return link
}
