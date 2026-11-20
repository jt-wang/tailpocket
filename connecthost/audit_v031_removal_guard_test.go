package connecthost

// Audit, v0.3.1 re-review (1d0b52c). Two guards for lines of the V4 fix (c702a8d) that no test fails
// without. Both pass on 1d0b52c.
//
//   - restartMain revokes the removed phones' encrypted sessions before it lingers. Without that
//     line the app is still safe (the next stream finds no Noise key), but the phone hears no
//     "unpaired" until the node has restarted: during the linger it gets "denied" instead.
//   - When the save fails, SetAllowed changes nothing, so restartMain puts back the Noise keys it
//     cut. Without that the host lists a phone that can no longer use the relay or lan, and cannot
//     pair over them again either (paired-without-this-key).

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jt-wang/tailpocket/connectphone"
)

func TestAuditRemovedPhoneHearsUnpairedWhileTheNodeLingers(t *testing.T) {
	_, b := phoneKey(t)
	h, f, _ := newTestHost(t, Config{Allowed: []string{b}, Relays: []Relay{{URL: startRelay(t), Token: relayToken}}, NoLAN: true})
	waitRelay(t, h)
	serveApp(t, h)
	s, link := pairOverRelay(t, h, &wire{}, "x")
	a, _ := connectphone.PublicKey(link.Key)
	if body, err := get(t, s); err != nil || !strings.Contains(body, a) {
		t.Fatalf("control: before the removal: %q %v", body, err)
	}
	tailcat := f.live(DefaultPort).dial(t, a) // what makes restartMain linger
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
	time.Sleep(500 * time.Millisecond)
	_, err := get(t, s)
	if took := time.Since(start); took > byeLinger {
		t.Fatalf("control: asked %v after the removal, later than the linger", took)
	}
	if !errors.Is(err, connectphone.ErrRevoked) {
		t.Errorf("while the node lingers the removed phone's next connection ends with %v, want ErrRevoked (bye unpaired)", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestAuditFailedRemovalKeepsThePhonesKey(t *testing.T) {
	_, b := phoneKey(t)
	h, _, sv := newTestHost(t, Config{Allowed: []string{b}, Relays: []Relay{{URL: startRelay(t), Token: relayToken}}, NoLAN: true})
	waitRelay(t, h)
	serveApp(t, h)
	w := &wire{}
	s, link := pairOverRelay(t, h, w, "x")
	a, _ := connectphone.PublicKey(link.Key)
	if body, err := get(t, s); err != nil || !strings.Contains(body, a) {
		t.Fatalf("control: before the removal: %q %v", body, err)
	}
	failSave := func(fail bool) {
		sv.mu.Lock()
		sv.fail = fail
		sv.mu.Unlock()
	}
	failSave(true)
	if err := h.SetAllowed(context.Background(), []string{b}); err == nil {
		t.Fatal("control: SetAllowed succeeded with a failing save")
	}
	failSave(false)
	h.mu.Lock()
	listed, keyed := false, false
	for _, k := range h.allowed {
		if k.String() == a {
			listed = true
			_, keyed = h.noise[k]
		}
	}
	h.mu.Unlock()
	if !listed || !keyed {
		t.Fatalf("after the failed removal the phone is listed: %v, has its Noise key: %v; want both", listed, keyed)
	}
	// The session it had heard unpaired (fail closed); the phone's link still works from a new one.
	s2, err := connectphone.Connect(link2(link), connectphone.Options{HTTPClient: w.client()})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if body, err := get(t, s2); err != nil || !strings.Contains(body, a) {
		t.Fatalf("the phone the host kept cannot connect over the relay: %q %v", body, err)
	}
}
