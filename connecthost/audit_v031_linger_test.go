package connecthost

// Audit, v0.3.1 review (6a032a7). SetAllowed that removes a phone with an open Tailcat connection now
// closes that connection first and then waits byeLinger (3 s) before it restarts the main node, so
// the close reaches the phone. During those 3 s the removed phone is still in the host's tables
// (byIP, allowed, noise) and the old node still runs, so the phone connects again at once and
// reaches the app: the host closed its connection and then admits it again for 3 s (and Authorize
// still sees it as paired). Before b8b0274 the node stopped first and the phone could not come back
// over Tailcat.
//
// The fix: take the removed phones out of byIP in the same h.mu section that takes their
// connections (it is put back if the save fails).

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestAuditRemovedPhoneConnectsAgainWhileTheNodeLingers(t *testing.T) {
	_, a := phoneKey(t)
	_, b := phoneKey(t)
	h, f, _ := newTestHost(t, Config{Allowed: []string{a, b}})
	main := f.live(DefaultPort)
	phone := main.dial(t, a)
	_ = accept(t, h)

	start := time.Now()
	done := make(chan error, 1)
	go func() { done <- h.SetAllowed(context.Background(), []string{b}) }()
	if !closedByHost(phone) {
		t.Fatal("control: the removed phone's connection was not closed")
	}
	// The removed phone dials again at once, as a phone app does when its connection drops.
	again := main.dial(t, a)
	if again == nil {
		<-done
		return // the node refused it
	}
	got := make(chan net.Conn, 1)
	go func() {
		if c, err := h.Listener().Accept(); err == nil {
			got <- c
		}
	}()
	select {
	case c := <-got:
		go io.WriteString(again, "x")
		buf := make([]byte, 1)
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		n, _ := c.Read(buf)
		t.Errorf("%v after SetAllowed closed the removed phone's connection, the same phone connected again and the app got it (PhoneOf is the removed phone: %v, bytes read from it: %d)",
			time.Since(start).Round(100*time.Millisecond), PhoneOf(c) == a, n)
	case <-time.After(byeLinger + 2*time.Second):
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
