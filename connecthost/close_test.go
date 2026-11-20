package connecthost

import (
	"context"
	"testing"
	"time"

	"github.com/jt-wang/tailpocket/internal/closing"
)

// A Tailcat node's Close can wait forever: tailcat v0.6.0's Close waits for WireGuard's receive
// goroutines, and with TS_DEBUG_ALWAYS_USE_DERP tailscale.com's magicsock leaves one parked on a UDP
// stand-in it replaced without closing. Pairing.Close and Host.Close (SIGTERM in the helper) still
// return within closing.Timeout per node.
func TestCloseWithNodesThatNeverClose(t *testing.T) {
	was := closing.Timeout
	closing.Timeout = 200 * time.Millisecond
	t.Cleanup(func() { closing.Timeout = was })
	_, a := phoneKey(t)
	h, f, _ := newTestHost(t, Config{Allowed: []string{a}})
	p, err := h.Pair(context.Background(), PairOptions{})
	if err != nil {
		t.Fatal(err)
	}
	hang := make(chan struct{})
	t.Cleanup(func() { close(hang) })
	f.mu.Lock()
	f.hang = hang
	f.mu.Unlock()

	start := time.Now()
	done := make(chan struct{})
	go func() {
		p.Close()
		_ = h.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Pairing.Close and Host.Close still wait for nodes that never close")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("closing took %v with a 200 ms limit per node", d)
	}
}

// Revoking the last phone stops the main node. Its open connections must be closed while the node
// still carries the close: over a stopped node (dead, as seen over DERP) the phone never hears it and
// kept the connection open until its own timeout.
func TestRevokingTheLastPhoneClosesItsConnections(t *testing.T) {
	_, a := phoneKey(t)
	h, f, _ := newTestHost(t, Config{Allowed: []string{a}})
	f.mu.Lock()
	f.dead = true
	f.mu.Unlock()
	main := f.live(DefaultPort)
	phone := main.dial(t, a)
	_ = accept(t, h)

	start := time.Now()
	if err := h.Revoke(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("Revoke took %v", d)
	}
	if !closedByHost(phone) {
		t.Fatal("the last phone's open connection stayed open after the revoke")
	}
	for deadline := time.Now().Add(byeLinger + 2*time.Second); !main.isClosed(); time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the main node still runs after its last phone was revoked")
		}
	}
}

// SetAllowed restarts the main node when it removes a phone; the removed phone hears its
// connections close before the old node stops.
func TestSetAllowedClosesRemovedPhonesBeforeTheNodeStops(t *testing.T) {
	_, a := phoneKey(t)
	_, b := phoneKey(t)
	h, f, _ := newTestHost(t, Config{Allowed: []string{a, b}})
	f.mu.Lock()
	f.dead = true
	f.mu.Unlock()
	phone := f.live(DefaultPort).dial(t, a)
	_ = accept(t, h)
	if err := h.SetAllowed(context.Background(), []string{b}); err != nil {
		t.Fatal(err)
	}
	if !closedByHost(phone) {
		t.Fatal("the removed phone's open connection stayed open after SetAllowed")
	}
}

// The main node lingering after its last phone went never runs beside a new one with the same key,
// and Host.Close closes it at once.
func TestRetiredMainNodeClosesBeforeTheNextAndOnClose(t *testing.T) {
	_, a := phoneKey(t)
	h, f, _ := newTestHost(t, Config{Allowed: []string{a}})
	f.mu.Lock()
	f.dead = true
	f.mu.Unlock()
	ctx := context.Background()
	old := f.live(DefaultPort)
	_ = old.dial(t, a)
	_ = accept(t, h)
	if err := h.Revoke(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := h.SetAllowed(ctx, []string{a}); err != nil {
		t.Fatal(err)
	}
	next := f.live(DefaultPort)
	if !old.isClosed() || next == nil || next == old {
		t.Fatal("the retired main node still runs beside the new one")
	}
	_ = next.dial(t, a)
	_ = accept(t, h)
	if err := h.Revoke(ctx, a); err != nil {
		t.Fatal(err)
	}
	_ = h.Close()
	if !next.isClosed() {
		t.Fatal("Host.Close left the retired main node to its timer")
	}
}
