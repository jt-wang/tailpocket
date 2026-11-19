package e2e

// Audit, pre.8 review (8371b6f): on the real Tailcat network, a phone pairing over the window's
// Tailcat node hears the computer's "no" at once (ErrUnauthorized), not when its handshake times out.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jt-wang/tailpocket/connecthost"
	"github.com/jt-wang/tailpocket/connectphone"
)

func TestAuditLiveRefusalReachesThePhone(t *testing.T) {
	live(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	st := &store{}
	h, err := connecthost.New(connecthost.Config{Name: "audit refusal", Save: st.save, TailcatOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if err := h.Start(ctx); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		asked := make(chan time.Time, 1)
		p, err := h.Pair(ctx, connecthost.PairOptions{Confirm: func(context.Context, connecthost.PairRequest) bool {
			asked <- time.Now()
			return false
		}})
		if err != nil {
			t.Fatal(err)
		}
		_, err = connectphone.PairV2(ctx, p.InviteV2(), connectphone.NewKey(), connectphone.Options{Device: "audit", TailcatOnly: true, OnSAS: func([]string) {}})
		heard := time.Now()
		var at time.Time
		select {
		case at = <-asked:
		default:
			t.Fatalf("run %d: Confirm never ran: %v", i+1, err)
		}
		t.Logf("run %d: the phone heard %v, %v after the no", i+1, err, heard.Sub(at).Round(10*time.Millisecond))
		if !errors.Is(err, connectphone.ErrUnauthorized) {
			t.Fatalf("run %d: %v, want ErrUnauthorized", i+1, err)
		}
		if heard.Sub(at) > 5*time.Second {
			t.Fatalf("run %d: the refusal took %v to reach the phone", i+1, heard.Sub(at))
		}
		select {
		case <-p.Done():
		case <-time.After(time.Second):
			t.Fatalf("run %d: the window stayed open after the no", i+1)
		}
	}
}
