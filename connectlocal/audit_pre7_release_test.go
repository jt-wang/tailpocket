package connectlocal

// Audit, pre.7 review (98969b3): handle now frees the single slot before it writes a denial, so the
// next phone can enter while the denied phone's handler is still returning. That handler's deferred
// end-of-window check reads the shared attempt count, not its own attempt's number. When the denied
// phone was attempt MaxAttempts-1 and the next phone takes attempt MaxAttempts inside that gap, the
// denied handler sees the count at MaxAttempts and ends the window under the phone that just got in,
// which the user was about to approve. Nobody gets an extra key (the bound of MaxAttempts holds);
// the cost is a window that ends one attempt early with ErrTooManyAttempts.
//
// Before pre.7 the slot was freed after that check, so the two could not overlap.

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestAuditDeniedHandlerEndsWindowUnderTheNextPhone(t *testing.T) {
	noGap(t)
	const rounds = 400
	early := 0
	for i := 0; i < rounds; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		var denied atomic.Int32
		secondWaiting := make(chan struct{})
		letGo := make(chan struct{})
		s := serve(t, ctx, HostOptions{Plaintext: []byte("ok"), Confirm: func(ctx context.Context, _, device string) bool {
			if device == "B" {
				return true // the phone the user wants
			}
			if denied.Add(1) == MaxAttempts-1 {
				close(secondWaiting)
				<-letGo
			}
			return false
		}})
		addr := s.addr(t)
		// Attempts 1 … MaxAttempts-1: phone A, denied each time.
		for n := 0; n < MaxAttempts-2; n++ {
			if _, err := Pair(ctx, addr, PhoneOptions{Label: DefaultLabel, Device: "A"}); !errors.Is(err, ErrDenied) {
				t.Fatalf("round %d: A: %v", i, err)
			}
		}
		aDone := make(chan struct{})
		go func() {
			defer close(aDone)
			for { // busy for an instant after the last denial on hosts before pre.7
				_, err := Pair(ctx, addr, PhoneOptions{Label: DefaultLabel, Device: "A"})
				select {
				case <-secondWaiting:
					return
				default:
				}
				if !errors.Is(err, ErrDenied) {
					return
				}
			}
		}()
		<-secondWaiting
		// Phone B keeps trying while A holds the slot; it enters as attempt MaxAttempts the moment A is denied.
		bGot := make(chan error, 1)
		go func() {
			for {
				got, err := Pair(ctx, addr, PhoneOptions{Label: DefaultLabel, Device: "B"})
				if err == nil && string(got) == "ok" {
					bGot <- nil
					return
				}
				if !errors.Is(err, ErrDenied) { // not "busy": the window is gone
					bGot <- err
					return
				}
				select {
				case <-s.err: // Serve returned
					bGot <- err
					return
				default:
				}
			}
		}()
		time.Sleep(2 * time.Millisecond) // B is in its loop
		close(letGo)
		var serveErr error
		select {
		case serveErr = <-s.err:
		case <-time.After(8 * time.Second):
			t.Fatalf("round %d: Serve did not return", i)
		}
		<-aDone
		cancel()
		if errors.Is(serveErr, ErrTooManyAttempts) {
			early++
		} else if serveErr != nil {
			t.Fatalf("round %d: Serve: %v", i, serveErr)
		}
	}
	t.Logf("%d of %d windows ended with ErrTooManyAttempts while phone B, attempt %d, was being approved", early, rounds, MaxAttempts)
	if early > 0 {
		t.Fatalf("a denied phone's handler ended the window under the next phone in %d of %d rounds", early, rounds)
	}
}
