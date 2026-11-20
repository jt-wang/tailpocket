// Package closing bounds how long closing a Tailcat node or client may take.
//
// tailcat v0.6.0's Close waits for WireGuard's receive goroutines to stop and has no time limit. When
// one of them never wakes (tailscale.com magicsock with TS_DEBUG_ALWAYS_USE_DERP rebinding: the
// replaced UDP stand-in is never closed), Close never returns: a refused pairing never reached the
// phone and a helper never exited on SIGTERM. TailPocket waits at most Timeout and then goes on.
package closing

import (
	"errors"
	"time"
)

// Timeout is how long Within waits by default. Tests shorten it.
var Timeout = 3 * time.Second

// ErrTimeout reports that close was still running when Within returned. It keeps running.
var ErrTimeout = errors.New("closing: still closing after the time limit; left running")

// Within runs close and returns its error, or ErrTimeout once Timeout has passed. A close that
// outlives the limit keeps its goroutine and whatever it holds; the caller no longer waits for it.
func Within(close func() error) error {
	done := make(chan error, 1)
	go func() { done <- close() }()
	t := time.NewTimer(Timeout)
	defer t.Stop()
	select {
	case err := <-done:
		return err
	case <-t.C:
		return ErrTimeout
	}
}
