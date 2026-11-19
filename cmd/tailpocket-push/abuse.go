package main

import (
	"sync"
	"time"
)

// badTokens blocks a source whose pushes keep landing on tokens APNs or
// FCM say are not valid: someone registering made-up tokens, or sending
// to them. Each push result counts against the source that sent it and
// the source that registered its handle. A source with at least
// badMinResults of its last badWindow results and more than half of them
// bad is blocked for badBlock, for every endpoint.
type badTokens struct {
	max int

	mu sync.Mutex
	m  map[srcTag]*outcomes
}

const (
	badWindow     = 20
	badMinResults = 10
	badBlock      = time.Hour
	badForget     = 24 * time.Hour
)

type outcomes struct {
	bad   [badWindow]bool
	n     int // results held, up to badWindow
	next  int
	last  time.Time
	until time.Time
}

func newBadTokens(maxKeys int) *badTokens {
	return &badTokens{max: maxKeys, m: map[srcTag]*outcomes{}}
}

func (b *badTokens) blocked(src srcTag, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	o := b.m[src]
	return o != nil && now.Before(o.until)
}

// note records one push result for src and reports whether it just
// blocked src.
func (b *badTokens) note(src srcTag, bad bool, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	o := b.m[src]
	if o == nil {
		if len(b.m) >= b.max {
			b.sweepLocked(now)
			if len(b.m) >= b.max {
				return false
			}
		}
		o = &outcomes{}
		b.m[src] = o
	}
	o.last = now
	o.bad[o.next] = bad
	o.next = (o.next + 1) % badWindow
	if o.n < badWindow {
		o.n++
	}
	nbad := 0
	for i := 0; i < o.n; i++ {
		if o.bad[i] {
			nbad++
		}
	}
	if o.n >= badMinResults && 2*nbad > o.n {
		o.until = now.Add(badBlock)
		o.n, o.next = 0, 0
		return true
	}
	return false
}

func (b *badTokens) sweep(now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sweepLocked(now)
}

func (b *badTokens) sweepLocked(now time.Time) {
	for k, o := range b.m {
		if now.After(o.until) && now.Sub(o.last) > badForget {
			delete(b.m, k)
		}
	}
}
