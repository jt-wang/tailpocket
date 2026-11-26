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

// attestFails blocks a source (an IPv4 address or an IPv6 /64) whose attestation evidence failed
// attestFailLimit times in a row, for attestFailBlock, on register and revoke. A success clears
// its count. A source's requests still at the verifier count with its failures, so one that sends
// in parallel gets no more past enter than one that waits for each answer: made-up Play Integrity
// tokens cost at most attestFailLimit decodes per source an hour. Answers that say nothing about
// the evidence (503 unavailable, unknown key, bad challenge) count nothing.
type attestFails struct {
	max int

	mu sync.Mutex
	m  map[string]*failRun
}

const (
	attestFailLimit = 3
	attestFailBlock = time.Hour
)

type failRun struct {
	n        int // failures in a row
	inflight int // requests past enter, not yet answered
	last     time.Time
	until    time.Time
}

func newAttestFails(maxKeys int) *attestFails {
	return &attestFails{max: maxKeys, m: map[string]*failRun{}}
}

// enter reports whether a request from addr may go to the verifier: addr is not blocked, and its
// failures plus its requests in flight are below attestFailLimit. A request that entered must end
// with exactly one of fail, pass or release. When the table is full of other sources it lets the
// request through untracked (fail, pass and release then do nothing for it).
func (f *attestFails) enter(addr string, now time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.m[addr]
	if r == nil {
		if len(f.m) >= f.max {
			f.sweepLocked(now)
			if len(f.m) >= f.max {
				return true
			}
		}
		r = &failRun{}
		f.m[addr] = r
	}
	if now.Before(r.until) || r.n+r.inflight >= attestFailLimit {
		return false
	}
	r.inflight++
	r.last = now
	return true
}

func (f *attestFails) leaveLocked(r *failRun) {
	if r.inflight > 0 {
		r.inflight--
	}
}

// fail ends a request whose evidence failed, and reports whether it just blocked addr.
func (f *attestFails) fail(addr string, now time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.m[addr]
	if r == nil {
		return false
	}
	f.leaveLocked(r)
	r.last = now
	if now.Before(r.until) {
		return false
	}
	r.n++
	if r.n >= attestFailLimit {
		r.n, r.until = 0, now.Add(attestFailBlock)
		return true
	}
	return false
}

// pass ends a request whose evidence passed, and clears addr's run of failures.
func (f *attestFails) pass(addr string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r := f.m[addr]; r != nil {
		f.leaveLocked(r)
		r.n = 0
	}
}

// release ends a request that said nothing about the evidence.
func (f *attestFails) release(addr string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r := f.m[addr]; r != nil {
		f.leaveLocked(r)
	}
}

func (f *attestFails) sweep(now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sweepLocked(now)
}

// sweepLocked forgets sources neither blocked, in flight, nor seen in attestFailBlock.
func (f *attestFails) sweepLocked(now time.Time) {
	for k, r := range f.m {
		if r.inflight == 0 && !now.Before(r.until) && now.Sub(r.last) >= attestFailBlock {
			delete(f.m, k)
		}
	}
}
