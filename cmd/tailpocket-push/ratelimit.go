package main

import (
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// limiter allows at most n events per key in any window. The window is
// cut into slots; each key keeps a count for the current slot and the
// slots before it that make up a window, and an event is allowed only
// while their sum is under n. Those counts always cover the last full
// window, so no window-long span ever holds more than n; the price is
// that an event up to one slot older than the window may still count.
type limiter struct {
	n     int
	slot  int64 // nanoseconds
	slots int64 // slots per window
	max   int   // most keys held

	mu sync.Mutex
	m  map[string]*slots
}

type slots struct {
	last  int64 // newest slot seen
	count []uint32
}

func newLimiter(n int, window time.Duration, nslots int, maxKeys int) *limiter {
	return &limiter{n: n, slot: int64(window) / int64(nslots), slots: int64(nslots), max: maxKeys, m: map[string]*slots{}}
}

func (l *limiter) allow(key string, now time.Time) bool {
	cur := now.UnixNano() / l.slot
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.m[key]
	if s == nil {
		if len(l.m) >= l.max {
			l.sweepLocked(cur)
			if len(l.m) >= l.max {
				return false // full of live keys: refuse rather than forget one
			}
		}
		s = &slots{last: cur, count: make([]uint32, l.slots+1)}
		l.m[key] = s
	}
	if cur < s.last {
		cur = s.last // clock went back: keep counting in the newest slot
	}
	ring := int64(len(s.count))
	if cur-s.last > l.slots {
		clear(s.count)
	} else {
		for i := s.last + 1; i <= cur; i++ {
			s.count[i%ring] = 0
		}
	}
	s.last = cur
	sum := 0
	for _, c := range s.count {
		sum += int(c)
	}
	if sum >= l.n {
		return false
	}
	s.count[cur%ring]++
	return true
}

// sweep drops keys with no event in their window.
func (l *limiter) sweep(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(now.UnixNano() / l.slot)
}

func (l *limiter) sweepLocked(cur int64) {
	for k, s := range l.m {
		if cur-s.last > l.slots {
			delete(l.m, k)
		}
	}
}

func (l *limiter) len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.m)
}

// clientIP is the address the per-IP limit counts: the TCP peer, or, when
// the peer is a trusted proxy, the rightmost X-Forwarded-For hop that is
// not.
func clientIP(r *http.Request, trust []netip.Prefix) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	trusted := func(a netip.Addr) bool {
		for _, p := range trust {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	client := ap.Addr().Unmap()
	if !trusted(client) {
		return client
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		h := strings.TrimSpace(hops[i])
		a, err := netip.ParseAddr(h)
		if err != nil {
			p, err := netip.ParseAddrPort(h)
			if err != nil {
				break
			}
			a = p.Addr()
		}
		client = a.Unmap()
		if !trusted(client) {
			break
		}
	}
	return client
}

// addrKey is an IPv4 address as it is and an IPv6 address by its /64: one
// home or phone usually has a whole /64.
func addrKey(a netip.Addr) string {
	if a.Is6() {
		if p, err := a.Prefix(64); err == nil {
			return p.String()
		}
	}
	return a.String()
}
