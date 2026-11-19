package connectrelay

import (
	"container/list"
	"net/netip"
	"sync"
	"time"
)

// AddrKey is the source address limits count against: an IPv4 address as
// it is, an IPv6 address by its /64 (one home or phone usually gets a whole
// /64, so counting single IPv6 addresses would not limit anyone).
func AddrKey(a netip.Addr) netip.Addr {
	a = a.Unmap()
	if a.Is6() {
		p, err := a.Prefix(64)
		if err == nil {
			return p.Addr()
		}
	}
	return a
}

// rateLimiter allows at most n events per key in any window: a sliding
// window that keeps the times of the last n events.
//
// The table is bounded and never refuses an address for being full: past
// maxKeys keys it forgets the key seen longest ago, and one IPv6 /48 holds at
// most maxKeysPer48 keys, forgetting its own oldest past that. So one /48
// (exactly 1<<16 /64s) cannot fill the table, and no number of addresses
// can lock a new one out; a forgotten key only starts counting again.
type rateLimiter struct {
	n      int
	window time.Duration
	now    func() time.Time

	mu     sync.Mutex
	keys   map[netip.Addr]*ring
	lru    list.List // of *ring, most recently seen first
	groups map[netip.Prefix]*list.List
}

type ring struct {
	key  netip.Addr
	at   []int64 // unix nanoseconds; once full, the oldest is at next
	next int

	inLRU   *list.Element
	group   *list.List // the /48's keys, most recently seen first; nil for IPv4
	inGroup *list.Element
}

const (
	// maxKeys bounds memory: the table never holds more keys than this.
	maxKeys = 1 << 16
	// maxKeysPer48 is the most keys one IPv6 /48 holds, a sixteenth of the table.
	maxKeysPer48 = 1 << 12
)

func newRateLimiter(n int, window time.Duration, now func() time.Time) *rateLimiter {
	return &rateLimiter{n: n, window: window, now: now, keys: map[netip.Addr]*ring{}, groups: map[netip.Prefix]*list.List{}}
}

// group48 is the /48 an IPv6 key counts in, or false for IPv4.
func group48(k netip.Addr) (netip.Prefix, bool) {
	if !k.Is6() {
		return netip.Prefix{}, false
	}
	p, err := k.Prefix(48)
	return p, err == nil
}

// forget drops r from the table. l.mu must be held.
func (l *rateLimiter) forget(r *ring) {
	delete(l.keys, r.key)
	l.lru.Remove(r.inLRU)
	if r.group != nil {
		r.group.Remove(r.inGroup)
		if r.group.Len() == 0 {
			p, _ := group48(r.key)
			delete(l.groups, p)
		}
	}
}

func (l *rateLimiter) allow(a netip.Addr) bool {
	k := AddrKey(a)
	now := l.now().UnixNano()
	cut := now - l.window.Nanoseconds()
	l.mu.Lock()
	defer l.mu.Unlock()
	r := l.keys[k]
	if r == nil {
		var g *list.List
		if p, ok := group48(k); ok {
			if g = l.groups[p]; g == nil {
				g = list.New()
				l.groups[p] = g
			} else if g.Len() >= maxKeysPer48 {
				l.forget(g.Back().Value.(*ring))
			}
		}
		if len(l.keys) >= maxKeys {
			l.forget(l.lru.Back().Value.(*ring))
		}
		r = &ring{key: k, at: make([]int64, 0, l.n), group: g}
		r.inLRU = l.lru.PushFront(r)
		if g != nil {
			r.inGroup = g.PushFront(r)
			p, _ := group48(k)
			l.groups[p] = g // forget may have dropped the group it emptied
		}
		l.keys[k] = r
	} else {
		// Refused requests count as seen too, so a key that keeps trying
		// is not the one forgotten (which would start it afresh).
		l.lru.MoveToFront(r.inLRU)
		if r.group != nil {
			r.group.MoveToFront(r.inGroup)
		}
	}
	if len(r.at) < l.n {
		r.at = append(r.at, now)
		r.next = len(r.at) % l.n
		return true
	}
	// Full: the oldest of the last n must have left the window.
	if r.at[r.next] > cut {
		return false
	}
	r.at[r.next] = now
	r.next = (r.next + 1) % l.n
	return true
}
