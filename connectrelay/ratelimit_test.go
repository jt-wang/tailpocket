package connectrelay

import (
	"net/netip"
	"testing"
	"time"
)

// checkTable verifies the limiter's three indexes agree and stay within their bounds.
func checkTable(t *testing.T, l *rateLimiter) {
	t.Helper()
	if len(l.keys) > maxKeys || l.lru.Len() != len(l.keys) {
		t.Fatalf("keys %d, lru %d, max %d", len(l.keys), l.lru.Len(), maxKeys)
	}
	six := 0
	for k := range l.keys {
		if k.Is6() {
			six++
		}
	}
	inGroups := 0
	for p, g := range l.groups {
		if g.Len() == 0 || g.Len() > maxKeysPer48 {
			t.Fatalf("group %v holds %d keys", p, g.Len())
		}
		inGroups += g.Len()
	}
	if inGroups != six {
		t.Fatalf("groups hold %d keys, table has %d IPv6 keys", inGroups, six)
	}
}

func v6In48(prefix string, i int) netip.Addr {
	a := netip.MustParseAddr(prefix).As16()
	a[6], a[7] = byte(i>>8), byte(i)
	return netip.AddrFrom16(a)
}

// One /48 may hold only maxKeysPer48 keys: flooding it from every /64 forgets its own keys, not
// anyone else's, so a phone that used up its limit before the flood is still refused after it.
func TestRateLimitOne48CannotEvictOthers(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := newRateLimiter(3, time.Minute, func() time.Time { return now })
	spent := netip.MustParseAddr("203.0.113.9")
	spent6 := netip.MustParseAddr("2001:db8:bbbb:1::5")
	for i := 0; i < 3; i++ {
		l.allow(spent)
		l.allow(spent6)
	}
	for i := 0; i < 1<<16; i++ {
		if !l.allow(v6In48("2001:db8:aaaa::", i)) {
			t.Fatalf("/64 number %d refused on its first request", i)
		}
	}
	checkTable(t, l)
	g, _ := group48(AddrKey(v6In48("2001:db8:aaaa::", 0)))
	if n := l.groups[g].Len(); n != maxKeysPer48 {
		t.Fatalf("the flooding /48 holds %d keys, want %d", n, maxKeysPer48)
	}
	if l.allow(spent) || l.allow(spent6) {
		t.Fatal("the /48 flood made the relay forget addresses outside it: they got a fresh limit")
	}
	if !l.allow(netip.MustParseAddr("198.51.100.7")) || !l.allow(netip.MustParseAddr("2001:db8:cccc::1")) {
		t.Fatal("a new address was refused after the /48 flood")
	}
}

// A full table forgets the key seen longest ago and lets the new address in. A key that keeps
// trying while over its limit counts as seen, so it is not the one forgotten (that would reset it).
func TestRateLimitFullTableForgetsOldest(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := newRateLimiter(2, time.Minute, func() time.Time { return now })
	ipv4 := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}) }
	hammer := ipv4(0)
	l.allow(hammer)
	l.allow(hammer)
	for i := 1; i < maxKeys; i++ {
		if !l.allow(ipv4(i)) {
			t.Fatalf("address %d refused", i)
		}
		if i%1024 == 0 && l.allow(hammer) { // over its limit, still trying
			t.Fatal("over-limit address allowed")
		}
	}
	checkTable(t, l)
	if len(l.keys) != maxKeys {
		t.Fatalf("table %d, want full (%d)", len(l.keys), maxKeys)
	}
	for i := 0; i < 2048; i++ { // new addresses on a full table, all inside the window
		if !l.allow(ipv4(maxKeys + i)) {
			t.Fatalf("new address %d refused on a full table", i)
		}
	}
	checkTable(t, l)
	if _, ok := l.keys[ipv4(1)]; ok {
		t.Fatal("the key seen longest ago is still there")
	}
	if l.allow(hammer) {
		t.Fatal("the over-limit address that kept trying was forgotten and got a fresh limit")
	}
	if !l.allow(ipv4(1)) {
		t.Fatal("a forgotten address is refused")
	}
}
