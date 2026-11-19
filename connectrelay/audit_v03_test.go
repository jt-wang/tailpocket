package connectrelay

// Audit (v0.3, 83d4174): the per-address limiter keeps at most 1<<16 source keys and refuses every new
// key while the table is full. IPv6 counts by /64, and one /48 is exactly 1<<16 of them: one cheap
// allocation shuts every new phone address out of /v1/phone for as long as it keeps sending.

import (
	"net/netip"
	"testing"
	"time"
)

func TestAuditOneSlash48LocksEveryoneOutOfPhoneRate(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := newRateLimiter(DefaultPhoneRate, time.Minute, func() time.Time { return now })
	base := netip.MustParseAddr("2001:db8:aaaa::").As16()
	for i := 0; i < 1<<16; i++ { // one request from each /64 of 2001:db8:aaaa::/48
		a := base
		a[6], a[7] = byte(i>>8), byte(i)
		if !l.allow(netip.AddrFrom16(a)) {
			t.Fatalf("request %d refused", i)
		}
	}
	now = now.Add(30 * time.Second) // still inside the window
	if !l.allow(netip.MustParseAddr("198.51.100.7")) {
		t.Error("a phone on an address the relay has never seen is refused: the table is full of one /48's keys")
	}
}
