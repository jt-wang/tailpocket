package connectmdns

import (
	"net"
	"strings"
	"testing"

	"github.com/jt-wang/tailpocket/internal/lan"
)

// The responder answers only sources on the network of the interface a query came in on (RFC 6762
// section 11); loopback, other subnets, other interfaces and IPv6 get nothing. Needs no LAN.
func TestOnLinkOnly(t *testing.T) {
	_, wifi, _ := net.ParseCIDR("192.168.1.20/24")
	_, eth, _ := net.ParseCIDR("10.1.0.5/16")
	a := &advertiser{ifaces: []lan.Iface{
		{Interface: net.Interface{Index: 2, Name: "en0"}, Networks: []*net.IPNet{{IP: net.IPv4(192, 168, 1, 20).To4(), Mask: wifi.Mask}}},
		{Interface: net.Interface{Index: 3, Name: "en1"}, Networks: []*net.IPNet{{IP: net.IPv4(10, 1, 0, 5).To4(), Mask: eth.Mask}}},
	}}
	for _, tc := range []struct {
		src   string
		index int
		want  bool
	}{
		{"192.168.1.9", 2, true},
		{"192.168.1.20", 2, true}, // this machine's own browser
		{"10.1.200.7", 3, true},
		{"192.168.1.9", 0, true},  // no interface given: any served one
		{"192.168.1.9", 3, false}, // on a subnet, but not the one it came in on
		{"10.1.200.7", 2, false},
		{"192.168.2.9", 2, false},
		{"127.0.0.1", 0, false},
		{"127.0.0.1", 1, false},
		{"203.0.113.7", 0, false},
		{"::ffff:203.0.113.7", 2, false},
		{"fe80::1", 2, false},
	} {
		if got := a.onLink(net.ParseIP(tc.src), tc.index); got != tc.want {
			t.Errorf("onLink(%s, if %d) = %v, want %v", tc.src, tc.index, got, tc.want)
		}
	}
	if a.onLink(nil, 0) {
		t.Error("onLink(nil) = true")
	}
}

// avahi-publish-service takes the instance as an argument of its own, so an instance never starts
// with "-": CleanInstance drops leading dashes and validate refuses them.
func TestInstanceIsNeverAnOption(t *testing.T) {
	for _, in := range []string{"--domain=evil", "-Hevil", "-f", " - -x", "\x00-h"} {
		got := CleanInstance(in)
		if strings.HasPrefix(got, "-") {
			t.Errorf("CleanInstance(%q) = %q", in, got)
		}
		s := testService()
		s.Instance = in
		if s.validate() == nil && strings.HasPrefix(in, "-") {
			t.Errorf("validate accepted instance %q", in)
		}
	}
	if got := CleanInstance("Studio-Mac"); got != "Studio-Mac" {
		t.Errorf("CleanInstance dropped an inner dash: %q", got)
	}
}
