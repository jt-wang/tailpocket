package connectmdns

import (
	"net"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// Audit (fail closed): packets anyone on the network can send to the responder and to a browsing
// phone. Neither may panic, and a reply never exceeds one packet.
func FuzzAuditMDNSPackets(f *testing.F) {
	q, _ := build(dnsmessage.Header{ID: 7}, []dnsmessage.Question{{Name: dnsmessage.MustNewName("_tailpocket-demo._tcp.local."),
		Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET}}, nil, nil)
	f.Add(q, 49152)
	f.Add(q, 5353)
	f.Add([]byte{0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0}, 5353)
	r := newRecords(testService(), "studio-mac-1a2b.local.")
	f.Fuzz(func(t *testing.T, packet []byte, port int) {
		if reply, _, ok := r.respond(packet, port, []net.IP{net.IPv4(192, 168, 1, 20)}); ok && len(reply) > maxPacket {
			t.Fatalf("reply of %d bytes", len(reply))
		}
		b := &browser{typ: dnsmessage.MustNewName("_tailpocket-demo._tcp.local."), typText: "_tailpocket-demo._tcp",
			found: map[string]*partial{}, hosts: map[string][]net.IP{}, sent: map[string]string{}}
		b.absorb(packet, &net.UDPAddr{IP: net.IPv4(192, 168, 1, 9), Port: 5353})
	})
}
