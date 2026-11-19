package connectmdns

import (
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Audit (fail closed), M1: the built-in responder binds 0.0.0.0:5353 and answers a unicast
// ("legacy") query from any source address, on any interface, with the host's name, LAN
// addresses and pairing port. RFC 6762 section 11 has a responder ignore queries whose source is
// not on the local link. A computer with a public address (or behind a router that forwards UDP
// 5353) becomes a small UDP reflector while a same-Wi-Fi pairing window is open, and tells the
// internet its LAN addresses. Here 127.0.0.1 stands for an off-link source: it is on none of the
// interfaces the responder serves.
func TestAuditBuiltinResponderAnswersOffLinkUnicast(t *testing.T) {
	needLAN(t)
	s := uniqueService(t)
	stop := advertiseBuiltin(t, s)
	defer stop()

	for _, i := range lanInterfaces() {
		for _, n := range i.Networks {
			if n.Contains(net.IPv4(127, 0, 0, 1)) {
				t.Skip("loopback is inside a LAN subnet here")
			}
		}
	}
	c, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: mdnsPort})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	query := buildQuery(t, 0x5151, question(t, s.Type+".local.", dnsmessage.TypePTR))
	if _, err := c.Write(query); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, maxPacket)
	n, err := c.Read(buf)
	if err != nil {
		return // no answer: fixed
	}
	var p dnsmessage.Parser
	h, perr := p.Start(buf[:n])
	if perr != nil || !h.Response || h.ID != 0x5151 {
		t.Skipf("another responder answered on 5353: %v %+v", perr, h)
	}
	_ = p.SkipAllQuestions()
	answers, _ := p.AllAnswers()
	_ = p.SkipAllAuthorities()
	extra, _ := p.AllAdditionals()
	var addrs []string
	for _, r := range extra {
		if a, ok := r.Body.(*dnsmessage.AResource); ok {
			addrs = append(addrs, net.IP(a.A[:]).String())
		}
	}
	t.Fatalf("a %d-byte unicast query from 127.0.0.1 (on no LAN subnet) got a %d-byte answer: %d answers, LAN addresses %v",
		len(query), n, len(answers), addrs)
}
