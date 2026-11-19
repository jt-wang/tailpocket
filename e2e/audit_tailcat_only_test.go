//go:build linux

package e2e

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jt-wang/tailpocket/connecthost"
	"github.com/jt-wang/tailpocket/connectinvite"
	"github.com/jt-wang/tailpocket/connectphone"
)

// sock is one socket this process holds, read from /proc.
type sock struct {
	proto  string // tcp, tcp6, udp, udp6
	local  netip.AddrPort
	remote netip.AddrPort
	listen bool
}

func (s sock) String() string {
	if s.listen {
		return fmt.Sprintf("%s LISTEN %s", s.proto, s.local)
	}
	return fmt.Sprintf("%s %s -> %s", s.proto, s.local, s.remote)
}

// ownSockets lists the TCP and UDP sockets of this process: the inodes behind /proc/self/fd,
// looked up in /proc/net/{tcp,tcp6,udp,udp6}.
func ownSockets(t *testing.T) []sock {
	t.Helper()
	inodes := map[string]bool{}
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("no /proc/self/fd: %v", err)
	}
	for _, fd := range fds {
		if l, err := os.Readlink("/proc/self/fd/" + fd.Name()); err == nil && strings.HasPrefix(l, "socket:[") {
			inodes[strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]")] = true
		}
	}
	addr := func(hexAddr string) netip.AddrPort {
		ip, port, _ := strings.Cut(hexAddr, ":")
		p, _ := strconv.ParseUint(port, 16, 16)
		b := make([]byte, len(ip)/2)
		for i := range b {
			v, _ := strconv.ParseUint(ip[2*i:2*i+2], 16, 8)
			b[i] = byte(v)
		}
		// /proc prints each 32-bit word in host byte order.
		for i := 0; i+3 < len(b); i += 4 {
			b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
		}
		a, _ := netip.AddrFromSlice(b)
		return netip.AddrPortFrom(a.Unmap(), uint16(p))
	}
	var out []sock
	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
		f, err := os.Open("/proc/net/" + proto)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Scan() // header
		for sc.Scan() {
			fl := strings.Fields(sc.Text())
			if len(fl) < 10 || !inodes[fl[9]] {
				continue
			}
			out = append(out, sock{proto: proto, local: addr(fl[1]), remote: addr(fl[2]),
				listen: strings.HasPrefix(proto, "tcp") && fl[3] == "0A"})
		}
		f.Close()
	}
	return out
}

// Audit (Tailcat-only mode): a host with TailcatOnly, and a phone paired with it with TailcatOnly, use
// Tailcat and nothing else. Checked on the real network: the invite and the paired link list no
// relay or lan route, the process holds no listening TCP socket, and every TCP connection it holds
// goes to port 443 of a DERP node or the DERP map's host. UDP sockets are Tailcat's own (WireGuard
// and STUN); they are logged, since /proc does not show where an unconnected UDP socket sends.
func TestAuditTailcatOnlyOpensNothingElse(t *testing.T) {
	live(t)
	before := map[string]bool{}
	for _, s := range ownSockets(t) {
		before[s.String()] = true
	}

	st := &store{}
	h, err := connecthost.New(connecthost.Config{Name: "audit tailcat-only", Save: st.save, TailcatOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := h.Start(ctx); err != nil {
		t.Fatal(err)
	}
	serveEcho(h)
	p, err := h.Pair(ctx, connecthost.PairOptions{Confirm: func(context.Context, connecthost.PairRequest) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	inv := p.InviteV2()
	for _, r := range inv.Via {
		if r.T != connectinvite.RouteTailcat {
			t.Errorf("the invite of a host without Relays or Listen lists a %q route: %+v", r.T, r)
		}
	}
	key := connectphone.NewKey()
	pub, _ := connectphone.PublicKey(key)
	link, err := connectphone.PairV2(ctx, inv, key, connectphone.Options{Device: "audit", TailcatOnly: true, OnSAS: func([]string) {}})
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	if len(link.Via) != 0 {
		t.Errorf("the paired link lists routes besides Tailcat: %+v", link.Via)
	}
	for _, r := range h.Routes() {
		if r.T != connectinvite.RouteTailcat {
			t.Errorf("host route %+v", r)
		}
	}
	s, err := connectphone.Connect(link, connectphone.Options{TailcatOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	roundTrip(t, ctx, s.Dial, pub)
	if route, relay, err := s.Path(ctx); err == nil {
		t.Logf("path: %s %s", route, relay)
	}
	if l := s.Link(); len(l.Via) != 0 {
		t.Errorf("after connecting, the link lists routes besides Tailcat: %+v", l.Via)
	}

	// Who may the process talk to over TCP: the DERP map's host and the DERP nodes.
	allowed := map[netip.Addr]string{}
	names := []string{"tailcat.dev"}
	for _, n := range regionNodes(st.get().Identity) {
		names = append(names, n)
	}
	for _, n := range names {
		ips, _ := net.DefaultResolver.LookupNetIP(ctx, "ip", n)
		for _, ip := range ips {
			allowed[ip.Unmap()] = n
		}
		if a, err := netip.ParseAddr(n); err == nil {
			allowed[a] = n
		}
	}
	var lines []string
	for _, k := range ownSockets(t) {
		if before[k.String()] {
			continue
		}
		note := ""
		switch {
		case k.listen:
			t.Errorf("listening TCP socket in Tailcat-only mode: %s", k)
		case strings.HasPrefix(k.proto, "tcp"):
			who, ok := allowed[k.remote.Addr()]
			note = " (" + who + ")"
			if k.remote.Port() != 443 || !ok {
				t.Errorf("TCP connection to something that is neither a DERP node nor the DERP map host: %s", k)
			}
		default:
			if k.local.Addr().IsLoopback() {
				continue
			}
			note = " (Tailcat's UDP socket)"
		}
		lines = append(lines, k.String()+note)
	}
	sort.Strings(lines)
	t.Logf("sockets the host and phone opened:\n  %s", strings.Join(lines, "\n  "))
}

// regionNodes pulls the DERP node names and addresses out of a saved identity.
func regionNodes(identity string) []string {
	var out []string
	for _, f := range []string{`"HostName":"`, `"IPv4":"`, `"IPv6":"`} {
		rest := identity
		for {
			i := strings.Index(rest, f)
			if i < 0 {
				break
			}
			rest = rest[i+len(f):]
			j := strings.IndexByte(rest, '"')
			if j < 0 {
				break
			}
			out = append(out, rest[:j])
			rest = rest[j:]
		}
	}
	return out
}
