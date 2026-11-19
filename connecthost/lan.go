package connecthost

import (
	"crypto/sha256"
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/jt-wang/tailpocket/connectinvite"
	"github.com/jt-wang/tailpocket/connectsecure"
)

// The local network route without configuration: the host listens on each private address of its
// Wi-Fi and Ethernet (RFC 1918 IPv4, IPv6 ULA), on one port derived from its Noise key so that it
// stays the same across restarts and differs between apps on one computer, and follows address
// changes. A listener there accepts only TailPocket's Noise handshake (serveSecure); it admits only
// connections from private, link-local or loopback sources.

// maxLANAddrs caps the addresses the route lists.
const maxLANAddrs = 4

var (
	lanPoll = 30 * time.Second // how often the host looks for address changes
	// lanAddrs lists the addresses to listen on; tests replace it.
	lanAddrs = privateAddrs
)

// privateAddrs is the computer's private unicast addresses on interfaces that are up and not
// loopback or point-to-point (VPN tunnels), IPv4 first.
func privateAddrs() []netip.Addr {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var v4, v6 []netip.Addr
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(n.IP)
			if !ok || !ip.Unmap().IsPrivate() {
				continue
			}
			if ip = ip.Unmap(); ip.Is4() {
				v4 = append(v4, ip)
			} else {
				v6 = append(v6, ip)
			}
		}
	}
	out := append(v4, v6...)
	slices.SortFunc(out, netip.Addr.Compare) // IPv4 first: Compare orders by length
	out = slices.Compact(out)
	return out[:min(len(out), maxLANAddrs)]
}

// lanPortFor is the port for a host's Noise key: 49152–65535, the dynamic range.
func lanPortFor(pub [32]byte) int {
	h := sha256.Sum256(append([]byte("tailpocket lan port"), pub[:]...))
	return 49152 + int(binary.BigEndian.Uint16(h[:2])%16384)
}

// lanSource reports whether a connection may be from the same network: a private, link-local or
// loopback address. Anything else is closed before a byte is read.
func lanSource(c net.Conn) bool {
	ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		return false
	}
	ip := ap.Addr().Unmap()
	return ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLoopback()
}

// autoLAN is the running automatic local network route.
type autoLAN struct {
	mu    sync.Mutex
	addrs func() []netip.Addr // lanAddrs and lanPoll when it started: tests swap the globals
	poll  time.Duration
	port  int
	lns   map[netip.Addr]net.Listener
	limit *connectsecure.Limiter
	perIP *addrSlots
	stop  chan struct{}
}

// lanRoute is the automatic route's current addresses, or false when it has none.
func (a *autoLAN) route() (connectinvite.Route, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.lns) == 0 {
		return connectinvite.Route{}, false
	}
	var ips []netip.Addr
	for ip := range a.lns {
		ips = append(ips, ip)
	}
	slices.SortFunc(ips, func(x, y netip.Addr) int {
		if x.Is4() != y.Is4() {
			if x.Is4() {
				return -1
			}
			return 1
		}
		return x.Compare(y)
	})
	r := connectinvite.Route{T: RouteLAN}
	for _, ip := range ips {
		r.A = append(r.A, netip.AddrPortFrom(ip, uint16(a.port)).String())
	}
	return r, true
}

// startAutoLAN opens the automatic route and follows address changes until Close. h.op must be held.
func (h *Host) startAutoLAN() {
	h.mu.Lock()
	if !h.autoLANOn || h.lan != nil {
		h.mu.Unlock()
		return
	}
	a := &autoLAN{port: lanPortFor(h.id.noisePublic()), lns: map[netip.Addr]net.Listener{}, addrs: lanAddrs, poll: lanPoll,
		limit: connectsecure.NewLimiter(handshakesPerRoute), perIP: &addrSlots{n: map[netip.Addr]int{}}, stop: make(chan struct{})}
	h.lan = a
	h.mu.Unlock()
	h.refreshLAN()
	go func() {
		t := time.NewTicker(a.poll)
		defer t.Stop()
		for {
			select {
			case <-a.stop:
				return
			case <-t.C:
				h.refreshLAN()
			}
		}
	}()
}

// refreshLAN listens on new private addresses and stops on gone ones; when the route changed, every
// encrypted session gets the new routes.
func (h *Host) refreshLAN() {
	h.mu.Lock()
	a := h.lan
	h.mu.Unlock()
	if a == nil {
		return
	}
	want := a.addrs()
	a.mu.Lock()
	changed := false
	for ip, ln := range a.lns {
		if !slices.Contains(want, ip) {
			_ = ln.Close()
			delete(a.lns, ip)
			changed = true
		}
	}
	for _, ip := range want {
		if _, ok := a.lns[ip]; ok {
			continue
		}
		ln, err := net.Listen("tcp", net.JoinHostPort(ip.String(), strconv.Itoa(a.port)))
		if err != nil && len(a.lns) == 0 {
			// The port is taken (another program): take any while no address uses ours yet. Phones
			// learn the new one from the routes.
			ln, err = net.Listen("tcp", net.JoinHostPort(ip.String(), "0"))
			if err == nil {
				a.port = ln.Addr().(*net.TCPAddr).Port
			}
		}
		if err != nil {
			continue // this address cannot have the port; the others still work
		}
		a.lns[ip] = ln
		changed = true
		go h.acceptLAN(a, ln)
	}
	a.mu.Unlock()
	if changed {
		h.pushRoutes()
	}
}

func (h *Host) acceptLAN(a *autoLAN, ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-a.stop:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && !ne.Timeout() {
				return // closed: the address went away
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if !lanSource(c) {
			_ = c.Close()
			continue
		}
		release, ok := a.perIP.acquire(c)
		if !ok {
			_ = c.Close()
			continue
		}
		go h.serveSecure(c, RouteLAN, a.limit, release)
	}
}

func (a *autoLAN) close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	select {
	case <-a.stop:
		return
	default:
	}
	close(a.stop)
	for ip, ln := range a.lns {
		_ = ln.Close()
		delete(a.lns, ip)
	}
}

// pushRoutes sends the current routes on every encrypted session.
func (h *Host) pushRoutes() {
	h.mu.Lock()
	routes := h.routesLocked()
	ss := make([]*connectsecure.Session, 0, len(h.sessions))
	for s := range h.sessions {
		ss = append(ss, s)
	}
	h.mu.Unlock()
	for _, s := range ss {
		_ = s.Control().Send(routesMsg{Type: "routes", Via: routes})
	}
}
