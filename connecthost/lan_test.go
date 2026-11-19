package connecthost

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jt-wang/tailpocket/connectinvite"
	"github.com/jt-wang/tailpocket/connectphone"
	"github.com/jt-wang/tailpocket/internal/testhook"
)

// Tests run without the computer's real addresses unless they ask for them (withLANAddrs).
func init() {
	lanAddrs = func() []netip.Addr { return nil }
	testhook.LoopbackRoutes = true // host and phone run on one machine
}

func withLANAddrs(t *testing.T, f func() []netip.Addr) {
	t.Helper()
	old, oldPoll := lanAddrs, lanPoll
	lanAddrs, lanPoll = f, 20*time.Millisecond
	t.Cleanup(func() { lanAddrs, lanPoll = old, oldPoll })
}

var loopback = netip.MustParseAddr("127.0.0.1")

// listeningPorts is every TCP port this process listens on (Linux): LISTEN sockets whose inode is
// one of this process's file descriptors, so other programs on the machine do not count.
func listeningPorts(t *testing.T) map[string]bool {
	t.Helper()
	mine := map[string]bool{}
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("no /proc/self/fd: %v", err)
	}
	for _, fd := range fds {
		if l, err := os.Readlink("/proc/self/fd/" + fd.Name()); err == nil && strings.HasPrefix(l, "socket:[") {
			mine[strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]")] = true
		}
	}
	out := map[string]bool{}
	for _, f := range []string{"/proc/self/net/tcp", "/proc/self/net/tcp6"} {
		fd, err := os.Open(f)
		if err != nil {
			t.Skipf("no %s: %v", f, err)
		}
		sc := bufio.NewScanner(fd)
		for sc.Scan() {
			fs := strings.Fields(sc.Text())
			if len(fs) > 9 && fs[3] == "0A" && mine[fs[9]] {
				out[fs[1]] = true
			}
		}
		fd.Close()
	}
	return out
}

func lanRoute(rs []connectinvite.Route) *connectinvite.Route {
	for i := range rs {
		if rs[i].T == RouteLAN {
			return &rs[i]
		}
	}
	return nil
}

// With no configuration the host listens on its private addresses, lists them as the lan route,
// follows them when they change, and a phone pairs and connects there.
func TestLANByDefault(t *testing.T) {
	addrs := []netip.Addr{loopback}
	ch := make(chan []netip.Addr, 1)
	withLANAddrs(t, func() []netip.Addr {
		select {
		case a := <-ch:
			addrs = a
		default:
		}
		return addrs
	})
	h, _, _ := newTestHost(t, Config{})
	serveApp(t, h)
	p, err := h.Pair(context.Background(), PairOptions{Confirm: confirmAll})
	if err != nil {
		t.Fatal(err)
	}
	inv := p.InviteV2()
	r := lanRoute(inv.Via)
	if r == nil || len(r.A) != 1 || !strings.HasPrefix(r.A[0], "127.0.0.1:") {
		t.Fatalf("v2 invite routes %+v, want lan on 127.0.0.1", inv.Via)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	lanOnly := inv
	lanOnly.Via = []connectinvite.Route{*r}
	link, err := connectphone.PairV2(ctx, lanOnly, connectphone.NewKey(), connectphone.Options{Device: "Test Phone", OnSAS: func([]string) {}})
	if err != nil {
		t.Fatalf("pair over the automatic lan route: %v", err)
	}
	link.Address, link.Port = "", 0
	s, err := connectphone.Connect(link, connectphone.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if body, err := get(t, s); err != nil || !strings.HasSuffix(body, marker) {
		t.Fatalf("over the automatic lan route: %q %v", body, err)
	}
	// The address goes away: the listener closes and the route goes.
	ch <- nil
	deadline := time.Now().Add(5 * time.Second)
	for lanRoute(h.Routes()) != nil {
		if time.Now().After(deadline) {
			t.Fatal("the lan route stayed after its address went away")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if c, err := net.DialTimeout("tcp", r.A[0], time.Second); err == nil {
		c.Close()
		t.Fatal("still listening on a gone address")
	}
}

// The port comes from the host's Noise key: the same across restarts, different between hosts.
func TestLANPortIsStable(t *testing.T) {
	a, b := newIdentity(), newIdentity()
	pa := lanPortFor(a.noisePublic())
	if pa != lanPortFor(a.noisePublic()) || pa < 49152 || pa > 65535 {
		t.Fatalf("port %d", pa)
	}
	if pa == lanPortFor(b.noisePublic()) {
		t.Log("two hosts drew the same port (1 in 16384); not an error")
	}
}

// The automatic lan listener closes a connection from a public address before reading a byte.
func TestLANRefusesPublicSources(t *testing.T) {
	for _, tc := range []struct {
		addr string
		ok   bool
	}{{"192.168.1.9:5000", true}, {"10.0.0.2:1", true}, {"[fe80::1]:2", true}, {"127.0.0.1:3", true},
		{"[fd00::5]:4", true}, {"8.8.8.8:5", false}, {"[2001:db8::1]:6", false}, {"100.64.0.1:7", false}} {
		if got := lanSource(&addrConn{remote: net.TCPAddrFromAddrPort(netip.MustParseAddrPort(tc.addr))}); got != tc.ok {
			t.Errorf("lanSource(%s) = %v, want %v", tc.addr, got, tc.ok)
		}
	}
}

// Tailcat-only: no TCP listener anywhere, no relay, and invites and routes list only Tailcat. The
// same host without it does listen (the control).
func TestTailcatOnlyListensNowhere(t *testing.T) {
	withLANAddrs(t, func() []netip.Addr { return []netip.Addr{loopback} })
	before := listeningPorts(t)
	h, _, _ := newTestHost(t, Config{TailcatOnly: true})
	p, err := h.Pair(context.Background(), PairOptions{Confirm: confirmAll})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	for port := range listeningPorts(t) {
		if !before[port] {
			t.Fatalf("Tailcat-only host listens on %s", port)
		}
	}
	inv := p.InviteV2()
	if len(inv.Via) != 1 || inv.Via[0].T != RouteTailcat {
		t.Fatalf("Tailcat-only invite lists %+v", inv.Via)
	}
	for _, r := range h.Routes() {
		if r.T != RouteTailcat {
			t.Fatalf("Tailcat-only routes list %+v", r)
		}
	}
	h.Close()

	h2, _, _ := newTestHost(t, Config{})
	time.Sleep(100 * time.Millisecond)
	grew := false
	for port := range listeningPorts(t) {
		grew = grew || !before[port]
	}
	if !grew || lanRoute(h2.Routes()) == nil {
		t.Fatal("control: the default host opened no lan listener, so the check above proves nothing")
	}
}

func TestTailcatOnlyAndNoLANConfig(t *testing.T) {
	ok := func(State) error { return nil }
	for name, cfg := range map[string]Config{
		"tailcat-only with relay":  {Save: ok, TailcatOnly: true, Relays: []Relay{{URL: "wss://relay.example", Token: "t"}}},
		"tailcat-only with listen": {Save: ok, TailcatOnly: true, Listen: []string{"192.168.1.20:7681"}},
		"nolan with listen":        {Save: ok, NoLAN: true, Listen: []string{"192.168.1.20:7681"}},
		"opaque without app auth":  {Save: ok, Relays: []Relay{{URL: "wss://relay.example", Token: "t", Opaque: true}}},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: New accepted it", name)
		}
	}
	withLANAddrs(t, func() []netip.Addr { return []netip.Addr{loopback} })
	h, _, _ := newTestHost(t, Config{NoLAN: true})
	if lanRoute(h.Routes()) != nil {
		t.Fatal("NoLAN host lists a lan route")
	}
}

// The Noise key never equals the Tailcat key: a saved identity where it does is refused.
func TestNoiseKeyIsNotTheTailcatKey(t *testing.T) {
	id := newIdentity()
	if id.noise == id.key.Raw32() {
		t.Fatal("new identity reuses the Tailcat key")
	}
	var doc map[string]any
	_ = json.Unmarshal([]byte(id.String()), &doc)
	raw := id.key.Raw32()
	doc["noise"] = base64.RawURLEncoding.EncodeToString(raw[:])
	b, _ := json.Marshal(doc)
	if _, err := parseIdentity(string(b)); err == nil {
		t.Fatal("an identity whose Noise key is its Tailcat key was accepted")
	}
}
