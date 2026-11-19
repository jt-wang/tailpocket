package connectrelay_test

import (
	"crypto/ed25519"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/jt-wang/tailpocket/connectrelay"
)

// fakeConn is a TCP connection from a made-up address. Only RemoteAddr and
// Close are used by the listener.
type fakeConn struct {
	net.Conn
	remote net.Addr
	once   sync.Once
	closed chan struct{}
}

func (c *fakeConn) RemoteAddr() net.Addr { return c.remote }
func (c *fakeConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

type fakeLn struct {
	ch   chan net.Conn
	done chan struct{}
}

func (l *fakeLn) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *fakeLn) Close() error   { close(l.done); return nil }
func (l *fakeLn) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

// limitRig runs Accept on the server's listener in the background; push
// hands it one connection and says whether it came out or was closed.
type limitRig struct {
	t    *testing.T
	in   *fakeLn
	out  chan net.Conn
	logs *syncBuf
}

func newLimitRig(t *testing.T, mod func(*connectrelay.Config)) *limitRig {
	logs := &syncBuf{}
	cfg := connectrelay.Config{Token: testToken, PublicHost: testPublicHost, Logger: log.New(logs, "", 0)}
	if mod != nil {
		mod(&cfg)
	}
	srv, err := connectrelay.NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	in := &fakeLn{ch: make(chan net.Conn), done: make(chan struct{})}
	ln := srv.Listener(in)
	r := &limitRig{t: t, in: in, out: make(chan net.Conn), logs: logs}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			r.out <- c
		}
	}()
	t.Cleanup(func() { ln.Close(); srv.Close() })
	return r
}

// push returns the accepted connection, or nil if the listener closed it.
func (r *limitRig) push(addr string) net.Conn {
	r.t.Helper()
	c := &fakeConn{remote: net.TCPAddrFromAddrPort(netip.MustParseAddrPort(addr)), closed: make(chan struct{})}
	r.in.ch <- c
	select {
	case got := <-r.out:
		if got.RemoteAddr().String() != c.remote.String() {
			r.t.Fatalf("accepted %v, pushed %v", got.RemoteAddr(), c.remote)
		}
		return got
	case <-c.closed:
		return nil
	case <-time.After(3 * time.Second):
		r.t.Fatalf("connection from %s neither accepted nor closed", addr)
		return nil
	}
}

func TestConnLimitTotal(t *testing.T) {
	r := newLimitRig(t, func(c *connectrelay.Config) { c.MaxConns = 3 })
	var held []net.Conn
	for _, a := range []string{"192.0.2.1:1001", "192.0.2.2:1002", "192.0.2.3:1003"} {
		c := r.push(a)
		if c == nil {
			t.Fatalf("connection from %s closed under the limit", a)
		}
		held = append(held, c)
	}
	if c := r.push("192.0.2.4:1004"); c != nil {
		t.Fatal("4th connection with MaxConns 3 was accepted")
	}
	if l := r.logs.String(); !strings.Contains(l, "refused room=- why=max-conns") || strings.Contains(l, "192.0.2") {
		t.Fatalf("want one refused why=max-conns line without the address:\n%s", l)
	}
	held[0].Close()
	held[0].Close() // a second Close must not give back a second slot
	if c := r.push("192.0.2.5:1005"); c == nil {
		t.Fatal("no room for a connection after one closed")
	}
	if c := r.push("192.0.2.6:1006"); c != nil {
		t.Fatal("closing one connection twice freed two slots")
	}
}

func TestConnLimitPerAddress(t *testing.T) {
	r := newLimitRig(t, nil)
	for i := 0; i < connectrelay.DefaultMaxConnsPerAddr; i++ {
		if r.push(netip.AddrPortFrom(netip.MustParseAddr("192.0.2.10"), uint16(2000+i)).String()) == nil {
			t.Fatalf("connection %d from one address closed, want %d allowed", i+1, connectrelay.DefaultMaxConnsPerAddr)
		}
	}
	if r.push("192.0.2.10:3000") != nil {
		t.Fatalf("connection %d from one address accepted", connectrelay.DefaultMaxConnsPerAddr+1)
	}
	if r.push("192.0.2.11:3000") == nil {
		t.Fatal("another address was closed too")
	}
	if l := r.logs.String(); !strings.Contains(l, "why=addr-conns") || strings.Contains(l, "192.0.2") {
		t.Fatalf("want a refused why=addr-conns line without the address:\n%s", l)
	}
	// IPv6 counts by /64: two addresses in one /64 share the 64.
	for i := 0; i < connectrelay.DefaultMaxConnsPerAddr; i++ {
		a := "2001:db8:1:1::a"
		if i%2 == 1 {
			a = "2001:db8:1:1::b"
		}
		if r.push(netip.AddrPortFrom(netip.MustParseAddr(a), uint16(4000+i)).String()) == nil {
			t.Fatalf("IPv6 connection %d closed", i+1)
		}
	}
	if r.push("[2001:db8:1:1::c]:5000") != nil {
		t.Fatal("65th connection from one /64 accepted")
	}
	if r.push("[2001:db8:1:2::c]:5000") == nil {
		t.Fatal("another /64 was closed too")
	}
}

// A trusted proxy stands for many users: no per-address limit for it.
func TestConnLimitTrustedProxy(t *testing.T) {
	r := newLimitRig(t, func(c *connectrelay.Config) {
		c.TrustProxy = []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}
	})
	for i := 0; i < connectrelay.DefaultMaxConnsPerAddr+10; i++ {
		if r.push(netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(2000+i)).String()) == nil {
			t.Fatalf("connection %d from the trusted proxy closed", i+1)
		}
	}
}

// On a real listener: a connection that never sends a request line and an
// upgraded WebSocket both take a slot.
func TestConnLimitCountsIdleAndUpgraded(t *testing.T) {
	srv, err := connectrelay.NewServer(connectrelay.Config{Token: testToken, PublicHost: testPublicHost, MaxConns: 2})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(srv)
	inner := ts.Listener
	ts.Listener = srv.Listener(inner)
	ts.Start()
	t.Cleanup(func() { srv.Close(); ts.Close() })
	e := &env{t: t, srv: srv, ts: ts, logs: &syncBuf{}, pub: testPublicHost}

	ctx := ctxT(t, 10*time.Second)
	host, _ := e.mustHost(ctx) // slot 1: upgraded
	defer host.CloseNow()
	idle, err := net.Dial("tcp", inner.Addr().String()) // slot 2: no request
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	third, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	third.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := third.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("3rd connection with MaxConns 2: read %v, want it closed (EOF)", err)
	}
	idle.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := idle.Read(make([]byte, 1)); !isTimeout(err) {
		t.Fatalf("idle connection: %v, want it still open (read timeout)", err)
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// A handler that panics after the upgrade still gives its slot back: net/http
// does not close a hijacked connection, so the relay must.
func TestPanicAfterUpgradeGivesSlotBack(t *testing.T) {
	for _, path := range []string{connectrelay.PathHost, connectrelay.PathPhone, connectrelay.PathAccept} {
		t.Run(path, func(t *testing.T) {
			srv, err := connectrelay.NewServer(connectrelay.Config{Token: testToken, PublicHost: testPublicHost})
			if err != nil {
				t.Fatal(err)
			}
			srv.SetAfterUpgrade(func(p string) {
				if p == path {
					panic(http.ErrAbortHandler) // net/http recovers this one quietly
				}
			})
			ts := httptest.NewUnstartedServer(srv)
			ts.Listener = srv.Listener(ts.Listener)
			ts.Config.ErrorLog = log.New(io.Discard, "", 0)
			ts.Start()
			t.Cleanup(func() { srv.Close(); ts.Close() })
			e := &env{t: t, srv: srv, ts: ts, logs: &syncBuf{}, pub: testPublicHost}
			ctx := ctxT(t, 10*time.Second)

			want := 0
			var phone *websocket.Conn
			switch path {
			case connectrelay.PathHost:
				c, _, _ := dial(ctx, e.wsURL(connectrelay.PathHost+"?room="+connectrelay.RoomFor(mustPub(t))), bearer(testToken))
				if c != nil {
					defer c.CloseNow()
				}
			case connectrelay.PathPhone:
				host, room := e.mustHost(ctx)
				defer host.CloseNow()
				want = 1
				c, _, _ := e.phone(ctx, room)
				if c != nil {
					defer c.CloseNow()
				}
			case connectrelay.PathAccept:
				host, room := e.mustHost(ctx)
				defer host.CloseNow()
				want = 1
				phone, _, err = e.phone(ctx, room)
				if err != nil {
					t.Fatal(err)
				}
				defer phone.CloseNow()
				id, err := nextIncoming(ctx, host)
				if err != nil {
					t.Fatal(err)
				}
				c, _, _ := e.accept(ctx, room, id, testToken)
				if c != nil {
					defer c.CloseNow()
				}
				// The waiting phone is not left hanging on an accept that
				// will never come.
				code, err := waitClosed(ctxT(t, 3*time.Second), phone)
				if code != websocket.StatusGoingAway {
					t.Fatalf("phone after its accept's handler panicked: %v (%v), want 1001", code, err)
				}
			}
			deadline := time.Now().Add(3 * time.Second)
			for srv.ConnsForTest() != want {
				if time.Now().After(deadline) {
					t.Fatalf("%d connections counted after the %s handler panicked, want %d", srv.ConnsForTest(), path, want)
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}

func mustPub(t *testing.T) ed25519.PublicKey {
	pub, _ := newKey(t)
	return pub
}
