package connectphone

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jt-wang/tailpocket/connectinvite"
)

// Audit (fail closed), F1: Session.Forward (Connect on mobile) listens on 127.0.0.1 and carries
// every TCP connection to the host as the paired phone. Nothing tells the app's own connections
// from another process's: on Android every app may connect to another app's loopback port, and a
// web page in the phone's browser can open ws://127.0.0.1:PORT (WebSocket has no same-origin
// rule). Whoever finds the port (about 28,000 to try) reaches the computer's app port with this
// phone's identity. Here "another process" is a plain dial that presents nothing.
func TestAuditForwardCarriesAnyLocalProcess(t *testing.T) {
	var dials atomic.Int32
	hostSide := make(chan net.Conn, 1)
	f, err := startForward(func(ctx context.Context) (net.Conn, error) {
		dials.Add(1)
		a, b := net.Pipe()
		hostSide <- b
		return a, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	other, err := net.DialTimeout("tcp", f.Addr(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	go io.WriteString(other, "GET /from-another-app HTTP/1.1\r\n\r\n")
	select {
	case c := <-hostSide:
		defer c.Close()
		buf := make([]byte, 21)
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := io.ReadFull(c, buf)
		t.Fatalf("a local connection that presented no secret was carried to the host as this phone: %q (dials %d)", buf[:n], dials.Load())
	case <-time.After(time.Second):
	}
}

// Audit (fail closed), F2: a phone dials whatever a lan route names. A route comes from a scanned
// or tapped invite, or from a paired host. Loopback, public addresses and host names all pass, so
// one invite makes the phone open TCP connections to up to 16 x 8 addresses of the sender's
// choice, on the phone itself and on whatever network it is on, and keeps trying once a second
// until the pairing times out.
func TestAuditLanRouteAcceptsAnyAddress(t *testing.T) {
	for _, a := range []string{
		"127.0.0.1:22",       // the phone itself
		"[::1]:5037",         // the phone itself (adb)
		"8.8.8.8:53",         // a public address
		"example.com:25",     // a name, resolved by the phone
		"169.254.169.254:80", // link-local metadata address
	} {
		via := []connectinvite.Route{{T: connectinvite.RouteLAN, A: []string{a}}}
		if err := connectinvite.ValidateRoutes(via); err == nil {
			t.Errorf("a lan route to %s is accepted", a)
		}
	}
	// And the phone does dial it: a listener on loopback stands for a service on the phone.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4)
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		io.ReadFull(c, buf)
		got <- buf
	}()
	other, _ := parsePrivate(NewKey()) // any host key: the dial comes before the handshake
	link := Link{Name: "Mac", Key: NewKey(), HostKey: noisePublic(other),
		Via: []connectinvite.Route{{T: connectinvite.RouteLAN, A: []string{ln.Addr().String()}}}}
	s, err := Connect(link, Options{})
	if err != nil {
		return // refused at Connect: fixed
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go s.Dial(ctx)
	select {
	case b := <-got:
		t.Errorf("the phone connected to its own loopback service at %s and sent %q", ln.Addr(), b)
	case <-time.After(2 * time.Second):
	}
}
