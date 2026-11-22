package connectphone

// Audit of v0.3.4, PoC A. Runs unchanged, and passes, on v0.3.3 and v0.3.4.
//
// CHANGELOG v0.3.4 says of the last route: "Before, only the caller bounded it, and the forward never
// did, so on a network that drops packets an attempt could hang as long as the app kept the connection
// open." Session.Forward has bounded every Dial with max(20 s, routes x 10 s) since before v0.3.3, so a
// request through the forward already ended: a lan address that takes the connection and never
// answers after 10 s (the handshake's own limit), a relay that never answers after 20 s. The same
// bounds mean the new 30 s is not what ends a Dial made through the forward.

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/jt-wang/tailpocket/connectinvite"
	"github.com/jt-wang/tailpocket/internal/testhook"
)

func TestAuditV034ForwardEndsADialWithoutTheNewTimeout(t *testing.T) {
	testhook.LoopbackRoutes = true
	silent, err := net.Listen("tcp", "127.0.0.1:0") // takes the connection and never answers
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { silent.Close() }) // after the parallel subtests
	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			c.Close()
		}
	})
	for _, tc := range []struct {
		name     string
		route    connectinvite.Route
		min, max time.Duration
	}{
		// The handshake's own 10 s limit ends it.
		{"lan address that never answers", connectinvite.Route{T: connectinvite.RouteLAN, A: []string{silent.Addr().String()}}, 9 * time.Second, 12 * time.Second},
		// Session.Forward's own 20 s ends it, in v0.3.4 too (20 s is less than the new 30 s).
		{"relay that never answers", connectinvite.Route{T: connectinvite.RouteRelay, U: "ws://" + silent.Addr().String(), R: "AAAAAAAAAAAAAAAAAAAAAA"}, 19 * time.Second, 23 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, err := Connect(Link{Name: "Mac", Key: NewKey(), HostKey: auditSomeHostKey(t), Via: []connectinvite.Route{tc.route}}, Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			f, err := s.Forward()
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			// The app: one request, and it keeps its connection open for as long as it takes (90 s here).
			c, err := net.Dial("tcp", f.Addr())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			start := time.Now()
			if _, err := io.WriteString(c, "GET "+f.BasePath()+"/ HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			_ = c.SetReadDeadline(time.Now().Add(90 * time.Second))
			_, err = io.ReadAll(c)
			took := time.Since(start)
			t.Logf("the forward closed the app's connection after %s (read error: %v)", took.Round(100*time.Millisecond), err)
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Fatalf("the request hung for the whole 90 s: the forward did not end the Dial")
			}
			if took < tc.min || took > tc.max {
				t.Fatalf("ended after %s, want %s to %s", took, tc.min, tc.max)
			}
		})
	}
}

// auditSomeHostKey is a valid Noise public key nobody on this network holds the private half of.
func auditSomeHostKey(t *testing.T) string {
	t.Helper()
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(pub)
}
