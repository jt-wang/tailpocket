package connectphone

// Audit of v0.3.5, item 2: v0.3.5 took the 30 s bound of v0.3.4 off the last route again. Does any Dial
// now go on for ever, and does a network that drops packets end in no-answer?
//
//   - TestAuditV035DirectDialWithoutADeadline: Session.Dial(context.Background()), the Go API used
//     without the forward, against a last route that takes the connection and never answers. lan and
//     Tailcat end by themselves (10 s). A relay does not: nothing bounds the WebSocket upgrade.
//   - TestAuditV035DroppedPackets (AUDIT_DROP=1, in a container whose firewall drops every packet that
//     leaves): a link with Tailcat, lan and relay, through the forward, as the apps use it.

import (
	"context"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jt-wang/tailpocket/connectinvite"
	"github.com/jt-wang/tailpocket/internal/testhook"
)

// auditSilent takes connections and never answers.
func auditSilent(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			c.Close()
		}
	})
	return ln.Addr().String()
}

func TestAuditV035DirectDialWithoutADeadline(t *testing.T) {
	testhook.LoopbackRoutes = true
	silent := auditSilent(t)
	const watch = 75 * time.Second
	for _, tc := range []struct {
		name string
		link Link
	}{
		{"lan last", Link{Name: "Mac", Key: NewKey(), HostKey: auditSomeHostKey(t),
			Via: []connectinvite.Route{{T: connectinvite.RouteLAN, A: []string{silent}}}}},
		{"tailcat last", Link{Address: testAddress(t), Port: 48931, Name: "Mac", Key: NewKey()}},
		{"relay last", Link{Name: "Mac", Key: NewKey(), HostKey: auditSomeHostKey(t),
			Via: []connectinvite.Route{{T: connectinvite.RouteRelay, U: "ws://" + silent, R: "AAAAAAAAAAAAAAAAAAAAAA"}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, err := Connect(tc.link, Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			done := make(chan error, 1)
			start := time.Now()
			go func() {
				c, err := s.Dial(context.Background()) // no deadline: the caller relies on the library
				if err == nil {
					c.Close()
				}
				done <- err
			}()
			select {
			case err := <-done:
				f, _ := s.LastFailure()
				t.Logf("Dial ended after %s: reason %q, routes %v (%v)", time.Since(start).Round(100*time.Millisecond), f.Reason, f.Routes, err != nil)
				if f.Reason != ReasonNoAnswer {
					t.Fatalf("reason %q, want no-answer", f.Reason)
				}
			case <-time.After(watch):
				_, recorded := s.LastFailure()
				t.Fatalf("Dial still running after %s, LastFailure recorded: %v: nothing but the caller's context ends it", watch, recorded)
			}
		})
	}
}

func TestAuditV035DroppedPackets(t *testing.T) {
	if os.Getenv("AUDIT_DROP") == "" {
		t.Skip("set AUDIT_DROP=1 in a network that drops every packet")
	}
	link := func(relay string) Link {
		return Link{Address: testAddress(t), Port: 48931, Name: "Mac", Key: NewKey(), HostKey: auditSomeHostKey(t),
			Via: []connectinvite.Route{
				{T: connectinvite.RouteLAN, A: []string{"10.77.0.9:7681"}},
				{T: connectinvite.RouteRelay, U: relay, R: "AAAAAAAAAAAAAAAAAAAAAA"},
			}}
	}
	// request makes the app's one request through the forward and returns when the forward closes it,
	// or when the app gives up after appWaits.
	request := func(t *testing.T, f *Forward, appWaits time.Duration) (took time.Duration, gaveUp bool) {
		c, err := net.Dial("tcp", f.Addr())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		start := time.Now()
		if _, err := io.WriteString(c, "GET "+f.BasePath()+"/ HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(appWaits))
		_, err = io.ReadAll(c)
		ne, ok := err.(net.Error)
		return time.Since(start), ok && ne.Timeout()
	}
	for _, tc := range []struct {
		name, relay string
		appWaits    time.Duration
	}{
		{"the app waits; relay by address", "wss://198.51.100.7", 120 * time.Second},
		{"the app waits; relay by name", "wss://relay.example.net", 120 * time.Second},
		{"the app gives up after 5 s", "wss://198.51.100.7", 5 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, err := Connect(link(tc.relay), Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			f, err := s.Forward()
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			start := time.Now()
			took, gaveUp := request(t, f, tc.appWaits)
			fail, ok := s.LastFailure()
			if gaveUp {
				t.Logf("the app gave up after %s; LastFailure right then: recorded=%v reason=%q", took.Round(100*time.Millisecond), ok, fail.Reason)
			} else {
				t.Logf("the forward closed the app's connection after %s", took.Round(100*time.Millisecond))
			}
			for !ok && time.Since(start) < 120*time.Second {
				time.Sleep(100 * time.Millisecond)
				fail, ok = s.LastFailure()
			}
			t.Logf("LastFailure after %s: recorded=%v reason=%q routes=%v", time.Since(start).Round(100*time.Millisecond), ok, fail.Reason, fail.Routes)
			if !ok || fail.Reason != ReasonNoAnswer {
				t.Fatalf("want no-answer")
			}
			if d := time.Since(start); d > 35*time.Second {
				t.Fatalf("no-answer only after %s, want within max(20 s, 3 routes x 10 s) = 30 s", d)
			}
		})
	}
}
