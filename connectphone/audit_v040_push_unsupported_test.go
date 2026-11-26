package connectphone

// Audit of v0.4.0 (91b6d1b), item 1: a phone with push gives its target to a computer that still runs
// TailPocket v0.3.x, over lan or a relay (no Tailcat). docs/PUSH.md and the SDKs promise "push-unsupported"
// (ErrPushUnsupported) for a computer without push; over Tailcat it comes from the 404. On an encrypted
// session a v0.3.x computer reads the {"type":"push"} message and never answers (connecthost's
// drainControl), and pushSecure waits pushAckWait (10 s) for the ack before saying ErrPushUnsupported.
// But sendPush gives each route perRoute (10 s) too, started before the session is set up, so the
// route's context always ends first: the phone gets ErrUnreachable ("lan: context deadline exceeded"),
// connectmobile says "unreachable", and the app keeps retrying a computer that will never take a target.
//
// The computer here is connectsecure.Accept with v0.3.6's control loop: read and drop.

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/jt-wang/tailpocket/connectinvite"
	"github.com/jt-wang/tailpocket/connectpush"
	"github.com/jt-wang/tailpocket/connectsecure"
	"github.com/jt-wang/tailpocket/internal/testhook"
)

// auditV036Computer takes encrypted sessions on a loopback lan route as v0.3.6 did: every phone is let
// in, what it sends on the control stream is read and dropped, and no stream is served.
func auditV036Computer(t *testing.T) Link {
	t.Helper()
	id, err := connectsecure.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				s, err := connectsecure.Accept(c, connectsecure.ServerConfig{Identity: id, Version: "0.3.6",
					Admit: func(p connectsecure.Peer) (connectsecure.Admission, error) {
						return connectsecure.Admission{OK: true, Device: p.Phone}, nil
					}})
				if err != nil {
					return
				}
				defer s.Close()
				go func() { // v0.3.6 drainControl
					for {
						if _, err := s.Control().Recv(); err != nil {
							return
						}
					}
				}()
				for {
					st, err := s.AcceptStream()
					if err != nil {
						return
					}
					st.Close()
				}
			}()
		}
	}()
	return Link{Name: "v0.3.6 computer", Key: NewKey(), HostKey: base64.RawURLEncoding.EncodeToString(id.Public[:]),
		Via: []connectinvite.Route{{T: connectinvite.RouteLAN, A: []string{ln.Addr().String()}}}}
}

func TestAuditV040GivePushToAComputerWithoutPush(t *testing.T) {
	testhook.LoopbackRoutes = true
	link := auditV036Computer(t)
	key := make([]byte, 32)
	key[0] = 1
	target := connectpush.Target{Gateway: "https://push.example.com", App: "io.example.alpha", Handle: "HANDLE-hhhhhhhhhhhhhhhhhhhhhhhhhhhhhh",
		Kid: "kid-1", Key: base64.RawURLEncoding.EncodeToString(key)}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	connect := func() *Session {
		s, err := Connect(link, Options{Routes: []string{connectinvite.RouteLAN}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	}
	// The session is already up: the route's 10 s and the ack's 10 s start microseconds apart, and either
	// can end first.
	up := connect()
	c, err := up.Dial(ctx)
	if err != nil {
		t.Fatalf("the phone does not reach the v0.3.6 computer: %v", err)
	}
	c.Close()
	cases := []struct {
		what string
		call func() error
	}{
		// An app gives its target as soon as it has a connection: this call sets the encrypted session up,
		// inside the route's 10 s, so the route always ends before the ack's 10 s.
		{"GivePush, the first call of a session", func(s *Session) func() error { return func() error { return s.GivePush(ctx, target) } }(connect())},
		{"ClearPush, the first call of a session", func(s *Session) func() error { return func() error { return s.ClearPush(ctx) } }(connect())},
		{"GivePush, the session already up", func() error { return up.GivePush(ctx, target) }},
	}
	var wg sync.WaitGroup
	for _, tc := range cases {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			err := tc.call()
			t.Logf("%s, after %v: %v", tc.what, time.Since(start).Round(100*time.Millisecond), err)
			if !errors.Is(err, ErrPushUnsupported) {
				t.Errorf("%s, to a computer without push: %v, want ErrPushUnsupported (push-unsupported)", tc.what, err)
			}
		}()
	}
	wg.Wait()
}
