// Package e2e runs the host and phone SDKs against each other over real Tailcat relays.
// Needs outbound internet; opt in with TAILPOCKET_LIVE=1.
package e2e

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jt-wang/tailpocket/connecthost"
	"github.com/jt-wang/tailpocket/connectinvite"
	"github.com/jt-wang/tailpocket/connectphone"
)

func live(t *testing.T) {
	t.Helper()
	if os.Getenv("TAILPOCKET_LIVE") != "1" {
		t.Skip("set TAILPOCKET_LIVE=1 to run over real Tailcat relays")
	}
}

type store struct {
	mu sync.Mutex
	st connecthost.State
}

func (s *store) save(st connecthost.State) error { s.mu.Lock(); s.st = st; s.mu.Unlock(); return nil }
func (s *store) get() connecthost.State          { s.mu.Lock(); defer s.mu.Unlock(); return s.st }

// serveEcho answers each connection with the phone's key on one line, then echoes.
func serveEcho(h *connecthost.Host) {
	go func() {
		for {
			c, err := h.Listener().Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.WriteString(c, connecthost.PhoneOf(c)+"\n")
				_, _ = io.Copy(c, c)
			}()
		}
	}()
}

// roundTrip dials until ctx ends and checks the greeting and an echo.
func roundTrip(t *testing.T, ctx context.Context, dial func(context.Context) (net.Conn, error), wantPhone string) {
	t.Helper()
	var conn net.Conn
	var err error
	for {
		attempt, cancel := context.WithTimeout(ctx, 20*time.Second)
		conn, err = dial(attempt)
		cancel()
		if err == nil || ctx.Err() != nil {
			break
		}
		t.Logf("dial: %v (retrying)", err)
		time.Sleep(time.Second)
	}
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	r := bufio.NewReader(conn)
	greeting, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("greeting: %v", err)
	}
	if strings.TrimSpace(greeting) != wantPhone {
		t.Fatalf("host identified the phone as %q, want %q", strings.TrimSpace(greeting), wantPhone)
	}
	if _, err := io.WriteString(conn, "ping\n"); err != nil {
		t.Fatal(err)
	}
	if echo, err := r.ReadString('\n'); err != nil || echo != "ping\n" {
		t.Fatalf("echo %q %v", echo, err)
	}
}

func TestLiveQRPairConnectRestartRevoke(t *testing.T) {
	live(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	st := &store{}
	h, err := connecthost.New(connecthost.Config{Name: "e2e host", Save: st.save})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Start(ctx); err != nil {
		t.Fatal(err)
	}
	serveEcho(h)
	started := time.Now()
	p, err := h.Pair(ctx, connecthost.PairOptions{TTL: 3 * time.Minute, Payload: func(ph connecthost.Phone) (string, error) { return "payload for " + ph.Device, nil }})
	if err != nil {
		t.Fatal(err)
	}
	qr, err := p.QR(connectinvite.DefaultPrefix)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("pairing window open after %v; QR text %d chars", time.Since(started).Round(time.Millisecond), len(qr))
	inv, err := connectinvite.Decode(qr, connectinvite.DefaultPrefix)
	if err != nil {
		t.Fatal(err)
	}

	phoneKey := connectphone.NewKey()
	phonePub, _ := connectphone.PublicKey(phoneKey)
	started = time.Now()
	pairCtx, pairCancel := context.WithTimeout(ctx, 90*time.Second)
	link, err := connectphone.Pair(pairCtx, inv, phoneKey, connectphone.Options{Device: "e2e phone"})
	pairCancel()
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	t.Logf("paired after %v", time.Since(started).Round(time.Millisecond))
	if link.Payload != "payload for e2e phone" || link.Address != h.Address() || link.Name != "e2e host" {
		t.Fatalf("link %+v", link)
	}
	joined, err := p.Wait(ctx)
	if err != nil || joined.Key != phonePub || joined.Device != "e2e phone" {
		t.Fatalf("wait %+v %v", joined, err)
	}

	s, err := connectphone.Connect(link, connectphone.Options{})
	if err != nil {
		t.Fatal(err)
	}
	started = time.Now()
	roundTrip(t, ctx, s.Dial, phonePub)
	t.Logf("first round trip after %v", time.Since(started).Round(time.Millisecond))

	f, err := s.Forward()
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, ctx, func(ctx context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(ctx, "tcp", f.Addr()) }, phonePub)
	f.Close()
	s.Close()

	// Restart from saved state: same address, the stored link still works.
	saved := st.get()
	h.Close()
	h2, err := connecthost.New(connecthost.Config{Name: "e2e host", Save: st.save, Identity: saved.Identity, Allowed: saved.Allowed})
	if err != nil {
		t.Fatal(err)
	}
	defer h2.Close()
	if err := h2.Start(ctx); err != nil {
		t.Fatal(err)
	}
	serveEcho(h2)
	if h2.Address() != link.Address {
		t.Fatal("address changed across a restart")
	}
	s2, _ := connectphone.Connect(link, connectphone.Options{})
	restartCtx, restartCancel := context.WithTimeout(ctx, 60*time.Second)
	roundTrip(t, restartCtx, s2.Dial, phonePub)
	restartCancel()
	defer s2.Close()
	t.Log("reconnected after host restart")
	// Keep this phone connected with its forwarder running, as an app would, across the revoke below.
	fw, err := s2.Forward()
	if err != nil {
		t.Fatal(err)
	}
	defer fw.Close()

	// Revoke: the phone can no longer reach the host.
	if err := h2.Revoke(ctx, phonePub); err != nil {
		t.Fatal(err)
	}
	s3, _ := connectphone.Connect(link, connectphone.Options{})
	defer s3.Close()
	revokedCtx, revokedCancel := context.WithTimeout(ctx, 15*time.Second)
	defer revokedCancel()
	if c, err := s3.Dial(revokedCtx); err == nil {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, rerr := bufio.NewReader(c).ReadString('\n'); rerr == nil {
			t.Fatal("revoked phone still reached the host")
		}
		c.Close()
	}
	t.Log("revoked phone refused")

	// The phone that was already connected dials again through its forwarder. The refused dial must
	// close the app's connection, not crash the app: Tailcat returns it as a nil *gonet.TCPConn
	// inside a non-nil net.Conn, and closing that panicked (found in an app integration, 2026-10-30).
	lc, err := net.Dial("tcp", fw.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	_ = lc.SetReadDeadline(time.Now().Add(30 * time.Second))
	if _, err := lc.Read(make([]byte, 1)); err == nil {
		t.Fatal("revoked phone read through the forwarder")
	} else if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("the forwarder neither connected nor closed the connection")
	}
	t.Log("forwarder closed the revoked phone's connection")
}

func TestLiveSameWiFiPairing(t *testing.T) {
	live(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	st := &store{}
	name := "tailpocket e2e " + time.Now().Format("150405")
	h, err := connecthost.New(connecthost.Config{Name: name, Save: st.save})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if err := h.Start(ctx); err != nil {
		t.Fatal(err)
	}
	serveEcho(h)
	p, err := h.Pair(ctx, connecthost.PairOptions{TTL: 2 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	const service = "_tcce2e._tcp"
	hostCode := make(chan string, 1)
	served := make(chan error, 1)
	go func() {
		served <- p.ServeLocal(ctx, connecthost.LocalOptions{Service: service, Confirm: func(_ context.Context, code, device string) bool {
			hostCode <- code
			return device == "wifi phone"
		}})
	}()
	entries, err := connectphone.Discover(ctx, service)
	if err != nil {
		t.Fatal(err)
	}
	var addr string
	for e := range entries {
		if e.Instance == name {
			addr = e.Addr()
			t.Logf("found %q at %s", e.Instance, addr)
			break
		}
	}
	if addr == "" {
		t.Fatal("host not discovered")
	}
	var phoneCode string
	inv, err := connectphone.PairLocal(ctx, addr, connectphone.LocalOptions{Device: "wifi phone", OnCode: func(c string) { phoneCode = c }})
	if err != nil {
		t.Fatalf("local pair: %v", err)
	}
	if code := <-hostCode; code != phoneCode {
		t.Fatalf("codes differ: host %s phone %s", code, phoneCode)
	}
	if err := <-served; err != nil {
		t.Fatalf("ServeLocal: %v", err)
	}
	phoneKey := connectphone.NewKey()
	pub, _ := connectphone.PublicKey(phoneKey)
	link, err := connectphone.Pair(ctx, inv, phoneKey, connectphone.Options{Device: "wifi phone"})
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	s, _ := connectphone.Connect(link, connectphone.Options{})
	defer s.Close()
	roundTrip(t, ctx, s.Dial, pub)
}
