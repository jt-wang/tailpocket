package e2e

// Without Tailcat (v0.3.2 Config.Routes and Options.Routes): a host and a phone that use only the
// local network, only a self-hosted tailpocket-relay, or both, pair with the emoji, connect, see
// revoke and close, and never create a Tailcat server or client. Everything runs on loopback (the
// relay too), so these need no internet and run without TAILPOCKET_LIVE. On Linux
// noTailcatSockets also checks that the process opens no socket beyond loopback; on the VM,
// scripts/e2e-no-tailcat.sh counts the test user's packets leaving loopback with iptables.

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jt-wang/tailpocket/connecthost"
	"github.com/jt-wang/tailpocket/connectinvite"
	"github.com/jt-wang/tailpocket/connectphone"
	"github.com/jt-wang/tailpocket/connectrelay"
	"github.com/jt-wang/tailpocket/internal/testhook"
)

// noTailcatHome points HOME and the XDG directories at an empty directory, and returns a check that
// nothing named tailcat was created there.
func noTailcatHome(t *testing.T) func() {
	dir := t.TempDir()
	for _, v := range []string{"HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "XDG_DATA_HOME"} {
		t.Setenv(v, filepath.Join(dir, strings.ToLower(v)))
	}
	return func() {
		t.Helper()
		_ = filepath.Walk(dir, func(p string, _ os.FileInfo, _ error) error {
			if strings.Contains(strings.ToLower(filepath.Base(p)), "tailcat") {
				t.Errorf("Tailcat state created: %s", p)
			}
			return nil
		})
	}
}

func localRelay(t *testing.T) string {
	srv, err := connectrelay.NewServer(connectrelay.Config{Token: "e2e-relay-token", PublicHost: "127.0.0.1", Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(func() { srv.Close(); ts.Close() })
	return "ws" + strings.TrimPrefix(ts.URL, "http")
}

func freeLoopback(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func TestNoTailcatLANOnly(t *testing.T) { noTailcat(t, []string{connectinvite.RouteLAN}) }
func TestNoTailcatRelayOnly(t *testing.T) {
	noTailcat(t, []string{connectinvite.RouteRelay})
}
func TestNoTailcatLANAndRelay(t *testing.T) {
	noTailcat(t, []string{connectinvite.RouteLAN, connectinvite.RouteRelay})
}

func noTailcat(t *testing.T, routes []string) {
	checkHome := noTailcatHome(t)
	checkSockets := noTailcatSockets(t)
	starts := testhook.TailcatStarts.Load()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	cfg := connecthost.Config{Name: "no tailcat", Routes: routes}
	for _, r := range routes {
		switch r {
		case connectinvite.RouteLAN:
			cfg.Listen = []string{freeLoopback(t)}
		case connectinvite.RouteRelay:
			cfg.Relays = []connecthost.Relay{{URL: localRelay(t), Token: "e2e-relay-token"}}
		}
	}
	st := &store{}
	cfg.Save = st.save
	h, err := connecthost.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if err := h.Start(ctx); err != nil {
		t.Fatal(err)
	}
	serveEcho(h)
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		up := true
		for _, err := range h.RelayStatus() {
			up = up && err == nil
		}
		if up {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("relay: %v", h.RelayStatus())
		}
	}
	var emoji []string
	p, err := h.Pair(ctx, connecthost.PairOptions{Confirm: func(_ context.Context, r connecthost.PairRequest) bool {
		emoji = r.Emoji
		return true
	}})
	if err != nil {
		t.Fatal(err)
	}
	text, err := p.QR2(connectinvite.DefaultPrefix2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.QR(connectinvite.DefaultPrefix); !errors.Is(err, connecthost.ErrNoTailcat) {
		t.Fatalf("v1 QR without Tailcat: %v", err)
	}
	inv, err := connectinvite.DecodeV2(text, connectinvite.DefaultPrefix2)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range inv.Via {
		if r.T == connectinvite.RouteTailcat {
			t.Fatalf("invite lists Tailcat: %+v", inv.Via)
		}
	}
	opts := connectphone.Options{Device: "no tailcat", Routes: routes, OnSAS: func([]string) {}}
	key := connectphone.NewKey()
	pub, _ := connectphone.PublicKey(key)
	link, err := connectphone.PairV2(ctx, inv, key, opts)
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	if len(emoji) != 4 || link.Address != "" || link.HostKey != inv.PK {
		t.Fatalf("emoji %v, link %+v", emoji, link)
	}
	if st.get().Keys[pub] == "" || h.Address() != "" {
		t.Fatalf("host state %+v, address %q", st.get(), h.Address())
	}
	s, err := connectphone.Connect(link, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	roundTrip(t, ctx, s.Dial, pub)
	r, err := s.Route(ctx)
	if err != nil || (r.Kind != connectphone.KindLAN && r.Kind != connectphone.KindRelay) {
		t.Fatalf("Route %+v %v", r, err)
	}
	t.Logf("route: %+v", r)
	if _, err := s.Sync(ctx); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	// Revoke: the phone hears it, encrypted, on its route.
	if err := h.Revoke(ctx, pub); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		c, err := s.Dial(ctx)
		if c != nil {
			c.Close()
		}
		if errors.Is(err, connectphone.ErrRevoked) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after revoke: %v, want ErrRevoked", err)
		}
	}
	start := time.Now()
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("Close took %v", d)
	}
	if n := testhook.TailcatStarts.Load() - starts; n != 0 {
		t.Fatalf("%d Tailcat servers or clients created", n)
	}
	checkSockets()
	checkHome()
}
