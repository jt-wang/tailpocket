package e2e

// On a network that blocks UDP (a company or hotel network), Tailcat reaches the other side over its
// DERP relays only. Run it that way with scripts/e2e-udp-block.sh on (Linux, root), both sides
// Tailcat-only. Every step has a time limit:
//   - a refusal reaches the phone, and the phone's pairing node closes, within seconds;
//   - revoking the computer's last phone closes that phone's open connection at once (before v0.3.1
//     the main node stopped first and the phone kept the connection until its own timeout);
//   - the phone's session and the Host (SIGTERM in the helper) close within seconds.
// With TS_DEBUG_ALWAYS_USE_DERP=1, tailscale.com's magicsock leaves a WireGuard receive goroutine
// parked for good and tailcat's Close never returns (tailscale/tailscale#22524); this test then hangs
// without internal/closing.

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jt-wang/tailpocket/connecthost"
	"github.com/jt-wang/tailpocket/connectphone"
)

const relayOnlyLimit = 5 * time.Second

func TestLiveRelayOnly(t *testing.T) {
	live(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	within := func(what string, start time.Time) {
		t.Helper()
		d := time.Since(start)
		t.Logf("%s: %v", what, d.Round(time.Millisecond))
		if d > relayOnlyLimit {
			t.Fatalf("%s took %v, limit %v", what, d, relayOnlyLimit)
		}
	}
	st := &store{}
	h, err := connecthost.New(connecthost.Config{Name: "relay only", Save: st.save, TailcatOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if err := h.Start(ctx); err != nil {
		t.Fatal(err)
	}
	serveEcho(h)
	opts := connectphone.Options{Device: "relay only", TailcatOnly: true, OnSAS: func([]string) {}}

	// Refusal.
	asked := make(chan time.Time, 1)
	p, err := h.Pair(ctx, connecthost.PairOptions{Confirm: func(context.Context, connecthost.PairRequest) bool {
		asked <- time.Now()
		return false
	}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = connectphone.PairV2(ctx, p.InviteV2(), connectphone.NewKey(), opts)
	if !errors.Is(err, connectphone.ErrUnauthorized) {
		t.Fatalf("pairing after a no: %v, want ErrUnauthorized", err)
	}
	within("refusal to the phone, its pairing node closed", <-asked)
	start := time.Now()
	p.Close()
	within("pairing window close", start)

	// The last phone: pair, hold a connection, revoke.
	p, err = h.Pair(ctx, connecthost.PairOptions{Confirm: func(context.Context, connecthost.PairRequest) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	phoneKey := connectphone.NewKey()
	phonePub, _ := connectphone.PublicKey(phoneKey)
	link, err := connectphone.PairV2(ctx, p.InviteV2(), phoneKey, opts)
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	s, err := connectphone.Connect(link, connectphone.Options{TailcatOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	conn, r := held(t, ctx, s, phonePub)
	defer conn.Close()
	// With UDP blocked the route is DERP, named by its region. TAILPOCKET_EXPECT_DERP=1 (set while
	// scripts/e2e-udp-block.sh is on) accepts nothing else: a direct route then means UDP got through.
	derpOnly := os.Getenv("TAILPOCKET_EXPECT_DERP") == "1"
	if rt, err := s.Route(ctx); err != nil || rt.Kind != connectphone.KindDERP && (derpOnly || rt.Kind != connectphone.KindDirect) ||
		rt.Kind == connectphone.KindDERP && (rt.DERPRegion == 0 || rt.DERPCode == "" && rt.DERPHost == "") {
		t.Errorf("route %+v %v", rt, err)
	} else {
		t.Logf("route: %+v", rt)
	}
	ended := make(chan error, 1)
	go func() {
		_ = conn.SetReadDeadline(time.Now().Add(time.Minute))
		_, err := r.ReadByte()
		ended <- err
	}()
	start = time.Now()
	if err := h.Revoke(ctx, phonePub); err != nil {
		t.Fatal(err)
	}
	within("Revoke", start)
	select {
	case err := <-ended:
		if timedOut(err) {
			t.Fatalf("the revoked phone's connection read timed out instead of closing: %v", err)
		}
		within("revoked phone's open connection closed", start)
	case <-time.After(relayOnlyLimit):
		t.Fatalf("the revoked phone's open connection is still open %v after the revoke", relayOnlyLimit)
	}

	start = time.Now()
	_ = s.Close()
	within("phone session close", start)
	start = time.Now()
	_ = h.Close()
	within("Host close", start)
}
