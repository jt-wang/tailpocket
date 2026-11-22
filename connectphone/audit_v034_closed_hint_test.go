package connectphone

// Audit of v0.3.4, PoC B (v0.3.4 only).
//
// SECURITY.md 6b: "refused from the lan route alone counts only when no route went unanswered: on a
// plane every other route times out while some device refuses the old lan address, and that is
// no-answer". The same network, with a device (or a captive portal, or an attacker on the Wi-Fi) that
// TAKES the connection to the old lan address and closes it, gives reason "handshake-closed", for which
// INTEGRATE.md has the app say "TailPocket isn't running on the computer, or it was reset ... pair
// again", although the computer was never reached and its other route went unanswered. Nothing here
// knows the computer's key: one accept and one close is enough.
//
// The test also shows what holds: the hint changes nothing. The link, its pinned key and its routes are
// as before, and the session is not revoked.

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/jt-wang/tailpocket/connectinvite"
	"github.com/jt-wang/tailpocket/connectsecure"
	"github.com/jt-wang/tailpocket/internal/testhook"
)

func TestAuditV034AnyDeviceCanSayTheComputerWasReset(t *testing.T) {
	// The rule itself: a lan refusal is discounted when another route went unanswered, a lan close is not.
	if r, _ := dialReason([]RouteFailure{{Route: "lan", Reason: RouteRefused}, {Route: "relay", Reason: ReasonNoAnswer}}); r != ReasonNoAnswer {
		t.Fatalf("lan refused + relay unanswered: %q, want no-answer", r)
	}
	guarded, _ := dialReason([]RouteFailure{{Route: "lan", Reason: ReasonHandshakeClosed}, {Route: "relay", Reason: ReasonNoAnswer}})

	// End to end, with nothing but a socket on the phone's network.
	testhook.LoopbackRoutes = true
	stranger, err := net.Listen("tcp", "127.0.0.1:0") // whatever holds the computer's old lan address here
	if err != nil {
		t.Fatal(err)
	}
	defer stranger.Close()
	go func() {
		for {
			c, err := stranger.Accept()
			if err != nil {
				return
			}
			go func() {
				buf := make([]byte, 4096)
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				_, _ = c.Read(buf) // the phone's first handshake message
				_ = c.Close()      // a clean close: no key, no answer
			}()
		}
	}()
	link := Link{Name: "Mac", Key: NewKey(), HostKey: auditSomeHostKey(t),
		Via: []connectinvite.Route{
			{T: connectinvite.RouteLAN, A: []string{stranger.Addr().String()}},
			// The phone's other route goes unanswered, as on a network that blocks it.
			{T: connectinvite.RouteRelay, U: "ws://127.0.0.1:1", R: "AAAAAAAAAAAAAAAAAAAAAA"},
		}}
	s, err := Connect(link, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err = s.Dial(ctx)
	if err == nil {
		t.Fatal("the Dial worked")
	}
	f, ok := s.LastFailure()
	if !ok {
		t.Fatal("no failure recorded")
	}
	t.Logf("Dial: %v", err)
	t.Logf("LastFailure: reason=%q route=%q routes=%v", f.Reason, f.Route, f.Routes)

	// What holds: a hint only.
	if s.Revoked() || errors.Is(err, ErrRevoked) {
		t.Fatal("the stranger's close revoked the phone")
	}
	if got := s.Link(); !reflect.DeepEqual(got, link) {
		t.Fatalf("the link changed: %+v", got)
	}
	if !errors.Is(err, connectsecure.ErrHandshakeClosed) {
		t.Fatalf("Dial: %v, want handshake-closed", err)
	}

	// The finding: the unanswered relay does not discount the lan close.
	if want := []RouteFailure{{Route: "lan", Reason: ReasonHandshakeClosed}, {Route: "relay", Reason: ReasonNoAnswer}}; !reflect.DeepEqual(f.Routes, want) {
		t.Fatalf("routes %v, want %v", f.Routes, want)
	}
	if f.Reason != ReasonNoAnswer || guarded != ReasonNoAnswer {
		t.Fatalf("reason %q (rule alone: %q), want no-answer: a close on the lan address alone, with another route unanswered, "+
			"is as weak as a lan refusal, and the app now says the computer was reset and offers pairing again", f.Reason, guarded)
	}
}
