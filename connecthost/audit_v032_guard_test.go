package connecthost

// Audit of v0.3.2 (42d9679): guard tests. They pass. They cover what v0.3.2 newly rests on: a host
// without Tailcat knows a phone only by its Noise key, pairs only over lan and relay, and has no
// Tailcat node to fall back on.
//
// Checked by breaking the host one check at a time: these tests fail when admit lets in a phone whose
// Noise key the host does not hold, when admitPairing skips the emoji question, and when it skips the
// nodekey proof. They do not tell apart admitPairing's early "paired-without-this-key" refusal from
// its last check (h.noise[k] == peer.Static), which refuses the same phone. Keeping a removed phone's
// Noise key while restartMain runs is caught by TestAuditRemovedPhoneKeepsItsRelaySessionWhileTheNodeLingers.
//
//   - TestAuditV032NoTailcatOnlyAPairedPhoneGetsIn: strangers, a claimed nodekey, someone holding
//     the whole QR code, a machine posing as the computer, a revoked phone and a phone whose key the
//     host lost get nothing on lan or relay.
//   - TestAuditV032EmojiIsTheHandshakeSASOnEveryRouteSet (D1): on all seven route sets and every
//     route in each invite, the four emoji on both ends are HKDF-SHA256(handshake hash,
//     "tailpocket2 sas"), worked out here without the library; without Tailcat a no, or the phone
//     hanging up while the computer asks, spends the code, and no window pairs without the emoji.
//   - TestAuditV032SameWiFiLimitsOnEveryRouteSet (H1): with Tailcat in the set, same-Wi-Fi pairing
//     keeps its three commitments per window and ends the window, QR code included; without Tailcat
//     it opens no listener and advertises nothing.
//   - TestAuditV032NodekeyClaim (SECURITY.md "Not defended"): what an invite holder can still do
//     with another phone's nodekey, with and without Tailcat.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"
	"tailscale.com/types/key"

	"github.com/jt-wang/tailpocket/connectinvite"
	"github.com/jt-wang/tailpocket/connectlocal"
	"github.com/jt-wang/tailpocket/connectmdns"
	"github.com/jt-wang/tailpocket/connectphone"
	"github.com/jt-wang/tailpocket/connectrelay"
	"github.com/jt-wang/tailpocket/connectsecure"
)

var (
	auditNoTailcatSets = [][]string{{RouteLAN}, {RouteRelay}, {RouteLAN, RouteRelay}}
	auditTailcatSets   = [][]string{{RouteTailcat}, {RouteTailcat, RouteLAN}, {RouteTailcat, RouteRelay}, {RouteTailcat, RouteLAN, RouteRelay}}
)

// auditConfig is a host config running exactly set.
func auditConfig(t *testing.T, set []string) Config {
	t.Helper()
	cfg := Config{Routes: set}
	if slices.Contains(set, RouteRelay) {
		cfg.Relays = []Relay{{URL: auditRelay(t), Token: relayToken}}
	}
	if slices.Contains(set, RouteLAN) {
		cfg.Listen = []string{freeAddr(t)}
	}
	return cfg
}

// auditRelay is startRelay without the relay's own limits on one source address (30 connections a
// minute, 4 at once in a room): every party of these tests dials from 127.0.0.1.
func auditRelay(t *testing.T) string {
	t.Helper()
	srv, err := connectrelay.NewServer(connectrelay.Config{Token: relayToken, PublicHost: "127.0.0.1", PhoneRate: 10000,
		MaxPhonesPerRoom: 64, MaxPhonesPerAddr: 64, Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(func() { srv.Close(); ts.Close() })
	return "ws" + strings.TrimPrefix(ts.URL, "http")
}

// auditNoiseKeys is the Noise key pair a phone derives from its Tailcat key (PROTOCOL.md).
func auditNoiseKeys(k key.NodePrivate) noise.DHKey {
	raw := k.Raw32()
	priv := sha256.Sum256(append([]byte("tailpocket2 noise key\n"), raw[:]...))
	pub, _ := curve25519.X25519(priv[:], curve25519.Basepoint)
	return noise.DHKey{Private: priv[:], Public: pub}
}

func auditHostKey(t *testing.T, pk string) [32]byte {
	t.Helper()
	var server [32]byte
	raw, err := base64.RawURLEncoding.DecodeString(pk)
	if err != nil || len(raw) != 32 {
		t.Fatalf("host key %q", pk)
	}
	copy(server[:], raw)
	return server
}

// auditDial opens the byte pipe of an encrypted route, as anyone who knows the route can.
func auditDial(t *testing.T, r connectinvite.Route) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if r.T != RouteRelay {
		c, err := (&net.Dialer{}).DialContext(ctx, "tcp", r.A[0])
		if err != nil {
			t.Fatalf("dial %s: %v", r.T, err)
		}
		return c
	}
	// The relay gives one source address 4 places in a room and frees one a moment after its
	// connection closed: wait for a place.
	for {
		c, err := connectrelay.DialPhone(ctx, r.U, r.R, nil)
		if err == nil {
			return c
		}
		select {
		case <-ctx.Done():
			t.Fatalf("dial %s: %v", r.T, err)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// auditConnect is a connect handshake written out by hand: static is the caller's Noise key, claim
// the nodekey its hello names.
func auditConnect(t *testing.T, r connectinvite.Route, server [32]byte, static noise.DHKey, claim string) (*connectsecure.Session, error) {
	t.Helper()
	return connectsecure.Dial(auditDial(t, r), connectsecure.ClientConfig{Static: static, Server: server, Version: "audit", Phone: claim})
}

// auditPair is a pairing handshake written out by hand. signer signs the nodekey proof; claim is
// the nodekey the hello names (signer's own for an honest phone).
func auditPair(t *testing.T, r connectinvite.Route, server [32]byte, code string, static noise.DHKey, claim string, signer key.NodePrivate, onSAS func([]string)) (*connectsecure.Session, error) {
	t.Helper()
	return auditPairOn(auditDial(t, r), server, code, static, claim, signer, onSAS)
}

func auditPairOn(c net.Conn, server [32]byte, code string, static noise.DHKey, claim string, signer key.NodePrivate, onSAS func([]string)) (*connectsecure.Session, error) {
	return connectsecure.Dial(c, connectsecure.ClientConfig{Static: static, Server: server, Version: "audit",
		Pair:   &connectsecure.PairHello{CID: connectsecure.CIDFor(code), PSK: connectsecure.PSKFor(code)},
		Device: "Audit", Phone: claim, OnSAS: onSAS,
		Prove: func(b []byte) ([]byte, error) {
			raw := signer.Raw32()
			return connectsecure.KeyProof(raw[:], server, connectinvite.ProofPair, b)
		}})
}

func auditEncrypted(rs []connectinvite.Route) []connectinvite.Route {
	var out []connectinvite.Route
	for _, r := range rs {
		if r.T == RouteLAN || r.T == RouteRelay {
			out = append(out, r)
		}
	}
	return out
}

func TestAuditV032NoTailcatOnlyAPairedPhoneGetsIn(t *testing.T) {
	for _, set := range auditNoTailcatSets {
		t.Run(strings.Join(set, "+"), func(t *testing.T) {
			noUpgrade(t)
			cfg := auditConfig(t, set)
			h, f, sv := newTestHost(t, cfg)
			if slices.Contains(set, RouteRelay) {
				waitRelay(t, h)
			}
			app := serveCounting(t, h)
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			routes := auditEncrypted(h.Routes())
			if len(routes) != len(set) {
				t.Fatalf("routes %+v", h.Routes())
			}

			// A phone pairs and connects, as the library does it. What the relay or the Wi-Fi carries
			// of it holds nothing readable.
			w := &wire{}
			opts := connectphone.Options{Device: "Phone A", OnSAS: func([]string) {}, Routes: set, HTTPClient: w.client()}
			p, err := h.Pair(ctx, PairOptions{Confirm: confirmAll, Payload: func(Phone) (string, error) { return "app-token-secret-9", nil }})
			if err != nil {
				t.Fatal(err)
			}
			inv := p.InviteV2()
			server := auditHostKey(t, inv.PK)
			a := key.NewNode()
			aText, _ := a.MarshalText()
			aPub := a.Public().String()
			link, err := connectphone.PairV2(ctx, inv, string(aText), opts)
			if err != nil {
				t.Fatalf("pair: %v", err)
			}
			if link.Address != "" || link.HostKey != inv.PK || link.Payload != "app-token-secret-9" {
				t.Fatalf("link %+v", link)
			}
			s, err := connectphone.Connect(link, opts)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if body, err := get(t, s); err != nil || body != aPub+" "+marker {
				t.Fatalf("paired phone: %q %v", body, err)
			}
			if slices.Contains(set, RouteRelay) && w.len() == 0 {
				t.Fatal("control: the wire recorded nothing")
			}
			for _, secret := range []string{marker, "app-token-secret-9", inv.PSK, aPub, "Phone A"} {
				if w.has(secret) {
					t.Fatalf("the relay saw %q", secret)
				}
			}
			requests := app.total()
			same := func(what string) {
				t.Helper()
				if got := h.Allowed(); len(got) != 1 || got[0] != aPub {
					t.Fatalf("%s: allowed %v", what, got)
				}
				if app.total() != requests {
					t.Fatalf("%s: the app got %d requests, had %d", what, app.total(), requests)
				}
			}

			for _, r := range routes {
				// 1. A key that never paired: told unpaired.
				stranger := key.NewNode()
				if _, err := auditConnect(t, r, server, auditNoiseKeys(stranger), stranger.Public().String()); !errors.Is(err, connectsecure.ErrUnpaired) {
					t.Fatalf("%s: a stranger: %v, want unpaired", r.T, err)
				}
				// 2. A stranger's key under the paired phone's name: not admitted, and not unpaired
				// either (unpaired would make a phone that hears it delete its link).
				if sess, err := auditConnect(t, r, server, auditNoiseKeys(stranger), aPub); err == nil {
					sess.Close()
					t.Fatalf("%s: a stranger naming the paired phone got a session", r.T)
				}
				// 3. No window open: a pairing with any code finds none.
				if sess, err := auditPair(t, r, server, connectinvite.NewCode(), auditNoiseKeys(stranger), stranger.Public().String(), stranger, func([]string) {}); err == nil {
					sess.Close()
					t.Fatalf("%s: paired without a window", r.T)
				}
				same(r.T + ": strangers")
			}

			// 4. Someone who holds the whole QR code (the computer's key, the code, the routes).
			var asked []PairRequest
			var mu sync.Mutex
			decide := make(chan bool)
			asking := make(chan struct{}, 4)
			p2, err := h.Pair(ctx, PairOptions{Confirm: func(ctx context.Context, r PairRequest) bool {
				mu.Lock()
				asked = append(asked, r)
				mu.Unlock()
				asking <- struct{}{}
				select {
				case ok := <-decide:
					return ok
				case <-ctx.Done():
					return false
				}
			}})
			if err != nil {
				t.Fatal(err)
			}
			inv2 := p2.InviteV2()
			mallory, victim := key.NewNode(), key.NewNode()
			for _, r := range routes {
				// Another phone's nodekey, which Mallory cannot sign for: refused before anyone is asked.
				if sess, err := auditPair(t, r, server, inv2.PSK, auditNoiseKeys(mallory), victim.Public().String(), mallory, func([]string) {}); !errors.Is(err, connectsecure.ErrDenied) {
					if sess != nil {
						sess.Close()
					}
					t.Fatalf("%s: a claimed nodekey: %v, want denied", r.T, err)
				}
				// The paired phone's nodekey with Mallory's Noise key: the same.
				if sess, err := auditPair(t, r, server, inv2.PSK, auditNoiseKeys(mallory), aPub, mallory, func([]string) {}); !errors.Is(err, connectsecure.ErrDenied) {
					if sess != nil {
						sess.Close()
					}
					t.Fatalf("%s: the paired phone's nodekey under another key: %v, want denied", r.T, err)
				}
				// Its own key, but no emoji on its screen: refused.
				if sess, err := auditPair(t, r, server, inv2.PSK, auditNoiseKeys(mallory), mallory.Public().String(), mallory, nil); !errors.Is(err, connectsecure.ErrDenied) {
					if sess != nil {
						sess.Close()
					}
					t.Fatalf("%s: a pairing without emoji: %v, want denied", r.T, err)
				}
				// A code that is not this window's.
				if sess, err := auditPair(t, r, server, connectinvite.NewCode(), auditNoiseKeys(mallory), mallory.Public().String(), mallory, func([]string) {}); err == nil {
					sess.Close()
					t.Fatalf("%s: paired with another code", r.T)
				}
			}
			mu.Lock()
			if len(asked) != 0 {
				t.Fatalf("the computer's user was asked about %+v", asked)
			}
			mu.Unlock()
			same("the QR holder's refused tries")

			// It pairs with its own key, ahead of the user's phone. The computer asks once, with
			// Mallory's emoji; the user's phone shows other emoji or none, so the user says no, and the
			// code is spent.
			var malloryShown []string
			malloryDone := make(chan error, 1)
			go func() {
				sess, err := auditPair(t, routes[0], server, inv2.PSK, auditNoiseKeys(mallory), mallory.Public().String(), mallory, func(e []string) { malloryShown = e })
				if sess != nil {
					sess.Close()
				}
				malloryDone <- err
			}()
			select {
			case <-asking:
			case <-ctx.Done():
				t.Fatal("the computer never asked about Mallory")
			}
			var phoneShown []string
			b := connectphone.NewKey()
			_, berr := connectphone.PairV2(ctx, inv2, b, connectphone.Options{Device: "Phone B", Routes: set, OnSAS: func(e []string) { phoneShown = e }})
			if berr == nil {
				t.Fatal("the user's phone paired while the computer asked about Mallory")
			}
			mu.Lock()
			if len(asked) != 1 || asked[0].Phone != mallory.Public().String() || len(asked[0].Emoji) != 4 {
				t.Fatalf("the computer asked %+v", asked)
			}
			onComputer := asked[0].Emoji
			mu.Unlock()
			if slices.Equal(phoneShown, onComputer) {
				t.Fatalf("the user's phone shows the emoji of Mallory's pairing: %v", phoneShown)
			}
			decide <- false
			if err := <-malloryDone; !errors.Is(err, connectsecure.ErrDenied) {
				t.Fatalf("Mallory after the no: %v", err)
			}
			if !slices.Equal(malloryShown, onComputer) {
				t.Fatalf("control: Mallory's own emoji %v are not the computer's %v", malloryShown, onComputer)
			}
			select {
			case <-p2.Done():
			case <-time.After(5 * time.Second):
				t.Fatal("the window stayed open after the no")
			}
			if sess, err := auditPair(t, routes[0], server, inv2.PSK, auditNoiseKeys(mallory), mallory.Public().String(), mallory, func([]string) {}); err == nil {
				sess.Close()
				t.Fatal("the spent code paired")
			}
			same("the QR holder pairing ahead")

			// 5. Posing as the computer on the local network: another host, with its own key, answers
			// where the code says the computer is. The phone pinned the computer's key from the code:
			// no emoji, no pairing, and the fake computer's user is never asked.
			if slices.Contains(set, RouteLAN) {
				fakeAddr := freeAddr(t)
				fake, _, _ := newTestHost(t, Config{Routes: []string{RouteLAN}, Listen: []string{fakeAddr}})
				var fakeAsked atomic.Int32
				if _, err := fake.Pair(ctx, PairOptions{Confirm: func(context.Context, PairRequest) bool { fakeAsked.Add(1); return true }}); err != nil {
					t.Fatal(err)
				}
				p3, err := h.Pair(ctx, PairOptions{Confirm: confirmAll})
				if err != nil {
					t.Fatal(err)
				}
				posed := p3.InviteV2()
				posed.Via = lanVia(fakeAddr)
				shown := false
				pctx, pcancel := context.WithTimeout(ctx, 4*time.Second)
				_, err = connectphone.PairV2(pctx, posed, connectphone.NewKey(), connectphone.Options{Routes: []string{RouteLAN}, OnSAS: func([]string) { shown = true }})
				pcancel()
				if err == nil || shown || fakeAsked.Load() != 0 || len(fake.Allowed()) != 0 {
					t.Fatalf("phone at a fake computer: err %v, emoji shown %v, fake asked %d, fake allowed %v", err, shown, fakeAsked.Load(), fake.Allowed())
				}
				p3.Close()
				// And for a paired phone: handshake-closed, never revoked.
				moved := link
				moved.Via = lanVia(fakeAddr)
				ms, _ := connectphone.Connect(moved, connectphone.Options{Routes: []string{RouteLAN}})
				_, err = get(t, ms)
				ms.Close()
				if !errors.Is(err, connectsecure.ErrHandshakeClosed) || errors.Is(err, connectphone.ErrRevoked) {
					t.Fatalf("paired phone at a fake computer: %v, want handshake-closed", err)
				}
				same("a fake computer")
			}

			// 6. A revoked phone, with its real keys, on every route.
			if err := h.Revoke(ctx, aPub); err != nil {
				t.Fatal(err)
			}
			for _, r := range routes {
				if sess, err := auditConnect(t, r, server, auditNoiseKeys(a), aPub); !errors.Is(err, connectsecure.ErrUnpaired) {
					if sess != nil {
						sess.Close()
					}
					t.Fatalf("%s: a revoked phone: %v, want unpaired", r.T, err)
				}
			}
			if _, err := get(t, s); !errors.Is(err, connectphone.ErrRevoked) {
				t.Fatalf("the revoked phone's session: %v, want ErrRevoked", err)
			}
			if app.total() != requests || len(h.Allowed()) != 0 {
				t.Fatalf("after revoke: %d requests (had %d), allowed %v", app.total(), requests, h.Allowed())
			}

			// 7. A phone whose Noise key the host no longer has (state restored without keys): it is not
			// allowed on any route. Pair a phone, restart on the same routes with Allowed but no Keys.
			p4, err := h.Pair(ctx, PairOptions{Confirm: confirmAll})
			if err != nil {
				t.Fatal(err)
			}
			c := key.NewNode()
			cText, _ := c.MarshalText()
			if _, err := connectphone.PairV2(ctx, p4.InviteV2(), string(cText), connectphone.Options{Routes: set, OnSAS: func([]string) {}}); err != nil {
				t.Fatalf("pair C: %v", err)
			}
			st := sv.last()
			if len(st.Allowed) != 1 || st.Keys[c.Public().String()] == "" {
				t.Fatalf("state %+v", st)
			}
			if len(f.nodes) != 0 {
				t.Fatalf("%d Tailcat nodes", len(f.nodes))
			}
			_ = h.Close()
			cfg.Identity, cfg.Allowed, cfg.Keys = st.Identity, st.Allowed, nil
			h2, f2, sv2 := newTestHost(t, cfg)
			if slices.Contains(set, RouteRelay) {
				waitRelay(t, h2)
			}
			app2 := serveCounting(t, h2)
			if len(h2.Allowed()) != 0 || len(sv2.last().Allowed) != 0 {
				t.Fatalf("a phone without a Noise key is allowed: %v (saved %v)", h2.Allowed(), sv2.last().Allowed)
			}
			for _, r := range auditEncrypted(h2.Routes()) {
				if sess, err := auditConnect(t, r, server, auditNoiseKeys(c), c.Public().String()); !errors.Is(err, connectsecure.ErrUnpaired) {
					if sess != nil {
						sess.Close()
					}
					t.Fatalf("%s: a phone without a key on the host: %v, want unpaired", r.T, err)
				}
			}
			// SetAllowed cannot bring it back without its key.
			if err := h2.SetAllowed(ctx, []string{c.Public().String(), aPub}); err != nil || len(h2.Allowed()) != 0 {
				t.Fatalf("SetAllowed without keys: %v, allowed %v", err, h2.Allowed())
			}
			for _, r := range auditEncrypted(h2.Routes()) {
				if sess, err := auditConnect(t, r, server, auditNoiseKeys(c), c.Public().String()); err == nil {
					sess.Close()
					t.Fatalf("%s: SetAllowed let a phone without a key in", r.T)
				}
			}
			if app2.total() != 0 || len(f2.nodes) != 0 {
				t.Fatalf("restarted host: %d requests, %d Tailcat nodes", app2.total(), len(f2.nodes))
			}
		})
	}
}

// auditSAS works the emoji out from a handshake hash without connectsecure: HKDF-SHA256 (RFC 5869)
// with no salt and info "tailpocket2 sas", 3 bytes, 6 bits per emoji.
func auditSAS(binding []byte) []string {
	ext := hmac.New(sha256.New, make([]byte, sha256.Size))
	ext.Write(binding)
	exp := hmac.New(sha256.New, ext.Sum(nil))
	exp.Write([]byte("tailpocket2 sas"))
	exp.Write([]byte{1})
	b := exp.Sum(nil)
	v := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
	return []string{connectsecure.SASEmoji[v>>18&63], connectsecure.SASEmoji[v>>12&63], connectsecure.SASEmoji[v>>6&63], connectsecure.SASEmoji[v&63]}
}

func TestAuditV032EmojiIsTheHandshakeSASOnEveryRouteSet(t *testing.T) {
	for _, set := range append(slices.Clone(auditTailcatSets), auditNoTailcatSets...) {
		t.Run(strings.Join(set, "+"), func(t *testing.T) {
			withTailcat := slices.Contains(set, RouteTailcat)
			h, f, _ := newTestHost(t, auditConfig(t, set))
			if slices.Contains(set, RouteRelay) {
				waitRelay(t, h)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			first, err := h.Pair(ctx, PairOptions{Confirm: confirmAll})
			if err != nil {
				t.Fatal(err)
			}
			via := first.InviteV2().Via
			first.Close()
			if len(via) != len(set) {
				t.Fatalf("invite routes %+v for %v", via, set)
			}
			// One window per route: every route of the invite pairs with the same check.
			for _, r := range via {
				var onComputer []string
				p, err := h.Pair(ctx, PairOptions{Confirm: func(_ context.Context, req PairRequest) bool {
					onComputer = req.Emoji
					return req.Route == r.T
				}})
				if err != nil {
					t.Fatal(err)
				}
				inv := p.InviteV2()
				server := auditHostKey(t, inv.PK)
				k := key.NewNode()
				var onPhone []string
				var sess *connectsecure.Session
				if r.T == RouteTailcat {
					sess, err = noisePairOverTailcat(t, pairingNode(t, f), inv, k, func(e []string) { onPhone = e })
				} else {
					sess, err = auditPair(t, r, server, inv.PSK, auditNoiseKeys(k), k.Public().String(), k, func(e []string) { onPhone = e })
				}
				if err != nil {
					t.Fatalf("%s: pair: %v", r.T, err)
				}
				want := auditSAS(sess.ChannelBinding())
				sess.Close()
				if len(want) != 4 || !slices.Equal(onPhone, want) || !slices.Equal(onComputer, want) {
					t.Fatalf("%s: HKDF(handshake hash) gives %v, the phone showed %v, the computer %v", r.T, want, onPhone, onComputer)
				}
				if !slices.Contains(h.Allowed(), k.Public().String()) {
					t.Fatalf("%s: not paired", r.T)
				}
			}
			if withTailcat {
				return // the Tailcat window's refusals: emoji_test.go; v1 windows: host_test.go
			}
			allowed := len(h.Allowed())

			// Without Tailcat there is no pairing that shows no emoji: no v1 invite, no same-Wi-Fi
			// delivery, and a window without Confirm pairs nobody.
			bare, err := h.Pair(ctx, PairOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := bare.QR2(connectinvite.DefaultPrefix2); !errors.Is(err, ErrNoConfirm) {
				t.Fatalf("QR2 without Confirm: %v", err)
			}
			if _, err := bare.QR(connectinvite.DefaultPrefix); !errors.Is(err, ErrNoTailcat) {
				t.Fatalf("QR without Tailcat: %v", err)
			}
			if v1 := bare.Invite(); v1.Validate() == nil {
				t.Fatalf("a usable v1 invite without Tailcat: %+v", v1)
			}
			advertised := false
			if err := bare.ServeLocal(ctx, LocalOptions{Service: "_tailpocket-demo._tcp",
				Bindings:  []connectlocal.Binding{{IP: net.IPv4(127, 0, 0, 1).To4(), Mask: net.CIDRMask(8, 32)}},
				Advertise: func(connectmdns.Service) (func(), error) { advertised = true; return func() {}, nil },
				Confirm:   func(context.Context, string, string) bool { return true }}); !errors.Is(err, ErrNoTailcat) || advertised {
				t.Fatalf("ServeLocal without Tailcat: %v, advertised %v", err, advertised)
			}
			bareInv := bare.InviteV2()
			server := auditHostKey(t, bareInv.PK)
			for _, r := range via {
				k := key.NewNode()
				// bare.Invite() marked the window as having handed out a v1 invite: that opens nothing here.
				if sess, err := auditPair(t, r, server, bareInv.PSK, auditNoiseKeys(k), k.Public().String(), k, func([]string) {}); !errors.Is(err, connectsecure.ErrDenied) {
					if sess != nil {
						sess.Close()
					}
					t.Fatalf("%s: a window without Confirm: %v, want denied", r.T, err)
				}
			}
			bare.Close()

			// A no, and the phone hanging up while the computer asks, each spend the code.
			for _, r := range via {
				for _, how := range []string{"refused", "phone-gone"} {
					asking := make(chan struct{}, 1)
					p, err := h.Pair(ctx, PairOptions{Confirm: func(ctx context.Context, _ PairRequest) bool {
						if how == "refused" {
							return false
						}
						asking <- struct{}{}
						<-ctx.Done() // the user has not answered when the phone goes away
						return true
					}})
					if err != nil {
						t.Fatal(err)
					}
					inv := p.InviteV2()
					k := key.NewNode()
					raw := auditDial(t, r)
					done := make(chan error, 1)
					go func() {
						sess, err := auditPairOn(raw, server, inv.PSK, auditNoiseKeys(k), k.Public().String(), k, func([]string) {})
						if sess != nil {
							sess.Close()
						}
						done <- err
					}()
					if how == "phone-gone" {
						select {
						case <-asking:
						case <-time.After(5 * time.Second):
							t.Fatalf("%s: Confirm never ran", r.T)
						}
						raw.Close()
					}
					if err := <-done; err == nil || (how == "refused" && !errors.Is(err, connectsecure.ErrDenied)) {
						t.Fatalf("%s %s: %v", r.T, how, err)
					}
					select {
					case <-p.Done():
					case <-time.After(5 * time.Second):
						t.Fatalf("%s %s: the window stayed open", r.T, how)
					}
					if sess, err := auditPair(t, r, server, inv.PSK, auditNoiseKeys(k), k.Public().String(), k, func([]string) {}); err == nil {
						sess.Close()
						t.Fatalf("%s %s: the same code paired after the window ended", r.T, how)
					}
				}
			}
			if len(h.Allowed()) != allowed || len(f.nodes) != 0 {
				t.Fatalf("allowed %v, %d Tailcat nodes", h.Allowed(), len(f.nodes))
			}
		})
	}
}

func TestAuditV032SameWiFiLimitsOnEveryRouteSet(t *testing.T) {
	for _, set := range auditTailcatSets {
		t.Run(strings.Join(set, "+"), func(t *testing.T) {
			t.Parallel()
			h, f, _ := newTestHost(t, auditConfig(t, set))
			var prompts atomic.Int32
			p, err := h.Pair(context.Background(), PairOptions{TTL: MaxTTL, Confirm: func(context.Context, PairRequest) bool { prompts.Add(1); return true }})
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			v1 := *p.InviteV2().Via[0].Inv
			node := pairingNode(t, f)
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			port := make(chan int, 1)
			errc := make(chan error, 1)
			opts := LocalOptions{Service: "_tailpocket-demo._tcp",
				Bindings:  []connectlocal.Binding{{IP: net.IPv4(127, 0, 0, 1).To4(), Mask: net.CIDRMask(8, 32)}},
				Advertise: func(s connectmdns.Service) (func(), error) { port <- s.Port; return func() {}, nil },
				Confirm:   func(context.Context, string, string) bool { prompts.Add(1); return false }}
			go func() { errc <- p.ServeLocal(ctx, opts) }()
			at := <-port
			// One source address gets a key at most every 2 s (SourceGap); 127.0.0.1 is the only loopback
			// address macOS has, so this takes about 4 s. Each commitment is dropped without a reveal.
			keys := 0
			var servedErr error
			for deadline := time.Now().Add(20 * time.Second); servedErr == nil && time.Now().Before(deadline); {
				if abandonedKey("127.0.0.1", at) {
					keys++
				}
				select {
				case servedErr = <-errc:
				case <-time.After(50 * time.Millisecond):
				}
			}
			if !errors.Is(servedErr, connectlocal.ErrTooManyAttempts) || keys != connectlocal.MaxAttempts {
				t.Fatalf("ServeLocal: %v after %d keys, want ErrTooManyAttempts after %d", servedErr, keys, connectlocal.MaxAttempts)
			}
			if abandonedKey("127.0.0.1", at) {
				t.Fatal("a fourth commitment got a key")
			}
			select {
			case <-p.ended:
			case <-time.After(3 * time.Second):
				t.Fatal("the pairing window stayed open after its same-Wi-Fi attempts ran out")
			}
			if prompts.Load() != 0 {
				t.Fatalf("%d prompts for commitments that never revealed", prompts.Load())
			}
			// The invite that window would have delivered pairs nobody now, by /pair or by its QR code.
			_, phone := phoneKey(t)
			req, _ := http.NewRequest(http.MethodPost, "http://pairing.invalid/pair", strings.NewReader(`{"phoneKey":"`+phone+`","device":"x"}`))
			req.Header.Set("Authorization", "Bearer "+v1.Proof)
			if resp, err := client(node, uint16(v1.Port)).Do(req); err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					t.Fatal("/pair worked after the window ended")
				}
			}
			inv := p.InviteV2()
			k := key.NewNode()
			if sess, err := noisePairOverTailcat(t, node, inv, k, func([]string) {}); err == nil {
				sess.Close()
				t.Fatal("the QR code paired after the same-Wi-Fi attempts ran out")
			}
			for _, r := range auditEncrypted(inv.Via) {
				if sess, err := auditPair(t, r, auditHostKey(t, inv.PK), inv.PSK, auditNoiseKeys(k), k.Public().String(), k, func([]string) {}); err == nil {
					sess.Close()
					t.Fatalf("%s: the QR code paired after the same-Wi-Fi attempts ran out", r.T)
				}
			}
			if err := p.ServeLocal(ctx, opts); !errors.Is(err, ErrLocalUsed) {
				t.Fatalf("second ServeLocal: %v, want ErrLocalUsed", err)
			}
			if len(h.Allowed()) != 0 {
				t.Fatalf("allowed %v", h.Allowed())
			}
		})
	}
	// Without Tailcat same-Wi-Fi pairing does not exist: TestAuditV032EmojiIsTheHandshakeSASOnEveryRouteSet
	// checks that ServeLocal returns ErrNoTailcat before it listens or advertises.
}

// SECURITY.md, "Not defended": over a Tailcat window opened for a v1 invite, the holder of that
// invite can name any nodekey. v0.3.2 does not change that for a host with Tailcat, and adds one
// consequence: a phone that leaves Tailcat out of its routes cannot take the documented way back
// (pair again over Tailcat, then sync), so the computer's user has to revoke the squatted key.
// Without Tailcat on the host the claim is not possible at all (every pairing proves its nodekey:
// TestAuditV032NoTailcatOnlyAPairedPhoneGetsIn, step 4), and a host restarted without Tailcat
// forgets a squatted key, since it has no Noise key.
func TestAuditV032NodekeyClaim(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	addr := freeAddr(t)
	cfg := Config{Routes: []string{RouteTailcat, RouteLAN}, Listen: []string{addr}}
	h, f, sv := newTestHost(t, cfg)
	app := serveCounting(t, h)
	victim := key.NewNode()
	victimText, _ := victim.MarshalText()
	victimPub := victim.Public().String()
	lanOnly := connectphone.Options{Routes: []string{RouteLAN}, OnSAS: func([]string) {}}
	lanInvite := func(p *Pairing) connectinvite.V2 {
		inv := p.InviteV2()
		inv.Via = auditEncrypted(inv.Via)
		return inv
	}

	// Mallory holds a v1 invite and names the victim's nodekey.
	p, err := h.Pair(ctx, PairOptions{})
	if err != nil {
		t.Fatal(err)
	}
	v1 := p.Invite()
	if code, _ := postPair(t, f.live(uint16(v1.Port)), v1, v1.Proof, victimPub, "Mallory"); code != http.StatusOK {
		t.Fatalf("/pair naming the victim: %d", code)
	}
	p.Close()
	if !slices.Contains(h.Allowed(), victimPub) || len(sv.last().Keys) != 0 {
		t.Fatalf("allowed %v keys %v", h.Allowed(), sv.last().Keys)
	}
	// Still true: the claimant gets no session as that phone. Its own Noise key under the victim's
	// name is turned away on lan (busy: the host waits for the phone to sync over Tailcat).
	mallory := key.NewNode()
	server := h.id.noisePublic()
	if sess, err := auditConnect(t, lanVia(addr)[0], server, auditNoiseKeys(mallory), victimPub); err == nil {
		sess.Close()
		t.Fatal("the claimant got a session as the victim")
	}
	// The victim uses no Tailcat (setRoutes without it): it cannot pair over lan while its nodekey is
	// squatted, and it will not go to Tailcat to sync.
	p2, err := h.Pair(ctx, PairOptions{Confirm: confirmAll})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connectphone.PairV2(ctx, lanInvite(p2), string(victimText), lanOnly); !errors.Is(err, connectphone.ErrUnauthorized) {
		t.Fatalf("victim pairing over lan while squatted: %v, want unauthorized", err)
	}
	if app.total() != 0 {
		t.Fatalf("the app got %d requests", app.total())
	}
	// Way out 1: the computer's user revokes that key; the phone then pairs as a new one.
	if err := h.Revoke(ctx, victimPub); err != nil {
		t.Fatal(err)
	}
	p3, err := h.Pair(ctx, PairOptions{Confirm: confirmAll})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connectphone.PairV2(ctx, lanInvite(p3), string(victimText), lanOnly); err != nil {
		t.Fatalf("victim pairing after the revoke: %v", err)
	}

	// Way out 2: a host that runs without Tailcat forgets a squatted key when it starts.
	other := key.NewNode()
	otherText, _ := other.MarshalText()
	p4, err := h.Pair(ctx, PairOptions{})
	if err != nil {
		t.Fatal(err)
	}
	v1 = p4.Invite()
	if code, _ := postPair(t, f.live(uint16(v1.Port)), v1, v1.Proof, other.Public().String(), "Mallory"); code != http.StatusOK {
		t.Fatalf("/pair naming the second victim: %d", code)
	}
	st := sv.last()
	_ = h.Close()
	h2, f2, _ := newTestHost(t, Config{Routes: []string{RouteLAN}, Listen: []string{addr}, Identity: st.Identity, Allowed: st.Allowed, Keys: st.Keys})
	if got := h2.Allowed(); len(got) != 1 || got[0] != victimPub {
		t.Fatalf("without Tailcat the host keeps %v, want only the phone with a key", got)
	}
	p5, err := h2.Pair(ctx, PairOptions{Confirm: confirmAll})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connectphone.PairV2(ctx, p5.InviteV2(), string(otherText), lanOnly); err != nil {
		t.Fatalf("second victim pairing with a host without Tailcat: %v", err)
	}
	if len(f2.nodes) != 0 {
		t.Fatalf("%d Tailcat nodes", len(f2.nodes))
	}
}

// Removing phones on a host without Tailcat (Revoke, SetAllowed, the earlier review's SetAllowed fix):
// the removed phone hears unpaired on its open session and is refused on every route at once, the
// phones that stay keep their sessions, nothing waits for a Tailcat node to linger, and a save that
// fails removes nobody.
func TestAuditV032RemovalWithoutTailcat(t *testing.T) {
	for _, set := range auditNoTailcatSets {
		t.Run(strings.Join(set, "+"), func(t *testing.T) {
			noUpgrade(t)
			h, f, sv := newTestHost(t, auditConfig(t, set))
			if slices.Contains(set, RouteRelay) {
				waitRelay(t, h)
			}
			serveApp(t, h)
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			opts := connectphone.Options{Routes: set, OnSAS: func([]string) {}}
			type phone struct {
				k   key.NodePrivate
				pub string
				s   *connectphone.Session
			}
			var phones []phone
			var server [32]byte
			for range 3 {
				p, err := h.Pair(ctx, PairOptions{Confirm: confirmAll})
				if err != nil {
					t.Fatal(err)
				}
				inv := p.InviteV2()
				server = auditHostKey(t, inv.PK)
				k := key.NewNode()
				text, _ := k.MarshalText()
				link, err := connectphone.PairV2(ctx, inv, string(text), opts)
				if err != nil {
					t.Fatal(err)
				}
				s, err := connectphone.Connect(link, opts)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				if _, err := get(t, s); err != nil {
					t.Fatal(err)
				}
				phones = append(phones, phone{k, k.Public().String(), s})
			}
			a, b, c := phones[0], phones[1], phones[2]
			routes := auditEncrypted(h.Routes())
			gone := func(what string, ph phone) {
				t.Helper()
				for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
					_, err := get(t, ph.s)
					if errors.Is(err, connectphone.ErrRevoked) {
						break
					}
					if err == nil || time.Now().After(deadline) {
						t.Fatalf("%s: the removed phone's session: %v, want ErrRevoked", what, err)
					}
				}
				for _, r := range routes {
					if sess, err := auditConnect(t, r, server, auditNoiseKeys(ph.k), ph.pub); !errors.Is(err, connectsecure.ErrUnpaired) {
						if sess != nil {
							sess.Close()
						}
						t.Fatalf("%s on %s: the removed phone: %v, want unpaired", what, r.T, err)
					}
				}
			}
			stays := func(what string, ph phone) {
				t.Helper()
				if body, err := get(t, ph.s); err != nil || body != ph.pub+" "+marker {
					t.Fatalf("%s: a phone that stays: %q %v", what, body, err)
				}
			}

			// A save that fails removes nobody (the phone it names may already have heard unpaired: that
			// fails closed, and it is still listed, so it can pair again with its key).
			sv.mu.Lock()
			sv.fail = true
			sv.mu.Unlock()
			if err := h.SetAllowed(ctx, []string{b.pub, c.pub}); err == nil {
				t.Fatal("SetAllowed with a failing save succeeded")
			}
			if err := h.Revoke(ctx, b.pub); err == nil {
				t.Fatal("Revoke with a failing save succeeded")
			}
			if len(h.Allowed()) != 3 {
				t.Fatalf("a failed save changed the phones: %v", h.Allowed())
			}
			sv.mu.Lock()
			sv.fail = false
			sv.mu.Unlock()
			stays("failed save", b)
			stays("failed save", c)

			// SetAllowed drops A.
			start := time.Now()
			if err := h.SetAllowed(ctx, []string{b.pub, c.pub}); err != nil {
				t.Fatal(err)
			}
			if d := time.Since(start); d > time.Second {
				t.Fatalf("SetAllowed took %v without a Tailcat node to restart", d)
			}
			gone("SetAllowed", a)
			stays("SetAllowed", b)
			stays("SetAllowed", c)
			if st := sv.last(); len(st.Allowed) != 2 || len(st.Keys) != 2 || st.Keys[a.pub] != "" {
				t.Fatalf("saved %+v", st)
			}

			// Revoke drops B, then C, the last one.
			for i, ph := range []phone{b, c} {
				start := time.Now()
				if err := h.Revoke(ctx, ph.pub); err != nil {
					t.Fatal(err)
				}
				if d := time.Since(start); d > time.Second {
					t.Fatalf("Revoke took %v without a Tailcat node", d)
				}
				gone("Revoke", ph)
				if i == 0 {
					stays("Revoke", c)
				}
			}
			if len(h.Allowed()) != 0 || len(sv.last().Allowed) != 0 || len(sv.last().Keys) != 0 {
				t.Fatalf("after the last revoke: %v, saved %+v", h.Allowed(), sv.last())
			}
			// A refused pairing leaves nothing lingering either: the host closes at once.
			p, err := h.Pair(ctx, PairOptions{Confirm: func(context.Context, PairRequest) bool { return false }})
			if err != nil {
				t.Fatal(err)
			}
			k := key.NewNode()
			if _, err := auditPair(t, routes[0], server, p.InviteV2().PSK, auditNoiseKeys(k), k.Public().String(), k, func([]string) {}); !errors.Is(err, connectsecure.ErrDenied) {
				t.Fatalf("refused pairing: %v", err)
			}
			start = time.Now()
			if err := h.Close(); err != nil {
				t.Fatal(err)
			}
			if d := time.Since(start); d > 2*time.Second {
				t.Fatalf("Close took %v", d)
			}
			if len(f.nodes) != 0 {
				t.Fatalf("%d Tailcat nodes", len(f.nodes))
			}
		})
	}
}
