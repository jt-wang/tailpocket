package connecthost

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/flynn/noise"
	"tailscale.com/types/key"

	"github.com/jt-wang/tailpocket/connectinvite"
	"github.com/jt-wang/tailpocket/connectsecure"
)

// pairingNode is the fake node of window p (the newest node with the pairing port).
func pairingNode(t *testing.T, f *fakeNet) *fakeNode {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.nodes) - 1; i >= 0; i-- {
		if f.nodes[i].spec.port == DefaultPairingPort {
			return f.nodes[i]
		}
	}
	t.Fatal("no pairing node")
	return nil
}

// noisePairOverTailcat runs a phone's Noise pairing through the window's Tailcat node, as PairV2 does
// for the tailcat route. It returns the dial error.
func noisePairOverTailcat(t *testing.T, n *fakeNode, inv connectinvite.V2, k key.NodePrivate, onSAS func([]string)) (*connectsecure.Session, error) {
	t.Helper()
	static, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(inv.PK)
	var server [32]byte
	copy(server[:], raw)
	c, s := net.Pipe()
	n.mu.Lock()
	n.conns = append(n.conns, s) // closing the node breaks it, as Tailcat does
	n.mu.Unlock()
	go n.spec.onTCP(DefaultPairingPort)(s)
	return connectsecure.Dial(c, connectsecure.ClientConfig{Static: static, Server: server,
		Pair:   &connectsecure.PairHello{CID: connectsecure.CIDFor(inv.PSK), PSK: connectsecure.PSKFor(inv.PSK)},
		Device: "Test Phone", Phone: k.Public().String(), OnSAS: onSAS,
		Prove: func(b []byte) ([]byte, error) {
			r := k.Raw32()
			return connectsecure.KeyProof(r[:], server, connectinvite.ProofPair, b)
		}})
}

// A v2 pairing over the Tailcat window runs the Noise handshake, shows the same emoji on both
// screens, waits for the computer's user and records the phone's Noise key.
func TestTailcatPairingShowsEmojiAndWaits(t *testing.T) {
	h, f, saved := newTestHost(t, Config{TailcatOnly: true})
	var asked []PairRequest
	var mu sync.Mutex
	p, err := h.Pair(context.Background(), PairOptions{Confirm: func(_ context.Context, r PairRequest) bool {
		mu.Lock()
		asked = append(asked, r)
		mu.Unlock()
		return true
	}})
	if err != nil {
		t.Fatal(err)
	}
	k := key.NewNode()
	var shown []string
	sess, err := noisePairOverTailcat(t, pairingNode(t, f), p.InviteV2(), k, func(e []string) { shown = e })
	if err != nil {
		t.Fatalf("pairing: %v", err)
	}
	defer sess.Close()
	mu.Lock()
	defer mu.Unlock()
	if len(asked) != 1 || asked[0].Route != RouteTailcat || asked[0].Phone != k.Public().String() || asked[0].Device != "Test Phone" {
		t.Fatalf("Confirm got %+v", asked)
	}
	if len(shown) != 4 || !slices.Equal(shown, asked[0].Emoji) {
		t.Fatalf("phone showed %v, computer showed %v", shown, asked[0].Emoji)
	}
	if st := saved.last(); len(st.Keys) != 1 || st.Keys[k.Public().String()] == "" {
		t.Fatalf("no Noise key saved for the phone: %+v", st)
	}
}

// A no from the computer's user, or the phone hanging up while it decides, ends the window: the
// next try with the same code finds no window.
func TestEmojiRefusedOrAbandonedEndsWindow(t *testing.T) {
	for _, tc := range []string{"refused", "phone-gone"} {
		t.Run(tc, func(t *testing.T) {
			h, f, _ := newTestHost(t, Config{TailcatOnly: true})
			asking := make(chan struct{}, 1)
			p, err := h.Pair(context.Background(), PairOptions{Confirm: func(ctx context.Context, _ PairRequest) bool {
				if tc == "refused" {
					return false
				}
				asking <- struct{}{}
				<-ctx.Done() // the user never answers; the phone goes away
				return true
			}})
			if err != nil {
				t.Fatal(err)
			}
			inv, node := p.InviteV2(), pairingNode(t, f)
			if tc == "refused" {
				// The no ends the window, but its bye still reaches the phone over the window's node:
				// the phone hears "denied" now, not a broken connection after its timeout.
				if _, err := noisePairOverTailcat(t, node, inv, key.NewNode(), func([]string) {}); !errors.Is(err, connectsecure.ErrDenied) {
					t.Fatalf("refused pairing: %v, want ErrDenied", err)
				}
			} else {
				done := make(chan error, 1)
				var hang func()
				static, _ := noise.DH25519.GenerateKeypair(rand.Reader)
				raw, _ := base64.RawURLEncoding.DecodeString(inv.PK)
				var server [32]byte
				copy(server[:], raw)
				k := key.NewNode()
				c, s := net.Pipe()
				hang = func() { _ = c.Close() }
				go node.spec.onTCP(DefaultPairingPort)(s)
				go func() {
					_, err := connectsecure.Dial(c, connectsecure.ClientConfig{Static: static, Server: server,
						Pair:  &connectsecure.PairHello{CID: connectsecure.CIDFor(inv.PSK), PSK: connectsecure.PSKFor(inv.PSK)},
						Phone: k.Public().String(), OnSAS: func([]string) {},
						Prove: func(b []byte) ([]byte, error) {
							r := k.Raw32()
							return connectsecure.KeyProof(r[:], server, connectinvite.ProofPair, b)
						}})
					done <- err
				}()
				select {
				case <-asking:
				case <-time.After(5 * time.Second):
					t.Fatal("Confirm never ran")
				}
				hang()
				<-done
			}
			select {
			case <-p.Done():
			case <-time.After(5 * time.Second):
				t.Fatal("the window stayed open")
			}
			if _, err := noisePairOverTailcat(t, node, inv, key.NewNode(), func([]string) {}); err == nil {
				t.Fatal("the same code paired after the window ended")
			}
		})
	}
}

// Only a v2 invite left the host: its Tailcat window does not take v1's /pair, which shows no
// emoji, even though the v2 invite carries that window's key and proof.
func TestV2InviteClosesV1Pair(t *testing.T) {
	h, f, _ := newTestHost(t, Config{TailcatOnly: true})
	p, err := h.Pair(context.Background(), PairOptions{Confirm: confirmAll})
	if err != nil {
		t.Fatal(err)
	}
	v1 := *p.InviteV2().Via[0].Inv
	_, phone := phoneKey(t)
	if code, _ := postPair(t, pairingNode(t, f), v1, v1.Proof, phone, "Mallory"); code != http.StatusForbidden {
		t.Fatalf("/pair with the v1 window inside a v2 invite: %d, want 403", code)
	}
	// Handing out the v1 invite opens it, and Confirm still decides (without emoji).
	_ = p.Invite()
	if code, _ := postPair(t, pairingNode(t, f), v1, v1.Proof, phone, "Old app"); code != http.StatusOK {
		t.Fatalf("/pair after Invite: %d", code)
	}
}

// A window without Confirm gives no v2 invite, and pairs no phone over the Noise routes.
func TestV2NeedsConfirm(t *testing.T) {
	h, f, _ := newTestHost(t, Config{TailcatOnly: true})
	p, err := h.Pair(context.Background(), PairOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.QR2(connectinvite.DefaultPrefix2); err != ErrNoConfirm {
		t.Fatalf("QR2 without Confirm: %v", err)
	}
	if _, err := noisePairOverTailcat(t, pairingNode(t, f), p.InviteV2(), key.NewNode(), func([]string) {}); err == nil {
		t.Fatal("a Noise pairing went through without Confirm")
	}
}

// A phone that does not show emoji (no OnSAS) cannot pair with a v2 window.
func TestPhoneWithoutEmojiIsRefused(t *testing.T) {
	h, f, _ := newTestHost(t, Config{TailcatOnly: true})
	p, err := h.Pair(context.Background(), PairOptions{Confirm: confirmAll})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := noisePairOverTailcat(t, pairingNode(t, f), p.InviteV2(), key.NewNode(), nil); err == nil {
		t.Fatal("a phone that shows no emoji paired")
	}
}
