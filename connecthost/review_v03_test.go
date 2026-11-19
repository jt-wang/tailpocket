package connecthost

// Independent security review of v0.3. Each test here fails on c13ffdf and marks one finding.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/flynn/noise"
	"tailscale.com/types/key"

	"github.com/jt-wang/tailpocket/connectinvite"
	"github.com/jt-wang/tailpocket/connectphone"
	"github.com/jt-wang/tailpocket/connectrelay"
	"github.com/jt-wang/tailpocket/connectsecure"
)

// Finding: the 16 handshake slots are one pool for every route. Anyone on the internet who knows the
// room (it is not secret) joins it 16 times through the relay and sends a preamble and nothing else;
// for the next 5 s the paired phone on the same Wi-Fi cannot connect over lan either.
// MaxPhonesPerAddr 16 stands in for 4 source addresses at the default 4.
func TestReviewRelayFloodBlocksLAN(t *testing.T) {
	srv, err := connectrelay.NewServer(connectrelay.Config{Token: relayToken, PublicHost: "127.0.0.1",
		MaxPhonesPerAddr: 16, Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(func() { srv.Close(); ts.Close() })
	relayURL := "ws" + strings.TrimPrefix(ts.URL, "http")
	hostAddr := freeAddr(t)
	h, _, _ := newTestHost(t, Config{Relays: []Relay{{URL: relayURL, Token: relayToken}}, Listen: []string{hostAddr}})
	waitRelay(t, h)
	serveApp(t, h)

	p, err := h.Pair(context.Background(), PairOptions{})
	if err != nil {
		t.Fatal(err)
	}
	inv := p.InviteV2()
	inv.Via = lanVia(hostAddr)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	link, err := connectphone.PairV2(ctx, inv, connectphone.NewKey(), connectphone.Options{Device: "Test Phone"})
	if err != nil {
		t.Fatal(err)
	}
	link.Address, link.Port, link.Via = "", 0, lanVia(hostAddr)

	var room string
	for _, r := range h.Routes() {
		if r.T == connectinvite.RouteRelay {
			room = r.R
		}
	}
	for i := 0; i < 16; i++ {
		c, err := connectrelay.DialPhone(ctx, relayURL, room, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		c.Write([]byte("TP2C"))
	}
	time.Sleep(300 * time.Millisecond) // the host accepts each one and holds a slot

	s, _ := connectphone.Connect(link, connectphone.Options{})
	defer s.Close()
	if _, err := get(t, s); err != nil {
		t.Fatalf("paired phone on lan while strangers hold the relay's handshakes: %v", err)
	}
}

// Finding: /v2/sync takes a Noise key on the phone's word and the first phone to report a key keeps
// it. A paired phone B that learns phone A's Noise public key before A syncs takes it, and A, which
// does hold the private key, gets 409 for good: no encrypted routes for A.
func TestReviewSyncSquatLocksOutTheOwner(t *testing.T) {
	a, phoneA := phoneKey(t)
	b, phoneB := phoneKey(t)
	h, f, saved := newTestHost(t, Config{Allowed: []string{phoneA, phoneB}})
	main := f.live(DefaultPort)
	// Fix (pre.2): a sync carries a proof made with the reported Noise key; B can sign only with its own.
	signer := map[string]key.NodePrivate{phoneA: a, phoneB: b}
	sync := func(phone, noise string) int {
		body := syncBody(h, signer[phone], phone, noise)
		req, _ := http.NewRequest(http.MethodPost, "http://control.invalid/v2/sync", bytes.NewReader(body))
		resp, err := controlClient(main, phone).Do(req)
		if err != nil {
			return 0
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	noiseA := noisePublicOf(a)
	if got := sync(phoneB, noiseA); got != http.StatusOK {
		t.Logf("B reporting A's key: %d", got)
	}
	if got := sync(phoneA, noiseA); got != http.StatusOK || saved.last().Keys[phoneA] != noiseA {
		t.Fatalf("A syncing the key it holds: %d, keys %v", got, saved.last().Keys)
	}
}

// Finding: pairing over Noise, the phone names its nodekey in the hello and nothing proves it. A
// holder of an invite claims the nodekey of a phone not paired here yet: its sessions reach the app
// as that phone (PhoneOf), and the real phone can no longer pair over relay or lan.
func TestReviewNoisePairingTakesAnyNodekey(t *testing.T) {
	hostAddr := freeAddr(t)
	h, _, _ := newTestHost(t, Config{Listen: []string{hostAddr}})
	victim := key.NewNode()
	victimID := victim.Public().String()

	p, err := h.Pair(context.Background(), PairOptions{})
	if err != nil {
		t.Fatal(err)
	}
	inv := p.InviteV2()
	var server [32]byte
	pk, _ := base64.RawURLEncoding.DecodeString(inv.PK)
	copy(server[:], pk)
	mallory, _ := noise.DH25519.GenerateKeypair(rand.Reader)
	raw, err := net.Dial("tcp", hostAddr)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := connectsecure.Dial(raw, connectsecure.ClientConfig{Static: mallory, Server: server, Version: "x",
		Pair:  &connectsecure.PairHello{CID: connectsecure.CIDFor(inv.PSK), PSK: connectsecure.PSKFor(inv.PSK)},
		Phone: victimID, Device: "Mallory"})
	// Fix (pre.2): the hello must carry a proof signed with the named nodekey, so this is refused.
	if err == nil {
		sess.Close()
		t.Fatal("an invite holder paired under another phone's nodekey")
	}
	p.Close()

	// The real phone with that nodekey now pairs, over lan, from a new invite.
	p2, err := h.Pair(context.Background(), PairOptions{})
	if err != nil {
		t.Fatal(err)
	}
	inv2 := p2.InviteV2()
	inv2.Via = lanVia(hostAddr)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	victimKey, _ := victim.MarshalText()
	if _, err := connectphone.PairV2(ctx, inv2, string(victimKey), connectphone.Options{Device: "Victim"}); err != nil {
		t.Fatalf("the phone that holds %s cannot pair over lan: %v", victimID, err)
	}
}
