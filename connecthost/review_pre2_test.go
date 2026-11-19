package connecthost

// Re-review of v0.3.0-pre.2 (779b2a0).

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/flynn/noise"
	"tailscale.com/types/key"

	"github.com/jt-wang/tailpocket/connectinvite"
	"github.com/jt-wang/tailpocket/connectphone"
	"github.com/jt-wang/tailpocket/connectsecure"
)

// Finding (L1 left open on the Tailcat pairing path): a /pair request names its nodekey without
// proof (the pairing node admits the invite's one-time key, not the phone's), and its Noise proof
// shows only that the sender holds the Noise key it reports. So an invite holder pairs over Tailcat
// as another phone's nodekey with its own Noise key: its relay or lan sessions then reach the app as
// that phone, and the real phone cannot pair over relay or lan.
func TestReviewTailcatPairingTakesAnyNodekey(t *testing.T) {
	hostAddr := freeAddr(t)
	h, f, _ := newTestHost(t, Config{Listen: []string{hostAddr}})
	serveApp(t, h)
	victim := key.NewNode()
	victimID := victim.Public().String()

	p, err := h.Pair(context.Background(), PairOptions{})
	if err != nil {
		t.Fatal(err)
	}
	inv := p.Invite()
	mallory, _ := noise.DH25519.GenerateKeypair(rand.Reader)
	malloryPub := base64.RawURLEncoding.EncodeToString(mallory.Public)
	proof, _ := connectsecure.KeyProof(mallory.Private, h.id.noisePublic(), connectinvite.ProofNoise,
		connectinvite.NoiseClaim(victimID, malloryPub))
	body, _ := json.Marshal(map[string]string{"phoneKey": victimID, "device": "Mallory", "noise": malloryPub,
		"proof": base64.RawURLEncoding.EncodeToString(proof)})
	req, _ := http.NewRequest(http.MethodPost, "http://pairing.invalid/pair", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+inv.Proof)
	resp, err := client(f.live(uint16(inv.Port)), uint16(inv.Port)).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	p.Close()

	// Mallory connects over lan with its own Noise key, naming the victim.
	var server [32]byte
	copy(server[:], func() []byte { b := h.id.noisePublic(); return b[:] }())
	raw, err := net.Dial("tcp", hostAddr)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := connectsecure.Dial(raw, connectsecure.ClientConfig{Static: mallory, Server: server, Version: "x", Phone: victimID})
	if err == nil {
		defer sess.Close()
		st, _ := sess.Open()
		io.WriteString(st, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		st.SetReadDeadline(time.Now().Add(3 * time.Second))
		got, _ := io.ReadAll(st)
		if strings.Contains(string(got), victimID) {
			t.Errorf("the app took Mallory's lan session for %s", victimID)
		}
	}

	// The real phone: a nodekey that is paired but has no Noise key cannot pair over relay or lan (as
	// in v1, C8). Its owner pairs over Tailcat and syncs on the main node, and then has lan.
	p2, err := h.Pair(context.Background(), PairOptions{})
	if err != nil {
		t.Fatal(err)
	}
	inv2 := p2.Invite()
	body2, _ := json.Marshal(map[string]string{"phoneKey": victimID, "device": "Victim"})
	req2, _ := http.NewRequest(http.MethodPost, "http://pairing.invalid/pair", strings.NewReader(string(body2)))
	req2.Header.Set("Authorization", "Bearer "+inv2.Proof)
	resp2, err := client(f.live(uint16(inv2.Port)), uint16(inv2.Port)).Do(req2)
	if err != nil || resp2.StatusCode != http.StatusOK {
		t.Fatalf("the real phone pairing over Tailcat: %v %v", resp2, err)
	}
	resp2.Body.Close()
	p2.Close()
	sreq, _ := http.NewRequest(http.MethodPost, "http://control.invalid/v2/sync",
		strings.NewReader(string(syncBody(h, victim, victimID, noisePublicOf(victim)))))
	sresp, err := controlClient(f.live(DefaultPort), victimID).Do(sreq)
	if err != nil || sresp.StatusCode != http.StatusOK {
		t.Fatalf("the real phone's sync: %v %v", sresp, err)
	}
	sresp.Body.Close()
	vk, _ := victim.MarshalText()
	pk := h.id.noisePublic()
	s, err := connectphone.Connect(connectphone.Link{Name: "Mac", Key: string(vk),
		HostKey: base64.RawURLEncoding.EncodeToString(pk[:]), Via: lanVia(hostAddr)}, connectphone.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got, err := get(t, s); err != nil || got != victimID+" "+marker {
		t.Errorf("the real phone over lan after Tailcat pairing and sync: %q %v", got, err)
	}
}
