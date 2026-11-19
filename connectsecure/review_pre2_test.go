package connectsecure

// Re-review of v0.3.0-pre.2: what a pre.1 phone (AESGCM, proto 1) gets from a pre.2 host.

import (
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/flynn/noise"
)

func TestPre1PhoneAtPre2Host(t *testing.T) {
	k := newKeys(t)
	a, b := pipe2(t)
	done := make(chan error, 1)
	go func() { _, err := Accept(b, k.server(nil)); done <- err }()
	old := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)
	hs, _ := noise.NewHandshakeState(noise.Config{CipherSuite: old, Pattern: noise.HandshakeIK, Initiator: true,
		Prologue: []byte(prologue), StaticKeypair: k.phone, PeerStatic: k.comp.Public[:]})
	p0, _ := json.Marshal(firstPayload{Proto: 1})
	m0, _, _, _ := hs.WriteMessage(nil, p0)
	a.Write(appendFrame([]byte("TP2C"), m0))
	var hdr [2]byte
	_, rerr := io.ReadFull(a, hdr[:])
	err := <-done
	t.Logf("host: %v; phone reads: %v", err, rerr)
	if !errors.Is(rerr, io.EOF) || !errors.Is(err, ErrHandshake) {
		t.Fatalf("pre.1 phone: host %v, phone %v", err, rerr)
	}
}
