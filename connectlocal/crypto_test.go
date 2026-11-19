package connectlocal

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func b64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The wire v2 frozen vector with DSH Mobile's label. DSH Mobile's docs/TAILCAT.md must carry the same
// values: its v1 vector (code 295936) describes the uncommitted exchange, which hosts no longer accept
// (TestHostRejectsV1Hello).
func TestFrozenVectorWithDSHLabel(t *testing.T) {
	const label = "dsh-mobile-local-pairing-v1"
	phone, err := KeyPairFromPrivate(b64(t, "ERERERERERERERERERERERERERERERERERERERERERE="))
	if err != nil {
		t.Fatal(err)
	}
	host, err := KeyPairFromPrivate(b64(t, "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI="))
	if err != nil {
		t.Fatal(err)
	}
	if got := base64.StdEncoding.EncodeToString(phone.Public[:]); got != "e06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxM=" {
		t.Fatalf("phone public %s", got)
	}
	if got := base64.StdEncoding.EncodeToString(host.Public[:]); got != "D6poTtKIZ7l/Smot7l34zpdOdrcBjj8iocTPJnhXDyA=" {
		t.Fatalf("host public %s", got)
	}
	nonce := b64(t, "REREREREREREREREREREREREREREREREREREREREREQ=")
	commit := Commit(label, phone.Public[:], nonce)
	if got := base64.StdEncoding.EncodeToString(commit[:]); got != "HnYkDXyQsAK46/99Ac05tBezHWWwGBiGq+FIYIScHcM=" {
		t.Fatalf("commit %s", got)
	}
	ps, err := NewSession(label, phone, host.Public[:], true, nonce)
	if err != nil {
		t.Fatal(err)
	}
	hs, err := NewSession(label, host, phone.Public[:], false, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if ps.Code != "933437" || hs.Code != "933437" {
		t.Fatalf("codes %s %s", ps.Code, hs.Code)
	}
	if got := base64.StdEncoding.EncodeToString(ps.key); got != "t//rOgjEARsMhj83BfiVqop/eRbw1t00Z3fyQL4UzPs=" || !bytes.Equal(ps.key, hs.key) {
		t.Fatalf("key %s", got)
	}
	sealed, err := hs.sealWithNonce([]byte(`{"version":3}`), b64(t, "MzMzMzMzMzMzMzMz"))
	if err != nil {
		t.Fatal(err)
	}
	if got := base64.StdEncoding.EncodeToString(sealed); got != "MzMzMzMzMzMzMzMzZK3iZP3rpvoh+Bk9sxZNBMqdAxZYW+EfL0AKpog=" {
		t.Fatalf("sealed %s", got)
	}
	plain, err := ps.Open(sealed)
	if err != nil || string(plain) != `{"version":3}` {
		t.Fatalf("open %q %v", plain, err)
	}
}

func TestSessionsAgreeAndRejectTampering(t *testing.T) {
	phone, _ := NewKeyPair()
	host, _ := NewKeyPair()
	nonce, _ := NewNonce()
	ps, _ := NewSession(DefaultLabel, phone, host.Public[:], true, nonce)
	hs, _ := NewSession(DefaultLabel, host, phone.Public[:], false, nonce)
	if ps.Code != hs.Code || len(ps.Code) != 6 {
		t.Fatalf("codes %q %q", ps.Code, hs.Code)
	}
	sealed, err := hs.Seal([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := ps.Open(sealed); err == nil {
		t.Fatal("tampered box opened")
	}
	other, _ := NewSession("another-label", phone, host.Public[:], true, nonce)
	if other.Code == ps.Code && bytes.Equal(other.key, ps.key) {
		t.Fatal("label does not separate sessions")
	}
	nonce2 := append([]byte{}, nonce...)
	nonce2[0] ^= 1
	if moved, _ := NewSession(DefaultLabel, phone, host.Public[:], true, nonce2); bytes.Equal(moved.key, ps.key) {
		t.Fatal("nonce is not bound into the key")
	}
}

func TestCommitBindsKeyNonceAndLabel(t *testing.T) {
	kp, _ := NewKeyPair()
	nonce, _ := NewNonce()
	c := Commit(DefaultLabel, kp.Public[:], nonce)
	other, _ := NewKeyPair()
	nonce2 := append([]byte{}, nonce...)
	nonce2[31] ^= 1
	for name, d := range map[string][32]byte{
		"key":   Commit(DefaultLabel, other.Public[:], nonce),
		"nonce": Commit(DefaultLabel, kp.Public[:], nonce2),
		"label": Commit("another-label", kp.Public[:], nonce),
	} {
		if d == c {
			t.Fatalf("commitment does not bind the %s", name)
		}
	}
}

func TestLowOrderPeerRejected(t *testing.T) {
	own, _ := NewKeyPair()
	nonce, _ := NewNonce()
	if _, err := NewSession(DefaultLabel, own, make([]byte, 32), true, nonce); err == nil {
		t.Fatal("all-zero peer key accepted")
	}
	if _, err := NewSession(DefaultLabel, own, make([]byte, 31), true, nonce); err == nil {
		t.Fatal("short peer key accepted")
	}
	if _, err := NewSession("", own, own.Public[:], true, nonce); err == nil {
		t.Fatal("empty label accepted")
	}
	if _, err := NewSession(DefaultLabel, own, own.Public[:], true, nonce[:31]); err == nil {
		t.Fatal("short nonce accepted")
	}
}
