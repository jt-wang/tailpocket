package connectlocal

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Construction, wire v2 (both roles derive the same values; phonePub ‖ hostPub order is fixed by role):
//
//	commit = SHA256(label ‖ "commit" ‖ phonePub ‖ nonce)        sent by the phone before it sees hostPub
//	shared = X25519(own private, peer public)
//	code   = "%06d" of uint64_be(SHA256(label ‖ "code" ‖ commit ‖ phonePub ‖ hostPub ‖ nonce ‖ shared)[0:8]) mod 1_000_000
//	key    = HKDF-SHA256(ikm = shared, salt = commit ‖ phonePub ‖ hostPub ‖ nonce, info = label ‖ " invitation", 32 bytes)
//	sealed = aeadNonce(12) ‖ ChaCha20-Poly1305(key, aeadNonce, plaintext) ‖ tag(16)
//
// nonce is the phone's 32 random bytes, revealed with phonePub only after the host sent hostPub.

// NonceSize is the size of the phone's commitment nonce.
const NonceSize = 32

type KeyPair struct{ Private, Public [32]byte }

func NewKeyPair() (KeyPair, error) {
	private := make([]byte, curve25519.ScalarSize)
	if _, err := io.ReadFull(rand.Reader, private); err != nil {
		return KeyPair{}, err
	}
	return KeyPairFromPrivate(private)
}

func KeyPairFromPrivate(private []byte) (KeyPair, error) {
	if len(private) != curve25519.ScalarSize {
		return KeyPair{}, errors.New("private key must be 32 bytes")
	}
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		return KeyPair{}, err
	}
	var kp KeyPair
	copy(kp.Private[:], private)
	copy(kp.Public[:], public)
	return kp, nil
}

// NewNonce returns a fresh commitment nonce.
func NewNonce() ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// Commit is the phone's commitment to its key: SHA256(label ‖ "commit" ‖ phonePub ‖ nonce).
func Commit(label string, phonePub, nonce []byte) [32]byte {
	d := sha256.New()
	d.Write([]byte(label))
	d.Write([]byte("commit"))
	d.Write(phonePub)
	d.Write(nonce)
	var c [32]byte
	copy(c[:], d.Sum(nil))
	return c
}

// Session is one side's view of a pairing exchange.
type Session struct {
	Code string
	key  []byte
}

// NewSession derives code and key once both keys and the phone's nonce are known. The host must
// first check that Commit(label, phonePub, nonce) equals the commitment the phone sent.
func NewSession(label string, own KeyPair, peerPublic []byte, phone bool, nonce []byte) (*Session, error) {
	if label == "" {
		return nil, errors.New("label is empty")
	}
	if len(peerPublic) != curve25519.PointSize {
		return nil, errors.New("peer key must be 32 bytes")
	}
	if len(nonce) != NonceSize {
		return nil, errors.New("nonce must be 32 bytes")
	}
	shared, err := curve25519.X25519(own.Private[:], peerPublic) // rejects low-order points
	if err != nil {
		return nil, err
	}
	phonePub, hostPub := own.Public[:], peerPublic
	if !phone {
		phonePub, hostPub = peerPublic, own.Public[:]
	}
	commit := Commit(label, phonePub, nonce)
	digest := sha256.New()
	digest.Write([]byte(label))
	digest.Write([]byte("code"))
	digest.Write(commit[:])
	digest.Write(phonePub)
	digest.Write(hostPub)
	digest.Write(nonce)
	digest.Write(shared)
	code := fmt.Sprintf("%06d", binary.BigEndian.Uint64(digest.Sum(nil)[:8])%1_000_000)
	salt := make([]byte, 0, 4*32)
	salt = append(append(append(append(salt, commit[:]...), phonePub...), hostPub...), nonce...)
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, salt, []byte(label+" invitation")), key); err != nil {
		return nil, err
	}
	return &Session{Code: code, key: key}, nil
}

func (s *Session) Seal(plain []byte) ([]byte, error) {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return s.sealWithNonce(plain, nonce)
}

func (s *Session) sealWithNonce(plain, nonce []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(s.key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(append([]byte{}, nonce...), nonce, plain, nil), nil
}

func (s *Session) Open(box []byte) ([]byte, error) {
	if len(box) < chacha20poly1305.NonceSize+chacha20poly1305.Overhead || len(box) > 128*1024 {
		return nil, errors.New("sealed box has the wrong size")
	}
	aead, err := chacha20poly1305.New(s.key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, box[:chacha20poly1305.NonceSize], box[chacha20poly1305.NonceSize:], nil)
}
