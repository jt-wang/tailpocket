package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
)

// Play Integrity classic tokens decoded on the gateway, with response encryption keys the
// publisher manages (Play Console → Play Integrity API settings → Manage response encryption →
// Change to manage my own keys). No call to Google, so no quota: made-up tokens cost only the AES
// and ECDSA work below.
//
// A classic token is a compact JWE (alg A256KW, enc A256GCM) under the decryption key, holding a
// compact JWS (alg ES256) signed with Google's key, whose public half is the verification key.
// Its payload is the verdict JSON, the same fields decodeIntegrityToken returns under
// tokenPayloadExternal. Anything else, including standard-request tokens, does not decode.

// localKeys are the publisher's response encryption keys for one app.
type localKeys struct {
	kek    cipher.Block // decryption key, AES-256
	verify *ecdsa.PublicKey
}

// loadLocalKeys reads the two keys as Play Console gives them: each a file holding one line of
// standard base64 (the decryption key: 32 bytes; the verification key: an X.509
// SubjectPublicKeyInfo of a P-256 key).
func loadLocalKeys(dir, decryption, verification string) (*localKeys, error) {
	read := func(name, f string) ([]byte, error) {
		if !filepath.IsAbs(f) {
			f = filepath.Join(dir, f)
		}
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		out, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if err != nil {
			return nil, fmt.Errorf("%s: %s is not base64", name, f)
		}
		return out, nil
	}
	if decryption == "" || verification == "" {
		return nil, errors.New("decryption_key_file and verification_key_file go together")
	}
	path := decryption
	if !filepath.IsAbs(path) {
		path = filepath.Join(dir, path)
	}
	if othersCanRead(path) {
		return nil, fmt.Errorf("decryption_key_file %s is readable by other users; chmod 600 it", path)
	}
	dk, err := read("decryption_key_file", decryption)
	if err != nil {
		return nil, err
	}
	if len(dk) != 32 {
		return nil, errors.New("decryption_key_file: the key is not 32 bytes (AES-256)")
	}
	vk, err := read("verification_key_file", verification)
	if err != nil {
		return nil, err
	}
	pub, err := x509.ParsePKIXPublicKey(vk)
	ek, ok := pub.(*ecdsa.PublicKey)
	if err != nil || !ok || ek.Curve != elliptic.P256() {
		return nil, errors.New("verification_key_file: not a P-256 public key (X.509 SubjectPublicKeyInfo)")
	}
	kek, _ := aes.NewCipher(dk)
	return &localKeys{kek: kek, verify: ek}, nil
}

var jwtB64 = base64.RawURLEncoding.Strict()

// decode decrypts and verifies token and returns the verdict's JSON. Every failure is the same
// attestFail("token"): the phone learns nothing about which step failed.
func (k *localKeys) decode(token string) ([]byte, error) {
	bad := attestFail("token")
	parts := strings.Split(token, ".")
	if len(parts) != 5 {
		return nil, bad
	}
	var hdr struct {
		Alg  string `json:"alg"`
		Enc  string `json:"enc"`
		Zip  string `json:"zip"`
		Crit []any  `json:"crit"`
	}
	h, err := jwtB64.DecodeString(parts[0])
	if err != nil || json.Unmarshal(h, &hdr) != nil || hdr.Alg != "A256KW" || hdr.Enc != "A256GCM" || hdr.Zip != "" || hdr.Crit != nil {
		return nil, bad
	}
	wrapped, err1 := jwtB64.DecodeString(parts[1])
	iv, err2 := jwtB64.DecodeString(parts[2])
	ct, err3 := jwtB64.DecodeString(parts[3])
	tag, err4 := jwtB64.DecodeString(parts[4])
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || len(iv) != 12 || len(tag) != 16 {
		return nil, bad
	}
	cek, ok := aesKeyUnwrap(k.kek, wrapped)
	if !ok || len(cek) != 32 {
		return nil, bad
	}
	blk, _ := aes.NewCipher(cek)
	gcm, _ := cipher.NewGCM(blk)
	jws, err := gcm.Open(nil, iv, append(ct, tag...), []byte(parts[0]))
	if err != nil {
		return nil, bad
	}
	payload, ok := k.verifyJWS(string(jws))
	if !ok {
		return nil, bad
	}
	return payload, nil
}

func (k *localKeys) verifyJWS(jws string) ([]byte, bool) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return nil, false
	}
	var hdr struct {
		Alg  string `json:"alg"`
		Crit []any  `json:"crit"`
	}
	h, err := jwtB64.DecodeString(parts[0])
	if err != nil || json.Unmarshal(h, &hdr) != nil || hdr.Alg != "ES256" || hdr.Crit != nil {
		return nil, false
	}
	sig, err := jwtB64.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return nil, false
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(k.verify, digest[:], r, s) {
		return nil, false
	}
	payload, err := jwtB64.DecodeString(parts[1])
	return payload, err == nil
}

// aesKeyUnwrap is RFC 3394 key unwrap with the default IV.
func aesKeyUnwrap(kek cipher.Block, c []byte) ([]byte, bool) {
	if len(c)%8 != 0 || len(c) < 24 {
		return nil, false
	}
	n := len(c)/8 - 1
	var a [8]byte
	copy(a[:], c[:8])
	r := make([]byte, n*8)
	copy(r, c[8:])
	var b [16]byte
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			t := uint64(n*j + i)
			binary.BigEndian.PutUint64(b[:8], binary.BigEndian.Uint64(a[:])^t)
			copy(b[8:], r[(i-1)*8:i*8])
			kek.Decrypt(b[:], b[:])
			copy(a[:], b[:8])
			copy(r[(i-1)*8:i*8], b[8:])
		}
	}
	iv := [8]byte{0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6}
	if subtle.ConstantTimeCompare(a[:], iv[:]) != 1 {
		return nil, false
	}
	return r, true
}
