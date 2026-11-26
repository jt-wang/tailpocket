package connectpush

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
)

// AttestLabel starts AttestClientData.
const AttestLabel = "tailpocket push attest 1"

// AttestClientData is what attestation evidence for a register or revoke
// request must be bound to:
//
//	AttestLabel \n op \n app \n platform \n token \n generation \n challenge
//
// with op "register" or "revoke" and generation in decimal. App Attest signs
// SHA-256 of it (the clientDataHash); Play Integrity carries
// base64url(SHA-256 of it) as the request hash (standard requests) or the
// nonce (classic requests). The gateway builds the same bytes from the
// request, so evidence made for one device, generation or operation does not
// pass for another.
func AttestClientData(op, app, platform, token string, generation uint64, challenge string) []byte {
	b := make([]byte, 0, 64+len(app)+len(token)+len(challenge))
	b = append(b, AttestLabel...)
	for _, s := range []string{op, app, platform, token, strconv.FormatUint(generation, 10), challenge} {
		b = append(b, '\n')
		b = append(b, s...)
	}
	return b
}

// AttestHash is SHA-256 of AttestClientData.
func AttestHash(op, app, platform, token string, generation uint64, challenge string) [32]byte {
	return sha256.Sum256(AttestClientData(op, app, platform, token, generation, challenge))
}

// AttestRequestHash is the Play Integrity request hash (or classic nonce):
// base64url without padding of AttestHash.
func AttestRequestHash(op, app, platform, token string, generation uint64, challenge string) string {
	h := AttestHash(op, app, platform, token, generation, challenge)
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// NewKey makes a phone's push key and its key id: 32 random bytes, and 16
// random bytes as base64url (22 characters).
func NewKey() (kid string, key [32]byte, err error) {
	if _, err := rand.Read(key[:]); err != nil {
		return "", key, err
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", key, err
	}
	return base64.RawURLEncoding.EncodeToString(id[:]), key, nil
}
