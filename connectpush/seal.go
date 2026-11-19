// Package connectpush encrypts push notes end to end and talks to a
// tailpocket-push gateway.
//
// The computer seals each note with the push key of the phone it goes to
// (Seal); the gateway, APNs and FCM only carry the result, and the phone's
// notification extension opens it (Open). The format is in docs/PUSH.md and
// testdata/vectors.json has fixed vectors for other implementations.
//
// AES-256-GCM is used because every side has it: iOS CryptoKit, javax.crypto
// on Android minSdk 26 (which has no ChaCha20-Poly1305) and the Go standard
// library.
package connectpush

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Note is what a push shows once the phone has opened it.
type Note struct {
	Title  string `json:"title,omitempty"`
	Body   string `json:"body,omitempty"`
	Thread string `json:"thread,omitempty"`
	URL    string `json:"url,omitempty"`
	Kind   string `json:"kind,omitempty"`
	Sent   int64  `json:"sent"` // unix seconds, the computer's clock
	Seq    uint64 `json:"seq"`  // per key id, from 1, always increasing
}

const (
	// MaxCiphertext is the longest sealed note the gateway takes, in
	// base64url characters. The largest Seal can make, with a MaxKid-byte
	// key id and the 2048-byte tier, is 2855.
	MaxCiphertext = 3000

	// MaxKid is the longest key id, in bytes.
	MaxKid = 64

	// MaxAge and MaxSkew bound Note.Sent as seen by Open.
	MaxAge  = 24 * time.Hour
	MaxSkew = 5 * time.Minute

	// Label starts the associated data, so a sealed note cannot be taken
	// for anything else sealed with the same key.
	Label = "tailpocket push 1"

	nonceSize = 12
	tagSize   = 16
	maxApp    = 255
)

// Tiers are the only plaintext lengths Seal produces: the note's JSON is
// padded to the smallest that fits, so the ciphertext length says which
// tier, not how long the text is.
var Tiers = [...]int{256, 1024, 2048}

var (
	ErrTooLarge   = errors.New("connectpush: note too long for the largest padding tier; shorten the body")
	ErrMalformed  = errors.New("connectpush: malformed sealed note")
	ErrUnknownKey = errors.New("connectpush: unknown key id")
	ErrAuth       = errors.New("connectpush: sealed note does not open with this key and app")
	ErrExpired    = errors.New("connectpush: note sent more than 24 hours ago")
	ErrFuture     = errors.New("connectpush: note sent more than 5 minutes in the future")
	ErrReplay     = errors.New("connectpush: note seq not above the highest seen for this key id")
)

// AAD is the associated data for app and kid:
// Label || 0x00 || app || 0x00 || kid.
func AAD(app, kid string) []byte {
	b := make([]byte, 0, len(Label)+2+len(app)+len(kid))
	b = append(b, Label...)
	b = append(b, 0)
	b = append(b, app...)
	b = append(b, 0)
	b = append(b, kid...)
	return b
}

func checkField(what, s string, max int) error {
	if s == "" || len(s) > max || strings.IndexByte(s, 0) >= 0 {
		return fmt.Errorf("connectpush: %s must be 1 to %d bytes without NUL", what, max)
	}
	return nil
}

// Seal encrypts n for the phone holding key under key id kid, for the
// gateway app id app. The result is base64url without padding of
// len(kid) || kid || nonce || AES-256-GCM(pad(JSON(n))), at most
// MaxCiphertext characters. n.Seq must be above 0.
func Seal(key [32]byte, kid string, app string, n Note) (string, error) {
	return SealRand(rand.Reader, key, kid, app, n)
}

// SealRand is Seal with the 12-byte nonce read from r. Only tests should
// pass anything but crypto/rand.Reader: a repeated nonce under one key
// gives the key stream away.
func SealRand(r io.Reader, key [32]byte, kid string, app string, n Note) (string, error) {
	if n.Seq == 0 {
		return "", errors.New("connectpush: Note.Seq must start at 1")
	}
	js, err := marshalNote(n)
	if err != nil {
		return "", err
	}
	pt, err := pad(js)
	if err != nil {
		return "", err
	}
	return sealPadded(r, key, kid, app, pt)
}

func sealPadded(r io.Reader, key [32]byte, kid, app string, pt []byte) (string, error) {
	if err := checkField("kid", kid, MaxKid); err != nil {
		return "", err
	}
	if err := checkField("app", app, maxApp); err != nil {
		return "", err
	}
	aead, err := newGCM(key)
	if err != nil {
		return "", err
	}
	out := make([]byte, 1+len(kid)+nonceSize, 1+len(kid)+nonceSize+len(pt)+tagSize)
	out[0] = byte(len(kid))
	copy(out[1:], kid)
	nonce := out[1+len(kid):]
	if _, err := io.ReadFull(r, nonce); err != nil {
		return "", fmt.Errorf("connectpush: read nonce: %w", err)
	}
	out = aead.Seal(out, nonce, pt, AAD(app, kid))
	s := base64.RawURLEncoding.EncodeToString(out)
	if len(s) > MaxCiphertext {
		return "", ErrTooLarge // not reached with MaxKid and Tiers as they are
	}
	return s, nil
}

// pad is uint16 big-endian len(js) || js || zero bytes, to the smallest
// tier at least len(js)+2.
func pad(js []byte) ([]byte, error) {
	for _, t := range Tiers {
		if len(js)+2 <= t {
			pt := make([]byte, t)
			binary.BigEndian.PutUint16(pt, uint16(len(js)))
			copy(pt[2:], js)
			return pt, nil
		}
	}
	return nil, ErrTooLarge
}

// unpad checks the padding of an opened plaintext and returns the JSON.
func unpad(pt []byte) ([]byte, error) {
	if !isTier(len(pt)) {
		return nil, ErrMalformed
	}
	n := int(binary.BigEndian.Uint16(pt))
	if n > len(pt)-2 {
		return nil, ErrMalformed
	}
	for _, b := range pt[2+n:] {
		if b != 0 {
			return nil, ErrMalformed
		}
	}
	return pt[2 : 2+n], nil
}

func isTier(n int) bool {
	for _, t := range Tiers {
		if n == t {
			return true
		}
	}
	return false
}

// marshalNote is the note as compact JSON without HTML escaping.
func marshalNote(n Note) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(n); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func newGCM(key [32]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// IsBase64URL reports whether s is only base64url characters (no padding,
// no white space). The standard decoder alone does not check this: it
// skips line breaks.
func IsBase64URL(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// Check reports whether ct has the shape of a sealed note, without opening
// it: base64url, at most MaxCiphertext characters, a key id, and a
// ciphertext of one of the Tiers. The gateway refuses anything else.
func Check(ct string) error {
	raw, err := decode(ct)
	if err != nil {
		return err
	}
	_, _, _, err = split(raw)
	return err
}

func decode(ct string) ([]byte, error) {
	if len(ct) > MaxCiphertext {
		return nil, ErrTooLarge
	}
	if !IsBase64URL(ct) {
		return nil, ErrMalformed
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(ct)
	if err != nil {
		return nil, ErrMalformed
	}
	return raw, nil
}

func split(raw []byte) (kid string, nonce, sealed []byte, err error) {
	if len(raw) < 1 {
		return "", nil, nil, ErrMalformed
	}
	k := int(raw[0])
	if k == 0 || k > MaxKid || len(raw) < 1+k+nonceSize {
		return "", nil, nil, ErrMalformed
	}
	kid = string(raw[1 : 1+k])
	sealed = raw[1+k+nonceSize:]
	if strings.IndexByte(kid, 0) >= 0 || !isTier(len(sealed)-tagSize) {
		return "", nil, nil, ErrMalformed
	}
	return kid, raw[1+k : 1+k+nonceSize], sealed, nil
}

// Open decrypts ct sealed for app and returns the note and its key id.
//
// keys returns the push key for a key id, or false when there is none.
// last returns the highest Seq already accepted for a key id (0 if none);
// Open only accepts a note whose Seq is above it. The caller must then
// store the returned note's Seq as the new highest for kid, durably,
// before showing it, and must run Open and that store under one lock so
// two notes cannot both pass against the same highest value.
//
// Any failure returns an error, a zero Note and no key id: nothing of a
// note that did not pass every check is returned.
func Open(keys func(kid string) ([32]byte, bool), app string, ct string, now time.Time, last func(kid string) uint64) (Note, string, error) {
	if keys == nil || last == nil {
		return Note{}, "", errors.New("connectpush: Open needs keys and last")
	}
	if err := checkField("app", app, maxApp); err != nil {
		return Note{}, "", err
	}
	raw, err := decode(ct)
	if err != nil {
		return Note{}, "", err
	}
	kid, nonce, sealed, err := split(raw)
	if err != nil {
		return Note{}, "", err
	}
	key, ok := keys(kid)
	if !ok {
		return Note{}, "", ErrUnknownKey
	}
	aead, err := newGCM(key)
	if err != nil {
		return Note{}, "", err
	}
	pt, err := aead.Open(nil, nonce, sealed, AAD(app, kid))
	if err != nil {
		return Note{}, "", ErrAuth
	}
	js, err := unpad(pt)
	if err != nil {
		return Note{}, "", err
	}
	var n Note
	if err := json.Unmarshal(js, &n); err != nil {
		return Note{}, "", ErrMalformed
	}
	// Sent comes from the computer's clock and the phone's may be off, so
	// this is a backstop; Seq is what stops a replay.
	sent := time.Unix(n.Sent, 0)
	if sent.Before(now.Add(-MaxAge)) {
		return Note{}, "", ErrExpired
	}
	if sent.After(now.Add(MaxSkew)) {
		return Note{}, "", ErrFuture
	}
	if n.Seq <= last(kid) {
		return Note{}, "", ErrReplay
	}
	return n, kid, nil
}
