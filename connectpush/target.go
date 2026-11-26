package connectpush

import (
	"encoding/base64"
	"errors"
	"strings"
)

// Target is what a phone gives each paired computer, over the encrypted
// TailPocket session only, so the computer can push to it: the gateway, the
// app id the gateway knows, the handle it got there, and the push key with
// its key id. Key is the secret: it opens every note sealed for the phone.
type Target struct {
	Gateway string `json:"gateway"`
	App     string `json:"app"`
	Handle  string `json:"handle"`
	Kid     string `json:"kid"`
	Key     string `json:"key"` // 32 bytes, base64url without padding
}

// Limits on a Target, so it fits one control message (4 KiB).
const (
	maxGatewayURL = 512
	maxHandle     = 2048
)

// Validate checks every field of t: an https:// gateway URL (http:// only to
// a loopback address), an app id and key id Seal takes, a base64url handle,
// and a 32-byte key that is not all zero.
func (t Target) Validate() error {
	bad := func(what string) error { return errors.New("connectpush: invalid push target: " + what) }
	if ValidGateway(t.Gateway) != nil {
		return bad("gateway")
	}
	if checkField("app", t.App, maxApp) != nil {
		return bad("app")
	}
	if checkField("kid", t.Kid, MaxKid) != nil {
		return bad("kid")
	}
	if t.Handle == "" || len(t.Handle) > maxHandle || !IsBase64URL(t.Handle) {
		return bad("handle")
	}
	if _, err := t.KeyBytes(); err != nil {
		return bad("key")
	}
	return nil
}

// ValidGateway checks a gateway URL as Client uses it: https:// (http:// only to a loopback
// address), no user, query or fragment, ASCII only (no lookalike host names), at most 512 characters.
func ValidGateway(u string) error {
	if len(u) > maxGatewayURL || strings.ContainsAny(u, " \t\r\n") || !isASCII(u) {
		return errors.New("connectpush: invalid gateway URL")
	}
	_, err := (&Client{URL: u}).base()
	return err
}

// KeyBytes decodes Key.
func (t Target) KeyBytes() ([32]byte, error) {
	var k [32]byte
	b, err := base64.RawURLEncoding.Strict().DecodeString(t.Key)
	if err != nil || len(b) != 32 || !IsBase64URL(t.Key) {
		return k, errors.New("connectpush: push key is not 32 bytes of base64url")
	}
	copy(k[:], b)
	if k == [32]byte{} {
		return k, errors.New("connectpush: push key is zero")
	}
	return k, nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
