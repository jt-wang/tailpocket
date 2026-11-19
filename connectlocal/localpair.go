// Package connectlocal delivers a pairing invite to a phone on the same Wi-Fi: the phone finds the host
// over Bonjour, commits to an X25519 key, the host answers with its own, the phone reveals its key,
// both show a 6-digit code, and after the host's user confirms the codes match, the host sends the
// invite sealed with ChaCha20-Poly1305. It only delivers the invite; the connection itself always
// goes over Tailcat.
//
// Wire format v2 (newline-terminated JSON lines, sorted keys, at most MaxLine bytes):
//
//	phone → host  {"commit":"<base64 SHA256(label‖\"commit\"‖phonePub‖nonce)>","device":"<≤64 chars>","v":2}
//	host  → phone {"publicKey":"<base64 X25519>","v":2}
//	phone → host  {"nonce":"<base64 32 random bytes>","publicKey":"<base64 X25519>","v":2}
//	              the host checks the commitment; both sides show the code; the host's user approves or denies
//	host  → phone {"sealed":"<base64>","status":"approved","v":2}
//	           or {"status":"denied","v":2} / {"reason":"expired","status":"denied","v":2}
//
// The host closes the connection without a reply on any malformed line, other version (v1 included),
// commitment mismatch or timeout. The commitment stops a machine in the middle from choosing its key
// after it has seen the other side's: each attempt matches the two codes with probability 10^-6.
// Throwing an attempt away and starting again is bounded too: a window gives its key to at most
// MaxAttempts commitments (an honest phone needs one), at most one per source address every
// SourceGap, and ends with ErrTooManyAttempts once that many have not been approved. So a window
// lets a machine in the middle match the codes with probability at most MaxAttempts × 10^-6.
package connectlocal

import (
	"errors"
	"strconv"
	"time"
)

const (
	DefaultLabel = "tailpocket-local-pairing-v1"
	MaxLine      = 4096
	wireVersion  = 2
	// MaxAttempts is how many commitments one window answers with its key.
	MaxAttempts = 3
	// SourceGap is the least time between two answers to the same source address.
	SourceGap = 2 * time.Second
)

// sourceGap is SourceGap; tests that pair many times from loopback set it to 0.
var sourceGap = SourceGap

var (
	ErrDenied      = errors.New("local pairing denied")
	ErrExpired     = errors.New("local pairing window expired")
	ErrFailed      = errors.New("local pairing failed")
	ErrNotApproved = errors.New("no phone was approved before the window closed")
	ErrUnavailable = errors.New("no Wi-Fi/LAN address to serve local pairing on")
	// ErrTooManyAttempts: MaxAttempts phones (or one machine trying again and again) got the host's
	// key without being approved, so the window closed. Tell the user to start again.
	ErrTooManyAttempts = errors.New("local pairing window closed after too many attempts")
)

func itoa(i int) string { return strconv.Itoa(i) }
