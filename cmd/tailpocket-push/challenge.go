package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"sync"
	"time"
)

// challenges are the one-time values attestation evidence is bound to
// (POST /v1/challenge). A challenge is
//
//	base64url(random (16) || expires (8, unix seconds) || HMAC-SHA256(k, label || 0x00 || app || 0x00 || random || expires)[:16])
//
// so the gateway checks one without storing it, and remembers only the ones
// already used, until they expire. k comes from the handle key. A restart
// forgets which were used: one may then be used again within its few minutes,
// still only for the same app, device, operation and generation.
type challenges struct {
	key []byte
	max int

	mu   sync.Mutex
	used map[string]int64 // challenge -> expires
}

const (
	challengeLabel = "tailpocket push challenge 1"
	challengeLife  = 5 * time.Minute
	challengeLen   = 16 + 8 + 16
	maxChallenges  = 1 << 16 // used ones held at once
)

func newChallenges(key []byte) *challenges {
	return &challenges{key: key, max: maxChallenges, used: map[string]int64{}}
}

func (c *challenges) mac(app string, body []byte) []byte {
	m := hmac.New(sha256.New, c.key)
	m.Write([]byte(challengeLabel))
	m.Write([]byte{0})
	m.Write([]byte(app))
	m.Write([]byte{0})
	m.Write(body)
	return m.Sum(nil)[:16]
}

func (c *challenges) issue(app string, now time.Time) (string, int64, error) {
	b := make([]byte, 24, challengeLen)
	if _, err := rand.Read(b[:16]); err != nil {
		return "", 0, err
	}
	exp := now.Add(challengeLife).Unix()
	binary.BigEndian.PutUint64(b[16:], uint64(exp))
	b = append(b, c.mac(app, b)...)
	return base64.RawURLEncoding.EncodeToString(b), exp, nil
}

// take reports whether ch is a challenge this gateway issued for app that
// has neither expired nor been taken before, and marks it taken.
func (c *challenges) take(app, ch string, now time.Time) bool {
	if base64.RawURLEncoding.EncodedLen(challengeLen) != len(ch) {
		return false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(ch)
	if err != nil || len(b) != challengeLen || !hmac.Equal(b[24:], c.mac(app, b[:24])) {
		return false
	}
	exp := int64(binary.BigEndian.Uint64(b[16:24]))
	if exp <= now.Unix() || exp > now.Add(challengeLife+time.Minute).Unix() {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.used[ch]; ok {
		return false
	}
	if len(c.used) >= c.max {
		c.sweepLocked(now)
		if len(c.used) >= c.max {
			return false // full of live ones: refuse rather than forget one
		}
	}
	c.used[ch] = exp
	return true
}

// give takes back a challenge whose evidence did not pass, so the table holds only challenges that
// paid for a success: requests with no real evidence cannot fill it. A challenge stays good for
// one success.
func (c *challenges) give(ch string) {
	c.mu.Lock()
	delete(c.used, ch)
	c.mu.Unlock()
}

func (c *challenges) sweep(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepLocked(now)
}

func (c *challenges) sweepLocked(now time.Time) {
	for k, exp := range c.used {
		if exp <= now.Unix() {
			delete(c.used, k)
		}
	}
}
