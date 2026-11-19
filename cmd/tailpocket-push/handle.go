package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"time"

	"github.com/jt-wang/tailpocket/connectpush"
)

// A handle is the gateway's own sealed record of one device token:
//
//	base64url(header || nonce || AES-256-GCM(key[id], nonce, body, aad))
//	header = version (1) || id (1) || len(app) (1) || app
//	aad    = handleLabel || 0x00 || header
//	body   = platform (1) || issued (8) || expires (8) || generation (8) || source (8) || token
//
// Integers are big-endian, times unix seconds. id is the number of the
// handle key, so keys can be rotated. The app id is in clear so the gateway
// knows which app a send is for without the request saying so, and the
// whole header is the associated data: change any of its bytes, such as the
// app id, and the handle no longer opens. The gateway keeps no handle
// database: a handle that opens is one it gave out.
const (
	handleVersion byte = 1
	handleLabel        = "tailpocket push handle 1"

	platAPNs byte = 1
	platFCM  byte = 2

	handleKeySize = 32
	handleNonce   = 12
	handleTag     = 16
	handleFixed   = 1 + 8 + 8 + 8 + 8

	minAPNsToken = 16  // bytes once hex-decoded; today Apple's are 32
	maxAPNsToken = 200 // Apple says the length may grow
	minFCMToken  = 32
	maxFCMToken  = 1024

	// maxHandle is the longest handle the gateway reads, in characters.
	maxHandle = 2048

	maxHandleTTL = maxHandleTTLDays * 24 * time.Hour
	// handleSkew is how far in the future an issue time may be.
	handleSkew = 5 * time.Minute

	// maxGeneration keeps generations exact in every JSON parser.
	maxGeneration = 1<<53 - 1
)

var fcmTokenRe = regexp.MustCompile(`^[A-Za-z0-9_:.-]+$`)

// handle is what an opened handle holds.
type handle struct {
	app     string
	plat    byte
	issued  int64
	expires int64
	gen     uint64
	src     srcTag // who registered it, for the bad-token count
	token   []byte
}

// srcTag stands for a source address: a keyed hash, so a handle does not
// carry an address even to someone who holds a handle key.
type srcTag [8]byte

type handleKeys struct {
	current byte
	aeads   map[byte]cipher.AEAD
	srcKey  []byte
}

func platName(p byte) string {
	if p == platAPNs {
		return "apns"
	}
	return "fcm"
}

func handleHeader(id byte, app string) []byte {
	h := make([]byte, 0, 3+len(app))
	h = append(h, handleVersion, id, byte(len(app)))
	return append(h, app...)
}

func handleAAD(header []byte) []byte {
	b := make([]byte, 0, len(handleLabel)+1+len(header))
	b = append(b, handleLabel...)
	b = append(b, 0)
	return append(b, header...)
}

func (k *handleKeys) seal(h handle) (string, error) {
	if len(h.app) == 0 || len(h.app) > 255 {
		return "", errors.New("bad app id")
	}
	hdr := handleHeader(k.current, h.app)
	out := make([]byte, len(hdr)+handleNonce, len(hdr)+handleNonce+handleFixed+len(h.token)+handleTag)
	copy(out, hdr)
	nonce := out[len(hdr):]
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	body := make([]byte, handleFixed, handleFixed+len(h.token))
	body[0] = h.plat
	binary.BigEndian.PutUint64(body[1:], uint64(h.issued))
	binary.BigEndian.PutUint64(body[9:], uint64(h.expires))
	binary.BigEndian.PutUint64(body[17:], h.gen)
	copy(body[25:33], h.src[:])
	body = append(body, h.token...)
	out = k.aeads[k.current].Seal(out, nonce, body, handleAAD(hdr))
	return base64.RawURLEncoding.EncodeToString(out), nil
}

// open returns what s holds, or false if s was not made by this gateway
// with a key it still has. It does not check times or generations.
func (k *handleKeys) open(s string) (handle, bool) {
	if len(s) > maxHandle || !connectpush.IsBase64URL(s) {
		return handle{}, false
	}
	// Strict: one handle has one spelling, so a changed character always
	// changes the bytes.
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(raw) < 3 || raw[0] != handleVersion {
		return handle{}, false
	}
	aead, ok := k.aeads[raw[1]]
	if !ok {
		return handle{}, false
	}
	n := int(raw[2])
	if n == 0 || len(raw) < 3+n+handleNonce+handleFixed+1+handleTag {
		return handle{}, false
	}
	hdr := raw[:3+n]
	body, err := aead.Open(nil, raw[3+n:3+n+handleNonce], raw[3+n+handleNonce:], handleAAD(hdr))
	if err != nil {
		return handle{}, false
	}
	h := handle{
		app:     string(raw[3 : 3+n]),
		plat:    body[0],
		issued:  int64(binary.BigEndian.Uint64(body[1:])),
		expires: int64(binary.BigEndian.Uint64(body[9:])),
		gen:     binary.BigEndian.Uint64(body[17:]),
		token:   body[handleFixed:],
	}
	copy(h.src[:], body[25:33])
	if h.plat != platAPNs && h.plat != platFCM {
		return handle{}, false
	}
	return h, true
}

func (k *handleKeys) srcTag(addr string) srcTag {
	m := hmac.New(sha256.New, k.srcKey)
	m.Write([]byte(addr))
	var t srcTag
	copy(t[:], m.Sum(nil))
	return t
}

// parseToken checks a device token from a request. APNs tokens are hex
// and kept as bytes; FCM tokens are kept as they are.
func parseToken(platform, token string) (byte, []byte, error) {
	switch platform {
	case "apns":
		if len(token)%2 != 0 || len(token) < 2*minAPNsToken || len(token) > 2*maxAPNsToken {
			return 0, nil, errors.New("bad length")
		}
		b, err := hex.DecodeString(token)
		if err != nil {
			return 0, nil, err
		}
		return platAPNs, b, nil
	case "fcm":
		if len(token) < minFCMToken || len(token) > maxFCMToken || !fcmTokenRe.MatchString(token) {
			return 0, nil, errors.New("bad token")
		}
		return platFCM, []byte(token), nil
	}
	return 0, nil, errors.New("bad platform")
}

// deviceKey names one token of one app, whatever handle it came in: the
// per-device limits and the generation state count against it. It is
// not keyed, so it stays the same when the handle key changes; device
// tokens are long and random, so it does not give the token away.
func deviceKey(app string, plat byte, token []byte) string {
	h := sha256.New()
	h.Write([]byte(app))
	h.Write([]byte{0, plat, 0})
	h.Write(token)
	return hex.EncodeToString(h.Sum(nil))
}

// handleHash is how logs name a handle: the first 8 hex characters of its
// SHA-256, never the handle itself.
func handleHash(h string) string {
	s := sha256.Sum256([]byte(h))
	return hex.EncodeToString(s[:4])
}

func loadHandleKeys(c *config, warn func(string, ...any)) (*handleKeys, error) {
	k := &handleKeys{current: byte(c.HandleKeyID), aeads: map[byte]cipher.AEAD{}}
	add := func(id int, key []byte) error {
		block, err := aes.NewCipher(key)
		if err != nil {
			return err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return err
		}
		k.aeads[byte(id)] = aead
		return nil
	}
	key, created, err := loadOrCreateKey(c.HandleKeyFile)
	if err != nil {
		return nil, err
	}
	if created {
		warn("created handle key %s (id %d); back it up: without it every handle given out stops working", c.HandleKeyFile, c.HandleKeyID)
	}
	if othersCanRead(c.HandleKeyFile) {
		warn("warning: %s is readable by other users; chmod 600 it", c.HandleKeyFile)
	}
	if err := add(c.HandleKeyID, key); err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte("tailpocket push source tag 1"))
	k.srcKey = m.Sum(nil)
	for _, o := range c.OldHandleKeys {
		b, err := os.ReadFile(o.File)
		if err != nil {
			return nil, fmt.Errorf("old handle key %d: %w", o.ID, err)
		}
		if len(b) != handleKeySize {
			return nil, fmt.Errorf("old handle key %d: %s holds %d bytes, want %d", o.ID, o.File, len(b), handleKeySize)
		}
		if err := add(o.ID, b); err != nil {
			return nil, err
		}
	}
	return k, nil
}

// loadOrCreateKey reads the 32-byte handle key at path, or creates it with
// mode 0600 when there is no file.
func loadOrCreateKey(path string) (key []byte, created bool, err error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		key = make([]byte, handleKeySize)
		if _, err := rand.Read(key); err != nil {
			return nil, false, err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			return loadOrCreateKey(path) // another start made it first
		}
		if err != nil {
			return nil, false, fmt.Errorf("create handle key: %w", err)
		}
		_, err = f.Write(key)
		if err == nil {
			err = f.Sync()
		}
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(path)
			return nil, false, fmt.Errorf("write handle key: %w", err)
		}
		return key, true, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read handle key: %w", err)
	}
	if len(b) != handleKeySize {
		return nil, false, fmt.Errorf("handle key %s holds %d bytes, want %d", path, len(b), handleKeySize)
	}
	return b, false, nil
}
