package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jt-wang/tailpocket/connectpush"
)

// testdata/playintegrity_local.json was made with Python's `cryptography` library, not with this
// package (.amp/in/orb-backup/pi-vec/gen.py in the thread that wrote it): a classic token, its
// keys and payload, and RFC 3394's 256-bit key-wrap vector.
type localVector struct {
	DecryptionKey   string `json:"decryption_key"`
	VerificationKey string `json:"verification_key"`
	Token           string `json:"token"`
	Payload         string `json:"payload"`
	RFC3394         struct {
		KEK, Key, Wrapped string
	} `json:"rfc3394"`
}

func readLocalVector(t *testing.T) localVector {
	t.Helper()
	b, err := os.ReadFile("testdata/playintegrity_local.json")
	if err != nil {
		t.Fatal(err)
	}
	var v localVector
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// writeLocalKeys writes the two key files as Play Console gives them and returns their names.
func writeLocalKeys(t *testing.T, dir, dk, vk string) (string, string) {
	t.Helper()
	writeFile(t, filepath.Join(dir, "pi-decryption.key"), []byte(dk+"\n"))
	writeFile(t, filepath.Join(dir, "pi-verification.key"), []byte(vk+"\n"))
	return "pi-decryption.key", "pi-verification.key"
}

func TestAESKeyUnwrapRFC3394(t *testing.T) {
	v := readLocalVector(t).RFC3394
	kek, _ := hex.DecodeString(v.KEK)
	want, _ := hex.DecodeString(v.Key)
	c, _ := hex.DecodeString(v.Wrapped)
	blk, _ := aes.NewCipher(kek)
	got, ok := aesKeyUnwrap(blk, c)
	if !ok || hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("unwrap: %x %v, want %x", got, ok, want)
	}
	c[len(c)-1] ^= 1
	if _, ok := aesKeyUnwrap(blk, c); ok {
		t.Fatal("a changed wrapped key unwrapped")
	}
}

func TestLocalDecodeVector(t *testing.T) {
	v := readLocalVector(t)
	dir := t.TempDir()
	dk, vk := writeLocalKeys(t, dir, v.DecryptionKey, v.VerificationKey)
	k, err := loadLocalKeys(dir, dk, vk)
	if err != nil {
		t.Fatal(err)
	}
	got, err := k.decode(v.Token)
	if err != nil || string(got) != v.Payload {
		t.Fatalf("decode: %q %v", got, err)
	}
	// Any one changed character, in any of the five parts, and nothing decodes.
	for i := 0; i < len(v.Token); i++ {
		if v.Token[i] == '.' {
			continue
		}
		b := []byte(v.Token)
		b[i] = map[bool]byte{true: 'B', false: 'A'}[b[i] == 'A']
		if _, err := k.decode(string(b)); err == nil {
			t.Fatalf("token changed at %d decoded", i)
		}
	}
	for name, tok := range map[string]string{
		"standard-request shape": "a.b.c",
		"empty":                  "",
		"six parts":              v.Token + ".x",
	} {
		if _, err := k.decode(tok); err == nil {
			t.Fatalf("%s decoded", name)
		}
	}
}

// classicToken makes a classic token the way Google does: payload signed ES256 with signer, then
// encrypted A256KW/A256GCM under dk. jweHeader and jwsHeader may be changed to test refusals.
func classicToken(t *testing.T, dk []byte, signer *ecdsa.PrivateKey, payload []byte, jweHeader, jwsHeader string) string {
	t.Helper()
	enc := base64.RawURLEncoding.EncodeToString
	signing := enc([]byte(jwsHeader)) + "." + enc(payload)
	d := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, signer, d[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	jws := signing + "." + enc(sig)
	cek := make([]byte, 32)
	iv := make([]byte, 12)
	rand.Read(cek)
	rand.Read(iv)
	eh := enc([]byte(jweHeader))
	blk, _ := aes.NewCipher(cek)
	gcm, _ := cipher.NewGCM(blk)
	sealed := gcm.Seal(nil, iv, []byte(jws), []byte(eh))
	kek, _ := aes.NewCipher(dk)
	return strings.Join([]string{eh, enc(aesKeyWrap(kek, cek)), enc(iv), enc(sealed[:len(sealed)-16]), enc(sealed[len(sealed)-16:])}, ".")
}

// aesKeyWrap is RFC 3394 key wrap, for tests (the gateway only unwraps).
func aesKeyWrap(kek cipher.Block, p []byte) []byte {
	n := len(p) / 8
	a := [8]byte{0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6}
	r := append([]byte(nil), p...)
	var b [16]byte
	for j := 0; j <= 5; j++ {
		for i := 1; i <= n; i++ {
			copy(b[:8], a[:])
			copy(b[8:], r[(i-1)*8:i*8])
			kek.Encrypt(b[:], b[:])
			binary.BigEndian.PutUint64(a[:], binary.BigEndian.Uint64(b[:8])^uint64(n*j+i))
			copy(r[(i-1)*8:i*8], b[8:])
		}
	}
	return append(a[:], r...)
}

// localGateway is a gateway whose attest.android decodes classic tokens with its own keys.
func localGateway(t *testing.T) (*gw, []byte, *ecdsa.PrivateKey) {
	t.Helper()
	g := newGatewayWith(t, attestedConfig())
	dk := make([]byte, 32)
	rand.Read(dk)
	google, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&google.PublicKey)
	dkf, vkf := writeLocalKeys(t, g.dir, base64.StdEncoding.EncodeToString(dk), base64.StdEncoding.EncodeToString(der))
	cfg := strings.Replace(attestedConfig(), `"package_name": "io.example.alpha",`,
		`"package_name": "io.example.alpha", "decryption_key_file": "`+dkf+`", "verification_key_file": "`+vkf+`",`, 1)
	g.srv = g.build(cfg)
	return g, dk, google
}

// localPayload is a verdict's payload, as a classic token carries it.
func localPayload(v verdict) []byte {
	var outer struct {
		P json.RawMessage `json:"tokenPayloadExternal"`
	}
	_ = json.Unmarshal([]byte(v.json()), &outer)
	return outer.P
}

const (
	jweHdr = `{"alg":"A256KW","enc":"A256GCM"}`
	jwsHdr = `{"alg":"ES256"}`
)

func TestPlayIntegrityLocalKeys(t *testing.T) {
	g, dk, google := localGateway(t)
	const piPath = "/pi/v1/io.example.alpha:decodeIntegrityToken"
	digest := base64.RawURLEncoding.EncodeToString(certDigest[:])
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	try := func(i int, signer *ecdsa.PrivateKey, jwe, jws string, edit func(*verdict)) *devResp {
		t.Helper()
		reg := devReq{"register", "fcm", fcmToken(200 + i), 1}
		ch := g.challenge(freshIP())
		v := verdict{nonce: connectpush.AttestRequestHash(reg.op, appA, reg.platform, reg.token, reg.gen, ch),
			pkg: appA, reqPkg: appA, recog: "PLAY_RECOGNIZED", certs: []string{digest},
			device: []string{"MEETS_DEVICE_INTEGRITY"}, ts: g.clock.now().Add(-time.Minute)}
		if edit != nil {
			edit(&v)
		}
		return g.attested(reg, freshIP(), map[string]any{"challenge": ch, "token": classicToken(t, dk, signer, localPayload(v), jwe, jws)})
	}
	try(0, google, jweHdr, jwsHdr, nil).want(t, 200, "")
	for i, c := range []struct {
		name     string
		signer   *ecdsa.PrivateKey
		jwe, jws string
		edit     func(*verdict)
	}{
		{"signed by another key", other, jweHdr, jwsHdr, nil},
		{"JWE alg dir", google, `{"alg":"dir","enc":"A256GCM"}`, jwsHdr, nil},
		{"JWE enc A128GCM", google, `{"alg":"A256KW","enc":"A128GCM"}`, jwsHdr, nil},
		{"JWE zip", google, `{"alg":"A256KW","enc":"A256GCM","zip":"DEF"}`, jwsHdr, nil},
		{"JWS alg none", google, jweHdr, `{"alg":"none"}`, nil},
		{"JWS alg HS256", google, jweHdr, `{"alg":"HS256"}`, nil},
		{"JWS crit", google, jweHdr, `{"alg":"ES256","crit":["x"]}`, nil},
		// The verdict checks still apply to a token that decodes.
		{"nonce for another request", google, jweHdr, jwsHdr, func(v *verdict) { v.nonce = "x" }},
		{"basic integrity only", google, jweHdr, jwsHdr, func(v *verdict) { v.device = []string{"MEETS_BASIC_INTEGRITY"} }},
	} {
		if r := try(1+i, c.signer, c.jwe, c.jws, c.edit); r.code != 401 || !strings.Contains(r.body, "attestation_failed") {
			t.Fatalf("%s: %d %s", c.name, r.code, r.body)
		}
	}
	if n := len(g.up.find(piPath)); n != 0 {
		t.Fatalf("%d calls to Google with local keys", n)
	}
}

// Made-up tokens on a gateway with local keys cost Google nothing and use up no budget: a real
// phone still registers after 1000 of them.
func TestPlayIntegrityLocalKeysHaveNoBudget(t *testing.T) {
	g, dk, google := localGateway(t)
	for i := 0; i < 1000; i++ {
		ip := freshIP()
		ch := g.challenge(ip)
		g.attested(devReq{"register", "fcm", fcmToken(5000 + i), 1}, ip, map[string]any{"challenge": ch, "token": "made-up-" + ch}).want(t, 401, "attestation_failed")
	}
	reg := devReq{"register", "fcm", fcmToken(1), 1}
	ch := g.challenge(freshIP())
	v := verdict{nonce: connectpush.AttestRequestHash(reg.op, appA, reg.platform, reg.token, reg.gen, ch),
		pkg: appA, reqPkg: appA, recog: "PLAY_RECOGNIZED", certs: []string{base64.RawURLEncoding.EncodeToString(certDigest[:])},
		device: []string{"MEETS_DEVICE_INTEGRITY"}, ts: g.clock.now().Add(-time.Minute)}
	g.attested(reg, freshIP(), map[string]any{"challenge": ch, "token": classicToken(t, dk, google, localPayload(v), jweHdr, jwsHdr)}).want(t, 200, "")
	if n := len(g.up.find("/pi/v1/io.example.alpha:decodeIntegrityToken")); n != 0 {
		t.Fatalf("%d calls to Google", n)
	}
}

func TestPlayIntegrityLocalKeyConfig(t *testing.T) {
	v := readLocalVector(t)
	dir := t.TempDir()
	dk, vk := writeLocalKeys(t, dir, v.DecryptionKey, v.VerificationKey)
	if _, err := loadLocalKeys(dir, dk, ""); err == nil {
		t.Fatal("a decryption key without its verification key was taken")
	}
	if _, err := loadLocalKeys(dir, vk, vk); err == nil {
		t.Fatal("a verification key was taken as the decryption key")
	}
	if _, err := loadLocalKeys(dir, dk, dk); err == nil {
		t.Fatal("the decryption key was taken as the verification key")
	}
	if err := os.Chmod(filepath.Join(dir, dk), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadLocalKeys(dir, dk, vk); err == nil && othersCanRead(filepath.Join(dir, dk)) {
		t.Fatal("a decryption key other users can read was taken")
	}
}

// A source whose evidence fails attestFailLimit times in a row is blocked for attestFailBlock,
// before Google is asked again; an IPv6 /64 is one source, and a success clears the run.
func TestAttestFailuresBlockTheSource(t *testing.T) {
	g := newGatewayWith(t, attestedConfig())
	const piPath = "/pi/v1/io.example.alpha:decodeIntegrityToken"
	g.up.setReply(func(p string) (int, string) { return 400, `{"error":{}}` })
	digest := base64.RawURLEncoding.EncodeToString(certDigest[:])
	send := func(ip string, i int, good bool) *devResp {
		t.Helper()
		reg := devReq{"register", "fcm", fcmToken(300 + i), 1}
		ch := g.challenge(ip)
		v := verdict{hash: connectpush.AttestRequestHash(reg.op, appA, reg.platform, reg.token, reg.gen, ch), pkg: appA, reqPkg: appA,
			recog: "PLAY_RECOGNIZED", certs: []string{digest}, device: []string{"MEETS_DEVICE_INTEGRITY"}, ts: g.clock.now().Add(-time.Minute)}
		g.up.setReply(func(p string) (int, string) {
			if p == piPath && good {
				return 200, v.json()
			}
			return 400, `{"error":{}}`
		})
		return g.attested(reg, ip, map[string]any{"challenge": ch, "token": "tok-" + ch})
	}
	a, a2 := "[2001:db8:1:2::1]:1", "[2001:db8:1:2:ffff::9]:1"
	for i := 0; i < attestFailLimit; i++ {
		send(a, i, false).want(t, 401, "attestation_failed")
	}
	calls := len(g.up.find(piPath))
	send(a, 10, true).want(t, 429, "blocked")
	send(a2, 11, true).want(t, 429, "blocked") // same /64
	if n := len(g.up.find(piPath)); n != calls {
		t.Fatalf("Google asked %d more times for a blocked source", n-calls)
	}
	send("[2001:db8:1:3::1]:1", 12, true).want(t, 200, "") // the next /64 is another source
	g.clock.advance(attestFailBlock + time.Second)
	send(a, 13, true).want(t, 200, "")

	// A success in between clears the run: fail, fail, pass, fail, fail is not blocked.
	b := freshIP()
	for i, good := range []bool{false, false, true, false, false} {
		r := send(b, 20+i, good)
		if good {
			r.want(t, 200, "")
		} else {
			r.want(t, 401, "attestation_failed")
		}
	}
	send(b, 30, true).want(t, 200, "")
}

// Answers that say nothing about the evidence free the source's slot: after attestFailLimit bad
// challenges the same source still reaches the verifier and registers.
func TestBadChallengesDoNotBlockTheSource(t *testing.T) {
	g := newGatewayWith(t, attestedConfig())
	ip := freshIP()
	for i := 0; i < attestFailLimit+1; i++ {
		g.attested(devReq{"register", "fcm", fcmToken(400 + i), 1}, ip, map[string]any{"challenge": "made-up", "token": "x"}).want(t, 401, "bad_challenge")
	}
	reg := devReq{"register", "fcm", fcmToken(1), 1}
	ch := g.challenge(ip)
	v := verdict{hash: connectpush.AttestRequestHash(reg.op, appA, reg.platform, reg.token, reg.gen, ch), pkg: appA, reqPkg: appA,
		recog: "PLAY_RECOGNIZED", certs: []string{base64.RawURLEncoding.EncodeToString(certDigest[:])},
		device: []string{"MEETS_DEVICE_INTEGRITY"}, ts: g.clock.now().Add(-time.Minute)}
	g.up.setReply(func(string) (int, string) { return 200, v.json() })
	g.attested(reg, ip, map[string]any{"challenge": ch, "token": "tok"}).want(t, 200, "")
}
