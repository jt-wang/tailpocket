package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jt-wang/tailpocket/connectpush"
)

// ---- a little CBOR encoder, for building evidence ----

func cborHead(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 1<<8:
		return []byte{major<<5 | 24, byte(n)}
	case n < 1<<16:
		return binary.BigEndian.AppendUint16([]byte{major<<5 | 25}, uint16(n))
	case n < 1<<32:
		return binary.BigEndian.AppendUint32([]byte{major<<5 | 26}, uint32(n))
	}
	return binary.BigEndian.AppendUint64([]byte{major<<5 | 27}, n)
}

func cborEnc(v any) []byte {
	switch x := v.(type) {
	case int:
		if x < 0 {
			return cborHead(1, uint64(-1-x))
		}
		return cborHead(0, uint64(x))
	case []byte:
		return append(cborHead(2, uint64(len(x))), x...)
	case string:
		return append(cborHead(3, uint64(len(x))), x...)
	case []any:
		b := cborHead(4, uint64(len(x)))
		for _, e := range x {
			b = append(b, cborEnc(e)...)
		}
		return b
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		b := cborHead(5, uint64(len(x)))
		for _, k := range keys {
			b = append(b, cborEnc(k)...)
			b = append(b, cborEnc(x[k])...)
		}
		return b
	}
	panic(fmt.Sprintf("cborEnc %T", v))
}

func TestCBORDecoder(t *testing.T) {
	in := map[string]any{"a": []byte{1, 2}, "b": []any{"x", 5, -3, []byte{}}, "c": map[string]any{"d": 70000}}
	v, err := decodeCBOR(cborEnc(in))
	if err != nil {
		t.Fatal(err)
	}
	m := v.(map[string]any)
	if b := m["b"].([]any); b[1] != uint64(5) || b[2] != int64(-3) || m["c"].(map[string]any)["d"] != uint64(70000) {
		t.Fatalf("decoded %#v", v)
	}
	for _, bad := range [][]byte{
		{},
		{0x5f, 0xff},                       // indefinite byte string
		{0x42, 1},                          // short
		{0xa1, 0x01, 0x01},                 // integer key
		{0xa2, 0x61, 'a', 1, 0x61, 'a', 2}, // duplicate key
		append(cborEnc(1), 0),              // trailing data
		{0xc0, 0x00},                       // tag
		{0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // huge array
	} {
		if _, err := decodeCBOR(bad); err == nil {
			t.Errorf("decoded % x", bad)
		}
	}
}

// ---- App Attest ----

type fakeCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCA(t *testing.T, name string, parent *fakeCA) *fakeCA {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Unix(1_700_000_000, 0), NotAfter: time.Unix(2_000_000_000, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	pc, pk := tmpl, k
	if parent != nil {
		pc, pk = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, pc, &k.PublicKey, pk)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &fakeCA{cert: c, key: k}
}

// device is one phone's App Attest key and how its maker signs.
type device struct {
	key   *ecdsa.PrivateKey
	id    []byte // SHA-256 of the public key
	inter *fakeCA
}

func newDevice(inter *fakeCA) *device {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pt, _ := k.PublicKey.Bytes()
	id := sha256.Sum256(pt)
	return &device{key: k, id: id[:], inter: inter}
}

func (d *device) keyID() string { return base64.StdEncoding.EncodeToString(d.id) }

// attOpts changes one thing about an attestation, to make it wrong.
type attOpts struct {
	rpID      string // default TEAM123456.io.example.alpha
	aaguid    []byte // default development
	counter   uint32
	credID    []byte
	nonceFrom []byte // clientDataHash the nonce is made from (default: the right one)
	noNonce   bool
}

func (d *device) attestation(t *testing.T, cdh [32]byte, o attOpts) string {
	t.Helper()
	if o.rpID == "" {
		o.rpID = "TEAM123456.io.example.alpha"
	}
	if o.aaguid == nil {
		o.aaguid = aaguidDevelopment[:]
	}
	if o.credID == nil {
		o.credID = d.id
	}
	rp := sha256.Sum256([]byte(o.rpID))
	auth := append([]byte(nil), rp[:]...)
	auth = append(auth, 0x41)
	auth = binary.BigEndian.AppendUint32(auth, o.counter)
	auth = append(auth, o.aaguid...)
	auth = binary.BigEndian.AppendUint16(auth, uint16(len(o.credID)))
	auth = append(auth, o.credID...)
	auth = append(auth, cborEnc(map[string]any{"1": 2})...) // stands for the COSE key, which the gateway does not read
	from := cdh[:]
	if o.nonceFrom != nil {
		from = o.nonceFrom
	}
	nonce := sha256.Sum256(append(append([]byte(nil), auth...), from...))
	ext, _ := asn1.Marshal(struct {
		Nonce []byte `asn1:"explicit,tag:1"`
	}{nonce[:]})
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "credcert"},
		NotBefore: time.Unix(1_700_000_000, 0), NotAfter: time.Unix(2_000_000_000, 0)}
	if !o.noNonce {
		tmpl.ExtraExtensions = []pkix.Extension{{Id: oidAppAttestNonce, Value: ext}}
	}
	leaf, err := x509.CreateCertificate(rand.Reader, tmpl, d.inter.cert, &d.key.PublicKey, d.inter.key)
	if err != nil {
		t.Fatal(err)
	}
	obj := cborEnc(map[string]any{"fmt": "apple-appattest", "authData": auth,
		"attStmt": map[string]any{"x5c": []any{leaf, d.inter.cert.Raw}, "receipt": []byte("receipt")}})
	return base64.StdEncoding.EncodeToString(obj)
}

func (d *device) assertion(t *testing.T, cdh [32]byte, counter uint32, rpID string) string {
	t.Helper()
	if rpID == "" {
		rpID = "TEAM123456.io.example.alpha"
	}
	rp := sha256.Sum256([]byte(rpID))
	auth := append(append([]byte(nil), rp[:]...), 0x01)
	auth = binary.BigEndian.AppendUint32(auth, counter)
	nonce := sha256.Sum256(append(append([]byte(nil), auth...), cdh[:]...))
	digest := sha256.Sum256(nonce[:])
	sig, err := ecdsa.SignASN1(rand.Reader, d.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(cborEnc(map[string]any{"signature": sig, "authenticatorData": auth}))
}

var certDigest = sha256.Sum256([]byte("play signing certificate"))

func attestedConfig() string {
	hexd := make([]string, 32)
	for i, b := range certDigest {
		hexd[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Replace(baseConfig, `"id": "io.example.alpha",`, `"id": "io.example.alpha", "attest": {
	  "ios": {"env": "development"},
	  "android": {"package_name": "io.example.alpha", "certificate_sha256": ["`+strings.Join(hexd, ":")+`"]}},`, 1)
}

// trustCA makes root the App Attest root for this test.
func trustCA(t *testing.T, root *fakeCA) {
	old := appAttestRoots
	p := x509.NewCertPool()
	p.AddCert(root.cert)
	appAttestRoots = p
	t.Cleanup(func() { appAttestRoots = old })
}

func (g *gw) challenge(remote string) string {
	g.t.Helper()
	w := g.post("/v1/challenge", remote, map[string]string{"app": appA})
	if w.Code != http.StatusOK {
		g.t.Fatalf("challenge: %d %s", w.Code, w.Body)
	}
	var out struct {
		Challenge string `json:"challenge"`
	}
	json.Unmarshal(w.Body.Bytes(), &out)
	return out.Challenge
}

type devReq struct {
	op, platform, token string
	gen                 uint64
}

func (r devReq) hash(ch string) [32]byte {
	return connectpush.AttestHash(r.op, appA, r.platform, r.token, r.gen, ch)
}

func (g *gw) attested(r devReq, remote string, ev map[string]any) *devResp {
	g.secret(r.token)
	w := g.post("/v1/"+r.op, remote, map[string]any{"app": appA, "platform": r.platform, "token": r.token, "generation": r.gen, "attest": ev})
	return &devResp{w.Code, w.Body.String()}
}

type devResp struct {
	code int
	body string
}

func (r *devResp) want(t *testing.T, code int, errCode string) {
	t.Helper()
	if r.code != code || errCode != "" && !strings.Contains(r.body, `"error":"`+errCode+`"`) {
		t.Fatalf("got %d %s, want %d %s", r.code, r.body, code, errCode)
	}
}

var ipSerial struct {
	sync.Mutex
	n int
}

// freshIP is a new source address, so register limits do not get in the way.
func freshIP() string {
	ipSerial.Lock()
	defer ipSerial.Unlock()
	ipSerial.n++
	return fmt.Sprintf("10.%d.%d.%d:1", ipSerial.n>>16&255, ipSerial.n>>8&255, ipSerial.n&255)
}

func TestAppAttestFlow(t *testing.T) {
	root := newCA(t, "root", nil)
	inter := newCA(t, "inter", root)
	trustCA(t, root)
	g := newGatewayWith(t, attestedConfig())
	tok := apnsToken(1)
	d := newDevice(inter)

	reg := devReq{"register", "apns", tok, 1}
	g.attested(reg, freshIP(), nil).want(t, 401, "attestation_required")
	g.attested(reg, freshIP(), map[string]any{"challenge": "made-up", "key_id": d.keyID(), "attestation": "AA=="}).want(t, 401, "bad_challenge")

	ch := g.challenge(freshIP())
	ev := map[string]any{"challenge": ch, "key_id": d.keyID(), "attestation": d.attestation(t, reg.hash(ch), attOpts{})}
	g.attested(reg, freshIP(), ev).want(t, 200, "")
	// The challenge is spent.
	g.attested(reg, freshIP(), ev).want(t, 401, "bad_challenge")
	// The same key attested again (a fresh, valid attestation) is refused.
	ch = g.challenge(freshIP())
	g.attested(reg, freshIP(), map[string]any{"challenge": ch, "key_id": d.keyID(), "attestation": d.attestation(t, reg.hash(ch), attOpts{})}).
		want(t, 401, "attestation_failed")

	// Later requests carry assertions with a rising counter.
	assert := func(r devReq, counter uint32) *devResp {
		ch := g.challenge(freshIP())
		return g.attested(r, freshIP(), map[string]any{"challenge": ch, "key_id": d.keyID(), "assertion": d.assertion(t, r.hash(ch), counter, "")})
	}
	reg2 := devReq{"register", "apns", tok, 2}
	assert(reg2, 1).want(t, 200, "")
	assert(reg2, 1).want(t, 401, "attestation_failed") // counter not above the last
	assert(reg2, 0).want(t, 401, "attestation_failed")
	assert(devReq{"revoke", "apns", tok, 2}, 2).want(t, 204, "")

	// Evidence made for one request does not pass for another.
	for _, c := range []struct {
		signed, sent devReq
	}{
		{devReq{"register", "apns", tok, 3}, devReq{"revoke", "apns", tok, 3}},            // operation
		{devReq{"register", "apns", tok, 3}, devReq{"register", "apns", tok, 4}},          // generation
		{devReq{"register", "apns", tok, 3}, devReq{"register", "apns", apnsToken(2), 3}}, // token
	} {
		ch := g.challenge(freshIP())
		g.attested(c.sent, freshIP(), map[string]any{"challenge": ch, "key_id": d.keyID(), "assertion": d.assertion(t, c.signed.hash(ch), 10, "")}).
			want(t, 401, "attestation_failed")
	}
	// A challenge for one challenge, signed over another.
	ch1, ch2 := g.challenge(freshIP()), g.challenge(freshIP())
	r3 := devReq{"register", "apns", tok, 3}
	g.attested(r3, freshIP(), map[string]any{"challenge": ch1, "key_id": d.keyID(), "assertion": d.assertion(t, r3.hash(ch2), 10, "")}).
		want(t, 401, "attestation_failed")

	// A key the gateway never saw.
	other := newDevice(inter)
	ch = g.challenge(freshIP())
	g.attested(r3, freshIP(), map[string]any{"challenge": ch, "key_id": other.keyID(), "assertion": other.assertion(t, r3.hash(ch), 1, "")}).
		want(t, 401, "attest_key_unknown")

	// The counter survives a restart.
	g.srv = g.build(attestedConfig())
	assert(r3, 2).want(t, 401, "attestation_failed")
	assert(r3, 3).want(t, 200, "")

	// FCM tokens of the same app go through Play Integrity, not App Attest.
	g.attested(devReq{"register", "fcm", fcmToken(1), 1}, freshIP(), nil).want(t, 401, "attestation_required")
	// App B has no attest: strict mode, and no challenges.
	g.register(appB, "apns", apnsToken(9), 1, freshIP())
	wantCode(t, g.post("/v1/challenge", freshIP(), map[string]string{"app": appB}), 400, "attest_not_configured")
	if n := len(g.up.find("/pi/v1/io.example.alpha:decodeIntegrityToken")); n != 0 {
		t.Fatalf("%d Play Integrity requests for App Attest", n)
	}
}

// TestAppAttestChecks calls the verifier with one thing wrong at a time.
func TestAppAttestChecks(t *testing.T) {
	root := newCA(t, "root", nil)
	inter := newCA(t, "inter", root)
	otherRoot := newCA(t, "other root", nil)
	otherInter := newCA(t, "other inter", otherRoot)
	trustCA(t, root)
	g := newGatewayWith(t, attestedConfig())
	v := g.srv.apps[appA].attest[platAPNs].(*appAttest)
	now := g.clock.now()
	req := func(d *device, cdh [32]byte, ev map[string]any) attestRequest {
		b, _ := json.Marshal(ev)
		return attestRequest{App: appA, Platform: "apns", Op: "register", Token: apnsToken(1), Generation: 1, Evidence: b, ClientDataHash: cdh, Now: now}
	}
	cdh := sha256.Sum256([]byte("client data"))
	wrongCDH := sha256.Sum256([]byte("other client data"))

	for name, c := range map[string]struct {
		dev    *device
		opts   attOpts
		reason string
		keyID  []byte
	}{
		"good":                 {opts: attOpts{}},
		"untrusted root":       {dev: newDevice(otherInter), reason: "chain"},
		"wrong rp id":          {opts: attOpts{rpID: "TEAM123456.io.example.bravo"}, reason: "rp-id"},
		"wrong team":           {opts: attOpts{rpID: "OTHER12345.io.example.alpha"}, reason: "rp-id"},
		"production aaguid":    {opts: attOpts{aaguid: aaguidProduction[:]}, reason: "environment"},
		"counter not 0":        {opts: attOpts{counter: 1}, reason: "counter"},
		"credential id":        {opts: attOpts{credID: make([]byte, 32)}, reason: "credential-id"},
		"nonce for other data": {opts: attOpts{nonceFrom: wrongCDH[:]}, reason: "nonce"},
		"no nonce":             {opts: attOpts{noNonce: true}, reason: "nonce"},
		"key id of another":    {keyID: newDevice(inter).id, reason: "key-id"},
	} {
		d := c.dev
		if d == nil {
			d = newDevice(inter)
		}
		kid := d.keyID()
		if c.keyID != nil {
			kid = base64.StdEncoding.EncodeToString(c.keyID)
		}
		err := v.Verify(context.Background(), req(d, cdh, map[string]any{"challenge": "c", "key_id": kid, "attestation": d.attestation(t, cdh, c.opts)}))
		if c.reason == "" {
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		if attestReason(err) != c.reason {
			t.Errorf("%s: %v, want %s", name, err, c.reason)
		}
		if _, ok := g.srv.gens.getAttestKey(base64.RawURLEncoding.EncodeToString(d.id)); ok {
			t.Errorf("%s: a refused key was stored", name)
		}
	}

	// Assertions.
	d := newDevice(inter)
	if err := v.Verify(context.Background(), req(d, cdh, map[string]any{"challenge": "c", "key_id": d.keyID(), "attestation": d.attestation(t, cdh, attOpts{})})); err != nil {
		t.Fatal(err)
	}
	as := func(sig string) error {
		return v.Verify(context.Background(), req(d, cdh, map[string]any{"challenge": "c", "key_id": d.keyID(), "assertion": sig}))
	}
	if err := as(d.assertion(t, wrongCDH, 1, "")); attestReason(err) != "signature" {
		t.Errorf("assertion over other data: %v", err)
	}
	if err := as(newDevice(inter).assertion(t, cdh, 1, "")); attestReason(err) != "signature" {
		t.Errorf("assertion by another key: %v", err)
	}
	if err := as(d.assertion(t, cdh, 1, "TEAM123456.io.example.bravo")); attestReason(err) != "rp-id" {
		t.Errorf("assertion for another app: %v", err)
	}
	if err := as(d.assertion(t, cdh, 5, "")); err != nil {
		t.Fatal(err)
	}
	for _, n := range []uint32{5, 4, 0} {
		if err := as(d.assertion(t, cdh, n, "")); attestReason(err) != "counter" {
			t.Errorf("counter %d after 5: %v", n, err)
		}
	}
	if err := as(d.assertion(t, cdh, 6, "")); err != nil {
		t.Fatal(err)
	}
	// Both evidence kinds, or neither.
	if err := v.Verify(context.Background(), req(d, cdh, map[string]any{"challenge": "c", "key_id": d.keyID(), "assertion": "AA==", "attestation": "AA=="})); attestReason(err) != "evidence" {
		t.Errorf("both: %v", err)
	}
	// The real Apple root is the default.
	if !strings.Contains(appleAppAttestRootPEM, "MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw") {
		t.Fatal("Apple root changed")
	}
}

func TestChallenges(t *testing.T) {
	c := newChallenges([]byte("k"))
	now := time.Unix(1_790_000_000, 0)
	ch, _, _ := c.issue(appA, now)
	if c.take(appB, ch, now) {
		t.Fatal("taken for another app")
	}
	if !c.take(appA, ch, now) || c.take(appA, ch, now) {
		t.Fatal("not taken exactly once")
	}
	ch, _, _ = c.issue(appA, now)
	if c.take(appA, ch, now.Add(challengeLife)) {
		t.Fatal("expired challenge taken")
	}
	raw, _ := base64.RawURLEncoding.DecodeString(ch)
	raw[3] ^= 1
	if c.take(appA, base64.RawURLEncoding.EncodeToString(raw), now) {
		t.Fatal("changed challenge taken")
	}
	if c2 := newChallenges([]byte("other")); c2.take(appA, ch, now) {
		t.Fatal("challenge from another key taken")
	}
}

// ---- Play Integrity ----

type verdict struct {
	hash, nonce, pkg, reqPkg, recog string
	certs                           []string
	device                          []string
	ts                              time.Time
}

func (v verdict) json() string {
	b, _ := json.Marshal(map[string]any{"tokenPayloadExternal": map[string]any{
		"requestDetails":  map[string]any{"requestPackageName": v.reqPkg, "requestHash": v.hash, "nonce": v.nonce, "timestampMillis": strconv.FormatInt(v.ts.UnixMilli(), 10)},
		"appIntegrity":    map[string]any{"appRecognitionVerdict": v.recog, "packageName": v.pkg, "certificateSha256Digest": v.certs, "versionCode": "42"},
		"deviceIntegrity": map[string]any{"deviceRecognitionVerdict": v.device},
		"accountDetails":  map[string]any{"appLicensingVerdict": "LICENSED"},
	}})
	return string(b)
}

func TestPlayIntegrity(t *testing.T) {
	g := newGatewayWith(t, attestedConfig())
	tok := fcmToken(1)
	digest := base64.RawURLEncoding.EncodeToString(certDigest[:])
	const piPath = "/pi/v1/io.example.alpha:decodeIntegrityToken"

	run := func(r devReq, edit func(*verdict, string), status int, body string) *devResp {
		t.Helper()
		ch := g.challenge(freshIP())
		good := verdict{hash: connectpush.AttestRequestHash(r.op, appA, r.platform, r.token, r.gen, ch), pkg: appA, reqPkg: appA,
			recog: "PLAY_RECOGNIZED", certs: []string{digest}, device: []string{"MEETS_BASIC_INTEGRITY", "MEETS_DEVICE_INTEGRITY"}, ts: g.clock.now().Add(-time.Minute)}
		if edit != nil {
			edit(&good, ch)
		}
		g.up.setReply(func(p string) (int, string) {
			if p != piPath {
				return 200, ""
			}
			if status != 0 {
				return status, body
			}
			return 200, good.json()
		})
		return g.attested(r, freshIP(), map[string]any{"challenge": ch, "token": "integrity-token-" + ch})
	}
	reg := devReq{"register", "fcm", tok, 1}
	run(reg, nil, 0, "").want(t, 200, "")
	req := g.up.find(piPath)[0]
	if !strings.Contains(string(req.body), `"integrity_token":"integrity-token-`) || req.header.Get("Authorization") != "Bearer ya29.test-access" {
		t.Fatalf("decode request %s %v", req.body, req.header)
	}
	scopes := ""
	for _, r := range g.up.find("/token") {
		scopes += string(r.body)
	}
	if !strings.Contains(scopes, "assertion=") {
		t.Fatal("no OAuth request")
	}

	for name, c := range map[string]struct {
		r      devReq
		edit   func(*verdict, string)
		status int
		code   string
	}{
		"classic nonce": {reg, func(v *verdict, _ string) { v.nonce, v.hash = v.hash+"=", "" }, 200, ""},
		"hash for other gen": {reg, func(v *verdict, ch string) {
			v.hash = connectpush.AttestRequestHash("register", appA, "fcm", tok, 2, ch)
		}, 401, "attestation_failed"},
		"hash for other op": {devReq{"revoke", "fcm", tok, 1}, func(v *verdict, ch string) {
			v.hash = connectpush.AttestRequestHash("register", appA, "fcm", tok, 1, ch)
		}, 401, "attestation_failed"},
		"hash for other token": {reg, func(v *verdict, ch string) {
			v.hash = connectpush.AttestRequestHash("register", appA, "fcm", fcmToken(2), 1, ch)
		}, 401, "attestation_failed"},
		"no hash":               {reg, func(v *verdict, _ string) { v.hash = "" }, 401, "attestation_failed"},
		"wrong package":         {reg, func(v *verdict, _ string) { v.pkg = "io.example.bravo" }, 401, "attestation_failed"},
		"wrong request package": {reg, func(v *verdict, _ string) { v.reqPkg = "io.example.bravo" }, 401, "attestation_failed"},
		"wrong certificate":     {reg, func(v *verdict, _ string) { v.certs = []string{base64.RawURLEncoding.EncodeToString(make([]byte, 32))} }, 401, "attestation_failed"},
		"extra certificate":     {reg, func(v *verdict, _ string) { v.certs = append(v.certs, "x") }, 401, "attestation_failed"},
		"no certificate":        {reg, func(v *verdict, _ string) { v.certs = nil }, 401, "attestation_failed"},
		"unrecognized app":      {reg, func(v *verdict, _ string) { v.recog = "UNRECOGNIZED_VERSION" }, 401, "attestation_failed"},
		"basic integrity only":  {reg, func(v *verdict, _ string) { v.device = []string{"MEETS_BASIC_INTEGRITY"} }, 401, "attestation_failed"},
		"no device verdict":     {reg, func(v *verdict, _ string) { v.device = nil }, 401, "attestation_failed"},
		"old":                   {reg, func(v *verdict, _ string) { v.ts = g.clock.now().Add(-piMaxAge - time.Second) }, 401, "attestation_failed"},
		"future":                {reg, func(v *verdict, _ string) { v.ts = g.clock.now().Add(piMaxSkew + time.Second) }, 401, "attestation_failed"},
	} {
		r := run(c.r, c.edit, 0, "")
		if r.code != c.status || c.code != "" && !strings.Contains(r.body, c.code) {
			t.Errorf("%s: %d %s", name, r.code, r.body)
		}
	}
	run(reg, nil, 400, `{"error":{"message":"upstream-secret-text"}}`).want(t, 401, "attestation_failed")
	r := run(reg, nil, 500, `upstream-secret-text`)
	r.want(t, 503, "attestation_unavailable")
	if strings.Contains(r.body, "upstream-secret") || strings.Contains(g.logs.String(), "upstream-secret") {
		t.Fatal("Google's text passed on")
	}
	// The evidence names no host: Google is the only place a token goes.
	evil := newCounter(t)
	ch := g.challenge(freshIP())
	g.up.setReply(nil)
	g.attested(reg, freshIP(), map[string]any{"challenge": ch, "token": evil.ts.URL}).want(t, 503, "")
	g.attested(reg, freshIP(), map[string]any{"challenge": g.challenge(freshIP()), "token": "x", "url": evil.ts.URL}).want(t, 401, "attestation_failed")
	if evil.n.Load() != 0 {
		t.Fatal("the gateway connected where the evidence said")
	}
}

func TestStrictModeNeverDialsPlayIntegrity(t *testing.T) {
	g := newGateway(t)
	g.register(appA, "fcm", fcmToken(1), 1, ipX)
	wantCode(t, g.post("/v1/challenge", ipX, map[string]string{"app": appA}), 400, "attest_not_configured")
	if g.up.total() != 0 {
		t.Fatalf("%d upstream requests in strict mode", g.up.total())
	}
}

func TestAttestConfigErrors(t *testing.T) {
	g := newGateway(t)
	for name, at := range map[string]string{
		"ios env":            `{"ios": {"env": "staging"}}`,
		"ios unknown field":  `{"ios": {"team": "x"}}`,
		"ios bad bundle":     `{"ios": {"bundle_id": "a b"}}`,
		"android no certs":   `{"android": {"package_name": "io.example.alpha"}}`,
		"android bad cert":   `{"android": {"package_name": "io.example.alpha", "certificate_sha256": ["abcd"]}}`,
		"android no package": `{"android": {"certificate_sha256": ["` + strings.Repeat("ab", 32) + `"]}}`,
		"android bad creds":  `{"android": {"package_name": "io.example.alpha", "certificate_sha256": ["` + strings.Repeat("ab", 32) + `"], "credentials_file": "none.json"}}`,
	} {
		cfgText := strings.Replace(baseConfig, `"id": "io.example.alpha",`, `"id": "io.example.alpha", "attest": `+at+`,`, 1)
		cfg, err := parseConfig([]byte(cfgText), g.dir)
		if err != nil {
			continue // refused already
		}
		if _, err := loadApps(cfg, g.upstream(), g.srv.gens, func(string, ...any) {}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A good one loads, with the defaults from apns.
	cfg, err := parseConfig([]byte(attestedConfig()), g.dir)
	if err != nil {
		t.Fatal(err)
	}
	apps, err := loadApps(cfg, g.upstream(), g.srv.gens, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	if v := apps[appA].attest[platAPNs].(*appAttest); v.rpIDHash != sha256.Sum256([]byte("TEAM123456.io.example.alpha")) || v.aaguid != aaguidDevelopment {
		t.Fatal("App Attest defaults")
	}
}

// An App Attest key belongs to the app that attested it: another app on the same gateway cannot
// use it, even with a higher counter.
func TestAttestKeyIsTheAppsOwn(t *testing.T) {
	g, err := loadGenStore(t.TempDir() + "/state.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := g.addAttestKey("key1", attestKey{App: "herdr", Pub: "x", Counter: 1}); err != nil {
		t.Fatal(err)
	}
	if err := g.useAttestKey("key1", "boop", 2, time.Now()); !errors.Is(err, errAttestUnknown) {
		t.Fatalf("another app's key: %v, want errAttestUnknown", err)
	}
	if err := g.useAttestKey("key1", "herdr", 2, time.Now()); err != nil {
		t.Fatalf("own key: %v", err)
	}
}

// An attested app's register_per_hour still counts requests whose evidence passed.
func TestAttestedAppKeepsItsHourlyBudget(t *testing.T) {
	root := newCA(t, "root", nil)
	inter := newCA(t, "inter", root)
	trustCA(t, root)
	g := newGatewayWith(t, strings.Replace(attestedConfig(), `"id": "io.example.alpha",`, `"id": "io.example.alpha", "register_per_hour": 2,`, 1))
	for i := 0; i < 3; i++ {
		d := newDevice(inter)
		reg := devReq{"register", "apns", apnsToken(1 + i), 1}
		ch := g.challenge(freshIP())
		ev := map[string]any{"challenge": ch, "key_id": d.keyID(), "attestation": d.attestation(t, reg.hash(ch), attOpts{})}
		if i < 2 {
			g.attested(reg, freshIP(), ev).want(t, 200, "")
		} else {
			g.attested(reg, freshIP(), ev).want(t, 429, "rate_limited")
		}
	}
}

// Play Integrity decodes are capped per app (decode_per_hour): over the cap the gateway answers
// 503 attestation_unavailable without calling Google, so made-up tokens cannot use up the
// project's quota.
func TestPlayIntegrityDecodeBudget(t *testing.T) {
	cfg := strings.Replace(attestedConfig(), `"package_name": "io.example.alpha",`, `"package_name": "io.example.alpha", "decode_per_hour": 2,`, 1)
	if cfg == attestedConfig() {
		t.Fatal("config not edited")
	}
	g := newGatewayWith(t, cfg)
	const piPath = "/pi/v1/io.example.alpha:decodeIntegrityToken"
	g.up.setReply(func(p string) (int, string) { return 400, `{"error":{}}` })
	for i := 0; i < 3; i++ {
		ch := g.challenge(freshIP())
		r := g.attested(devReq{"register", "fcm", fcmToken(10 + i), 1}, freshIP(), map[string]any{"challenge": ch, "token": "made-up-" + ch})
		if i < 2 {
			r.want(t, 401, "attestation_failed")
		} else {
			r.want(t, 503, "attestation_unavailable")
		}
	}
	if n := len(g.up.find(piPath)); n != 2 {
		t.Fatalf("%d decode calls, want 2", n)
	}
}

// An unknown App Attest key says nothing about the source: it frees its slot, so after more than
// attestFailLimit of them the same source still registers.
func TestUnknownAttestKeysDoNotBlockTheSource(t *testing.T) {
	root := newCA(t, "root", nil)
	inter := newCA(t, "inter", root)
	trustCA(t, root)
	g := newGatewayWith(t, attestedConfig())
	ip := freshIP()
	for i := 0; i < attestFailLimit+1; i++ {
		r := devReq{"register", "apns", apnsToken(600 + i), 1}
		other := newDevice(inter)
		ch := g.challenge(ip)
		g.attested(r, ip, map[string]any{"challenge": ch, "key_id": other.keyID(), "assertion": other.assertion(t, r.hash(ch), 1, "")}).
			want(t, 401, "attest_key_unknown")
	}
	d := newDevice(inter)
	reg := devReq{"register", "apns", apnsToken(1), 1}
	ch := g.challenge(ip)
	g.attested(reg, ip, map[string]any{"challenge": ch, "key_id": d.keyID(), "attestation": d.attestation(t, reg.hash(ch), attOpts{})}).want(t, 200, "")
}
