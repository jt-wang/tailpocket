package main

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

func decodeJWT(t *testing.T, jwt string) (signed string, hdr, claims map[string]any, sig []byte) {
	t.Helper()
	p := strings.Split(jwt, ".")
	if len(p) != 3 {
		t.Fatalf("JWT %q has %d parts", jwt, len(p))
	}
	for i, dst := range []*map[string]any{&hdr, &claims} {
		b, err := base64.RawURLEncoding.DecodeString(p[i])
		if err != nil || json.Unmarshal(b, dst) != nil {
			t.Fatalf("JWT part %d: %v", i, err)
		}
	}
	sig, err := base64.RawURLEncoding.DecodeString(p[2])
	if err != nil {
		t.Fatal(err)
	}
	return p[0] + "." + p[1], hdr, claims, sig
}

func TestAPNsPushCarriesOnlyPlaceholderAndCiphertext(t *testing.T) {
	g := newGateway(t)
	tok := apnsToken(1)
	h := g.register(appA, "apns", tok, 1, ipX)
	ct := g.ct(appA, 1)
	wantCode(t, g.send(h, ct, ipY, map[string]any{"collapse": "thread.1", "priority": "normal"}), http.StatusAccepted, "")
	wantCode(t, g.send(h, g.ct(appA, 2), ipY, nil), http.StatusAccepted, "")

	p := g.up.pushes()
	if len(p) != 2 {
		t.Fatalf("%d pushes, want 2", len(p))
	}
	r := p[0]
	if r.proto != 2 || r.method != http.MethodPost || r.path != "/sandbox/3/device/"+tok {
		t.Fatalf("APNs request HTTP/%d %s %s", r.proto, r.method, r.path)
	}
	for k, v := range map[string]string{
		"Apns-Topic": appA, "Apns-Push-Type": "alert", "Apns-Priority": "5", "Apns-Collapse-Id": "thread.1",
		"Content-Type": "application/json",
	} {
		if got := r.header.Get(k); got != v {
			t.Errorf("header %s = %q, want %q", k, got, v)
		}
	}
	if p[1].header.Get("Apns-Priority") != "10" || p[1].header.Get("Apns-Collapse-Id") != "" {
		t.Errorf("default push: priority %q collapse %q", p[1].header.Get("Apns-Priority"), p[1].header.Get("Apns-Collapse-Id"))
	}

	// The body is exactly the placeholder from the config and ct.
	var body map[string]any
	if err := json.Unmarshal(r.body, &body); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"aps": map[string]any{
			"alert":           map[string]any{"title": "Alpha", "body": "New activity"},
			"mutable-content": 1.0,
			"sound":           "default",
		},
		"tp": ct,
	}
	if !reflect.DeepEqual(body, want) {
		t.Fatalf("APNs payload\n%s\nwant\n%v", r.body, want)
	}
	for _, s := range []string{"SECRET", "evil.example"} {
		for _, q := range p {
			if strings.Contains(string(q.body), s) || strings.Contains(fmt.Sprint(q.header), s) {
				t.Fatalf("push carries %q in clear", s)
			}
		}
	}

	// ES256 provider token from the .p8, reused for the second push.
	auth := r.header.Get("Authorization")
	if !strings.HasPrefix(auth, "bearer ") || p[1].header.Get("Authorization") != auth {
		t.Fatalf("authorization %q then %q", auth, p[1].header.Get("Authorization"))
	}
	signed, hdr, claims, sig := decodeJWT(t, strings.TrimPrefix(auth, "bearer "))
	d := sha256.Sum256([]byte(signed))
	if len(sig) != 64 || !ecdsa.Verify(&ecKey.PublicKey, d[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("APNs JWT signature does not verify")
	}
	if hdr["alg"] != "ES256" || hdr["kid"] != "KEY1234567" || claims["iss"] != "TEAM123456" || claims["iat"] != float64(g.clock.now().Unix()) {
		t.Fatalf("APNs JWT %v %v", hdr, claims)
	}
	// Made again after 50 minutes.
	g.clock.advance(51 * time.Minute)
	wantCode(t, g.send(h, g.ct(appA, 3), ipY, nil), http.StatusAccepted, "")
	if p := g.up.pushes(); p[2].header.Get("Authorization") == auth {
		t.Fatal("APNs JWT not renewed after 51 minutes")
	}

	// App B goes to its own topic and the production host.
	hb := g.register(appB, "apns", apnsToken(2), 1, ipX)
	wantCode(t, g.send(hb, g.ct(appB, 1), ipY, nil), http.StatusAccepted, "")
	p = g.up.pushes()
	last := p[len(p)-1]
	if last.path != "/prod/3/device/"+apnsToken(2) || last.header.Get("Apns-Topic") != "io.example.bravo.app" {
		t.Fatalf("app B push %s topic %q", last.path, last.header.Get("Apns-Topic"))
	}
	if !strings.Contains(string(last.body), `"title":"Bravo"`) {
		t.Fatalf("app B placeholder: %s", last.body)
	}
	if !strings.Contains(g.logs.String(), "handle="+handleHash(h)) {
		t.Fatalf("log does not name the handle by its hash:\n%s", g.logs)
	}
}

func TestFCMPushIsDataOnly(t *testing.T) {
	g := newGateway(t)
	tok := fcmToken(1)
	h := g.register(appA, "fcm", tok, 1, ipX)
	ct := g.ct(appA, 1)
	wantCode(t, g.send(h, ct, ipY, map[string]any{"collapse": "c-1"}), http.StatusAccepted, "")
	wantCode(t, g.send(h, g.ct(appA, 2), ipY, map[string]any{"priority": "normal"}), http.StatusAccepted, "")

	if n := g.up.count("/token"); n != 1 {
		t.Fatalf("%d OAuth token requests for two pushes, want 1", n)
	}
	oauth := g.up.find("/token")[0]
	form, _ := url.ParseQuery(string(oauth.body))
	if form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		t.Fatalf("grant_type %q", form.Get("grant_type"))
	}
	signed, hdr, claims, sig := decodeJWT(t, form.Get("assertion"))
	d := sha256.Sum256([]byte(signed))
	if err := rsa.VerifyPKCS1v15(&rsaKey.PublicKey, crypto.SHA256, d[:], sig); err != nil {
		t.Fatalf("OAuth JWT: %v", err)
	}
	if hdr["alg"] != "RS256" || hdr["kid"] != "abc123" || claims["iss"] != "push@alpha-proj.iam.gserviceaccount.com" ||
		claims["aud"] != "https://oauth2.googleapis.com/token" || claims["scope"] != fcmScope {
		t.Fatalf("OAuth JWT %v %v", hdr, claims)
	}

	p := g.up.pushes()
	if len(p) != 2 || p[0].path != "/v1/projects/alpha-proj/messages:send" || p[0].header.Get("Authorization") != "Bearer ya29.test-access" {
		t.Fatalf("FCM requests %+v", p)
	}
	var m map[string]any
	if err := json.Unmarshal(p[0].body, &m); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"message": map[string]any{
		"token":   tok,
		"data":    map[string]any{"tp": ct},
		"android": map[string]any{"priority": "high", "collapse_key": "c-1", "ttl": "86400s"},
	}}
	if !reflect.DeepEqual(m, want) {
		t.Fatalf("FCM message\n%s\nwant %v", p[0].body, want)
	}
	if !strings.Contains(string(p[1].body), `"priority":"normal"`) || strings.Contains(string(p[1].body), "collapse_key") {
		t.Fatalf("second FCM message %s", p[1].body)
	}
}

func TestBadHandlesGet403AndNoUpstreamRequest(t *testing.T) {
	g := newGateway(t)
	h := g.register(appA, "apns", apnsToken(1), 1, ipX)
	ct := g.ct(appA, 1)
	raw, _ := base64.RawURLEncoding.DecodeString(h)

	var bad []string
	for i := range raw {
		b := append([]byte(nil), raw...)
		b[i] ^= 0x01
		bad = append(bad, base64.RawURLEncoding.EncodeToString(b))
	}
	ver := append([]byte(nil), raw...)
	ver[0] = 2
	kid := append([]byte(nil), raw...)
	kid[1] = 9 // a key id the gateway does not have
	bad = append(bad,
		base64.RawURLEncoding.EncodeToString(ver),
		base64.RawURLEncoding.EncodeToString(kid),
		h[:len(h)-1], h+"A", h[:20]+"\n"+h[20:], h+"=", "", "x",
		base64.RawURLEncoding.EncodeToString(make([]byte, 120)),
		strings.Repeat("A", 3000),
	)
	for i, b := range bad {
		wantCode(t, g.send(b, ct, ipY, nil), http.StatusForbidden, "forbidden")
		if g.up.total() != 0 {
			t.Fatalf("bad handle %d reached upstream", i)
		}
	}
	// A handle that opens still works, so the 403s were about the handle.
	wantCode(t, g.send(h, ct, ipY, nil), http.StatusAccepted, "")
}

func TestHandleIsBoundToItsApp(t *testing.T) {
	g := newGateway(t)
	h := g.register(appA, "apns", apnsToken(1), 1, ipX)
	raw, _ := base64.RawURLEncoding.DecodeString(h)
	if string(raw[3:3+len(appA)]) != appA {
		t.Fatalf("handle header does not start with the app id")
	}
	asB := append([]byte(nil), raw...)
	copy(asB[3:], appB)
	ct := g.ct(appB, 1)
	wantCode(t, g.send(base64.RawURLEncoding.EncodeToString(asB), ct, ipY, nil), http.StatusForbidden, "forbidden")

	// A shorter app id with the same sealed part after it.
	short := append([]byte{raw[0], raw[1], byte(len("io.x"))}, "io.x"...)
	short = append(short, raw[3+len(appA):]...)
	wantCode(t, g.send(base64.RawURLEncoding.EncodeToString(short), ct, ipY, nil), http.StatusForbidden, "forbidden")

	// The request cannot name the app: send takes no app field.
	wantCode(t, g.send(h, ct, ipY, map[string]any{"app": appB}), http.StatusBadRequest, "bad_request")
	if g.up.total() != 0 {
		t.Fatalf("%d upstream requests", g.up.total())
	}

	// An app taken out of the config: its handles stop working.
	g.srv = g.build(strings.Replace(baseConfig, `"id": "io.example.alpha"`, `"id": "io.example.other"`, 1))
	wantCode(t, g.send(h, g.ct(appA, 2), ipY, nil), http.StatusForbidden, "not_configured")
	if g.up.total() != 0 {
		t.Fatalf("%d upstream requests", g.up.total())
	}
}

func TestHandleExpires(t *testing.T) {
	g := newGateway(t)
	h := g.register(appA, "apns", apnsToken(1), 1, ipX)
	g.clock.advance(maxHandleTTL - time.Second)
	wantCode(t, g.send(h, g.ct(appA, 1), ipY, nil), http.StatusAccepted, "")
	g.clock.advance(time.Second)
	wantCode(t, g.send(h, g.ct(appA, 2), ipY, nil), http.StatusForbidden, "expired")
	if n := len(g.up.pushes()); n != 1 {
		t.Fatalf("%d pushes", n)
	}

	g2 := newGatewayWith(t, strings.Replace(baseConfig, `"state_file"`, `"handle_ttl_days": 1, "state_file"`, 1))
	h2 := g2.register(appA, "apns", apnsToken(1), 1, ipX)
	g2.clock.advance(24 * time.Hour)
	wantCode(t, g2.send(h2, g2.ct(appA, 1), ipY, nil), http.StatusForbidden, "expired")
	if g2.up.total() != 0 {
		t.Fatal("expired handle reached upstream")
	}
}

func TestGenerationsAndRevoke(t *testing.T) {
	g := newGateway(t)
	tok := apnsToken(1)
	dev := func(gen uint64) map[string]any {
		return map[string]any{"app": appA, "platform": "apns", "token": tok, "generation": gen}
	}
	h1 := g.register(appA, "apns", tok, 1, ipX)
	h2 := g.register(appA, "apns", tok, 2, ipX)
	wantCode(t, g.send(h1, g.ct(appA, 1), ipY, nil), http.StatusForbidden, "revoked")
	wantCode(t, g.send(h2, g.ct(appA, 2), ipY, nil), http.StatusAccepted, "")

	// The computer was removed: the phone revokes generation 2.
	if w := g.post("/v1/revoke", ipX, dev(2)); w.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", w.Code, w.Body)
	}
	wantCode(t, g.send(h2, g.ct(appA, 3), ipY, nil), http.StatusForbidden, "revoked")
	w := g.post("/v1/register", ipX, dev(2))
	wantCode(t, w, http.StatusConflict, "stale_generation")
	if !strings.Contains(w.Body.String(), `"min_generation":3`) {
		t.Fatalf("409 body %s", w.Body)
	}
	h3 := g.register(appA, "apns", tok, 3, ipX)

	// The state outlives a restart.
	g.srv = g.build(baseConfig)
	wantCode(t, g.send(h2, g.ct(appA, 4), ipY, nil), http.StatusForbidden, "revoked")
	wantCode(t, g.send(h3, g.ct(appA, 5), ipY, nil), http.StatusAccepted, "")
	if n := len(g.up.pushes()); n != 2 {
		t.Fatalf("%d pushes, want 2", n)
	}

	// Another token, or the same token for another app, is not affected.
	ho := g.register(appA, "apns", apnsToken(2), 1, ipX)
	hb := g.register(appB, "apns", tok, 1, ipX)
	wantCode(t, g.send(ho, g.ct(appA, 6), ipY, nil), http.StatusAccepted, "")
	wantCode(t, g.send(hb, g.ct(appB, 1), ipY, nil), http.StatusAccepted, "")

	for _, gen := range []any{0, -1, 1 << 53, "2", 1.5} {
		wantCode(t, g.post("/v1/revoke", ipZ, map[string]any{"app": appA, "platform": "apns", "token": tok, "generation": gen}), http.StatusBadRequest, "")
	}
	// Revoke checks the token like register does.
	wantCode(t, g.post("/v1/revoke", ipZ, map[string]any{"app": appA, "platform": "apns", "token": "zz", "generation": 5}), http.StatusBadRequest, "bad_token")
}

func TestRateLimitPerDevice(t *testing.T) {
	const perMin, perDay = 10, 300 // the limits as specified, not read from the code
	g := newGateway(t)
	tok := apnsToken(1)
	h := g.register(appA, "apns", tok, 1, ipX)
	ct := g.ct(appA, 1)
	for i := 0; i < perMin; i++ {
		wantCode(t, g.send(h, ct, ipY, nil), http.StatusAccepted, "")
	}
	w := g.send(h, ct, ipY, nil)
	wantCode(t, w, http.StatusTooManyRequests, "rate_limited")
	if w.Header().Get("Retry-After") == "" {
		t.Error("429 without Retry-After")
	}
	// Another handle for the same token shares the limit; another token does not.
	h2 := g.register(appA, "apns", tok, 1, ipZ)
	wantCode(t, g.send(h2, ct, ipZ, nil), http.StatusTooManyRequests, "rate_limited")
	wantCode(t, g.send(g.register(appA, "apns", apnsToken(2), 1, ipX), ct, ipY, nil), http.StatusAccepted, "")
	if n := len(g.up.pushes()); n != perMin+1 {
		t.Fatalf("%d pushes, want %d", n, perMin+1)
	}

	// Per day: keep sending a minute and a bit apart until the day is full.
	sent := perMin
	for step := 0; sent < perDay && step < 100; step++ {
		g.clock.advance(71 * time.Second)
		for i := 0; i < perMin; i++ {
			if g.send(h, ct, ipY, nil).Code == http.StatusAccepted {
				sent++
			}
		}
	}
	if sent != perDay {
		t.Fatalf("sent %d in the day, want %d", sent, perDay)
	}
	g.clock.advance(71 * time.Second)
	wantCode(t, g.send(h, ct, ipY, nil), http.StatusTooManyRequests, "rate_limited")
	if n := len(g.up.pushes()); n != perDay+1 {
		t.Fatalf("%d pushes, want %d", n, perDay+1)
	}
	g.clock.advance(26 * time.Hour)
	wantCode(t, g.send(h, ct, ipY, nil), http.StatusAccepted, "")
}

func TestRateLimitPerSourceAddress(t *testing.T) {
	g := newGateway(t)
	for i := 0; i < 600; i++ {
		wantCode(t, g.send("bogus", "x", "[2001:db8::1]:1", nil), http.StatusForbidden, "")
	}
	// Same /64, and register counts too.
	wantCode(t, g.send("bogus", "x", "[2001:db8::2]:1", nil), http.StatusTooManyRequests, "rate_limited")
	wantCode(t, g.post("/v1/register", "[2001:db8::3]:1", map[string]any{"app": appA, "platform": "apns", "token": apnsToken(1), "generation": 1}),
		http.StatusTooManyRequests, "rate_limited")
	// Another /64 and an IPv4 address are separate.
	wantCode(t, g.send("bogus", "x", "[2001:db8:0:1::1]:1", nil), http.StatusForbidden, "")
	wantCode(t, g.send("bogus", "x", ipX, nil), http.StatusForbidden, "")
	g.clock.advance(71 * time.Second)
	wantCode(t, g.send("bogus", "x", "[2001:db8::1]:1", nil), http.StatusForbidden, "")
}

func TestRegisterLimits(t *testing.T) {
	g := newGateway(t)
	for i := 0; i < 20; i++ { // the specified limit
		g.register(appA, "apns", apnsToken(i), 1, ipX)
	}
	dev := map[string]any{"app": appA, "platform": "apns", "token": apnsToken(99), "generation": 1}
	wantCode(t, g.post("/v1/register", ipX, dev), http.StatusTooManyRequests, "rate_limited")
	wantCode(t, g.post("/v1/revoke", ipX, dev), http.StatusTooManyRequests, "rate_limited")
	g.register(appA, "apns", apnsToken(99), 1, ipY)
	g.clock.advance(71 * time.Minute)
	g.register(appA, "apns", apnsToken(100), 1, ipX)

	// Per app, whatever the source.
	g2 := newGatewayWith(t, strings.Replace(baseConfig, `"id": "io.example.bravo",`, `"id": "io.example.bravo", "register_per_hour": 3,`, 1))
	for i := 0; i < 3; i++ {
		g2.register(appB, "apns", apnsToken(i), 1, fmt.Sprintf("192.0.2.%d:1", i+1))
	}
	wantCode(t, g2.post("/v1/register", "192.0.2.100:1", map[string]any{"app": appB, "platform": "apns", "token": apnsToken(9), "generation": 1}),
		http.StatusTooManyRequests, "rate_limited")
	g2.register(appA, "apns", apnsToken(9), 1, "192.0.2.100:1")
}

func TestGoneIsPassedOnWithoutUpstreamText(t *testing.T) {
	g := newGateway(t)
	cases := []struct {
		platform string
		code     int
		body     string
		want     int
	}{
		{"apns", 410, `{"reason":"Unregistered","timestamp":1}`, 410},
		{"apns", 400, `{"reason":"BadDeviceToken"}`, 410},
		{"apns", 400, `{"reason":"Unregistered"}`, 410},
		{"apns", 400, `{"reason":"BadTopic"}`, 502},
		{"apns", 500, `upstream-secret-text <script>`, 502},
		{"apns", 403, `{"reason":"ExpiredProviderToken"}`, 502},
		{"fcm", 404, `{"error":{"status":"NOT_FOUND","message":"upstream-secret-text"}}`, 410},
		{"fcm", 400, `{"error":{"status":"INVALID_ARGUMENT","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"UNREGISTERED"}]}}`, 410},
		{"fcm", 400, `{"error":{"status":"INVALID_ARGUMENT","message":"upstream-secret-text"}}`, 502},
		{"fcm", 503, `upstream-secret-text`, 502},
	}
	for i, c := range cases {
		tok := apnsToken(i)
		if c.platform == "fcm" {
			tok = fcmToken(i)
		}
		h := g.register(appA, c.platform, tok, 1, ipZ)
		g.up.setReply(func(string) (int, string) { return c.code, c.body })
		w := g.send(h, g.ct(appA, 1), fmt.Sprintf("10.0.0.%d:1", i), nil) // a fresh source each, so none is blocked
		want := `{"error":"gone"}` + "\n"
		if c.want == 502 {
			want = `{"error":"upstream_failed"}` + "\n"
		}
		if w.Code != c.want || w.Body.String() != want {
			t.Fatalf("case %d (%s %d %s): %d %q", i, c.platform, c.code, c.body, w.Code, w.Body)
		}
	}
	if strings.Contains(g.logs.String(), "upstream-secret-text") {
		t.Fatal("upstream text in the log")
	}
	// ExpiredProviderToken dropped the cached APNs JWT.
	g.up.setReply(nil)
	before := g.up.find("/sandbox/3/device/" + apnsToken(5))[0].header.Get("Authorization")
	wantCode(t, g.send(g.register(appA, "apns", apnsToken(50), 1, ipZ), g.ct(appA, 1), ipY, nil), http.StatusAccepted, "")
	p := g.up.pushes()
	if p[len(p)-1].header.Get("Authorization") == before {
		t.Fatal("APNs JWT kept after ExpiredProviderToken")
	}
}

func TestSourcesWithMostlyBadTokensAreBlocked(t *testing.T) {
	g := newGateway(t)
	var hs []string
	for i := 0; i < badMinResults+1; i++ {
		hs = append(hs, g.register(appA, "apns", apnsToken(i), 1, ipX))
	}
	g.up.setReply(func(string) (int, string) { return 400, `{"reason":"BadDeviceToken"}` })
	for i := 0; i < badMinResults; i++ {
		wantCode(t, g.send(hs[i], g.ct(appA, 1), ipY, nil), http.StatusGone, "gone")
	}
	pushes := len(g.up.pushes())
	// The sender and the source that registered are blocked, and so is
	// every handle that source registered, from anywhere.
	wantCode(t, g.send(hs[badMinResults], g.ct(appA, 1), ipY, nil), http.StatusTooManyRequests, "blocked")
	wantCode(t, g.post("/v1/register", ipX, map[string]any{"app": appA, "platform": "apns", "token": apnsToken(77), "generation": 1}),
		http.StatusTooManyRequests, "blocked")
	wantCode(t, g.send(hs[badMinResults], g.ct(appA, 1), ipZ, nil), http.StatusTooManyRequests, "blocked")
	if n := len(g.up.pushes()); n != pushes {
		t.Fatalf("blocked sources made %d more pushes", n-pushes)
	}
	g.register(appA, "apns", apnsToken(78), 1, ipZ)

	g.clock.advance(badBlock + time.Minute)
	g.up.setReply(nil)
	wantCode(t, g.send(hs[badMinResults], g.ct(appA, 1), ipY, nil), http.StatusAccepted, "")

	// Half bad is not more than half: no block.
	g2 := newGateway(t)
	g2.up.setReply(func(p string) (int, string) {
		if strings.HasSuffix(p, "1") { // odd pushes: never more than half bad
			return 410, `{"reason":"Unregistered"}`
		}
		return 200, ""
	})
	for i := 0; i < 2*badMinResults; i++ {
		tok := fmt.Sprintf("%063x%d", 0xb000+i, i%2) // last digit decides the answer
		h := g2.register(appA, "apns", tok, 1, ipX)
		want := http.StatusAccepted
		if i%2 == 1 {
			want = http.StatusGone
		}
		if w := g2.send(h, g2.ct(appA, 1), ipY, nil); w.Code != want {
			t.Fatalf("push %d: %d %s", i, w.Code, w.Body)
		}
	}
}

func TestRequestCannotChooseWhereTheGatewayConnects(t *testing.T) {
	g := newGateway(t)
	evil := newCounter(t)
	host := strings.TrimPrefix(evil.ts.URL, "http://")
	tok := apnsToken(1)
	h := g.register(appA, "apns", tok, 1, ipX)
	ct := g.ct(appA, 1)

	for i, body := range []map[string]any{
		{"app": appA, "platform": "apns", "token": evil.ts.URL, "generation": 1},
		{"app": appA, "platform": evil.ts.URL, "token": tok, "generation": 1},
		{"app": evil.ts.URL, "platform": "apns", "token": tok, "generation": 1},
		{"app": appA, "platform": "fcm", "token": evil.ts.URL + "/x", "generation": 1},
		{"app": appA, "platform": "apns", "token": tok, "generation": 1, "url": evil.ts.URL},
		{"app": appA, "platform": "apns", "token": tok, "generation": 1, "host": host},
	} {
		if w := g.post("/v1/register", ipZ, body); w.Code != http.StatusBadRequest {
			t.Fatalf("register %d: %d %s", i, w.Code, w.Body)
		}
	}
	for i, extra := range []map[string]any{
		{"url": evil.ts.URL},
		{"host": host},
		{"endpoint": evil.ts.URL},
		{"collapse": evil.ts.URL},
		{"collapse": "a\r\nHost: " + host},
		{"collapse": strings.Repeat("a", 65)},
		{"priority": evil.ts.URL},
		{"priority": ""},
		{"title": "visible"},
		{"body": "visible"},
	} {
		if w := g.send(h, ct, ipY, extra); w.Code != http.StatusBadRequest {
			t.Fatalf("send %d %v: %d %s", i, extra, w.Code, w.Body)
		}
	}
	wantCode(t, g.send(evil.ts.URL, ct, ipY, nil), http.StatusForbidden, "forbidden")
	wantCode(t, g.send(h, base64.RawURLEncoding.EncodeToString([]byte(evil.ts.URL)), ipY, nil), http.StatusBadRequest, "bad_ct")

	// Host and forwarding headers change nothing.
	b, _ := json.Marshal(map[string]any{"handle": h, "ct": ct})
	r := httptest.NewRequest(http.MethodPost, "/v1/send", strings.NewReader(string(b)))
	r.RemoteAddr = ipY
	r.Host = host
	for _, k := range []string{"X-Forwarded-Host", "X-Forwarded-For", "Forwarded", "X-Original-URL"} {
		r.Header.Set(k, host)
	}
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	g.srv.ServeHTTP(w, r)
	wantCode(t, w, http.StatusAccepted, "")

	p := g.up.pushes()
	if len(p) != 1 || p[0].path != "/sandbox/3/device/"+tok || p[0].host != strings.TrimPrefix(g.up.ts.URL, "https://") {
		t.Fatalf("pushes %+v", p)
	}
	if evil.n.Load() != 0 {
		t.Fatalf("the attacker's server got %d requests", evil.n.Load())
	}
}

func TestNotAProxy(t *testing.T) {
	g := newGateway(t)
	evil := newCounter(t)
	host := strings.TrimPrefix(evil.ts.URL, "http://")
	h := g.register(appA, "apns", apnsToken(1), 1, ipX)
	body, _ := json.Marshal(map[string]any{"handle": h, "ct": g.ct(appA, 1)})

	ts := httptest.NewUnstartedServer(g.srv)
	ts.Config.DisableGeneralOptionsHandler = true // as main.go sets it
	ts.Start()
	defer ts.Close()
	for _, raw := range []string{
		"CONNECT " + host + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n",
		"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"GET " + evil.ts.URL + "/healthz HTTP/1.1\r\nHost: " + host + "\r\n\r\n",
		fmt.Sprintf("POST %s/v1/send HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", evil.ts.URL, host, len(body), body),
		"OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n",
		// CONNECT with a path target, which Go parses like a normal request.
		fmt.Sprintf("CONNECT /v1/send HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body),
	} {
		c, err := net.Dial("tcp", strings.TrimPrefix(ts.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write([]byte(raw)); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		c.Close()
		if err != nil {
			t.Fatalf("%q: %v", raw[:20], err)
		}
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%q: %d, want 400", raw[:30], resp.StatusCode)
		}
	}
	if evil.n.Load() != 0 || g.up.total() != 0 {
		t.Fatalf("proxy requests reached the attacker (%d) or upstream (%d)", evil.n.Load(), g.up.total())
	}
}

func TestRoutesAndLimits(t *testing.T) {
	g := newGateway(t)
	for _, c := range []struct {
		method, path string
		want         int
	}{
		{"GET", "/healthz", 200},
		{"HEAD", "/healthz", 200},
		{"POST", "/healthz", 405},
		{"GET", "/v1/send", 405},
		{"PUT", "/v1/register", 405},
		{"DELETE", "/v1/revoke", 405},
		{"GET", "/", 404},
		{"POST", "/v1/send/", 404},
		{"POST", "/v1/sendx", 404},
		{"POST", "/V1/send", 404},
		{"GET", "/debug/pprof/", 404},
	} {
		if w := g.req(c.method, c.path, ipX, nil); w.Code != c.want {
			t.Errorf("%s %s: %d, want %d", c.method, c.path, w.Code, c.want)
		}
	}
	if w := g.req("GET", "/healthz", ipX, nil); w.Body.String() != "ok\n" {
		t.Errorf("healthz body %q", w.Body)
	}

	h := g.register(appA, "apns", apnsToken(1), 1, ipX)
	wantCode(t, g.send(h, strings.Repeat("A", 3001), ipY, nil), http.StatusRequestEntityTooLarge, "too_large")
	wantCode(t, g.send(h, "not base64!", ipY, nil), http.StatusBadRequest, "bad_ct")
	wantCode(t, g.post("/v1/send", ipY, `{"handle":"`+h+`","ct":"`+strings.Repeat("A", 9000)+`"}`), http.StatusRequestEntityTooLarge, "too_large")
	wantCode(t, g.post("/v1/send", ipY, `{"handle":"`+h+`"} {}`), http.StatusBadRequest, "bad_request")
	wantCode(t, g.post("/v1/send", ipY, `[`), http.StatusBadRequest, "bad_request")

	r := httptest.NewRequest("POST", "/v1/send", strings.NewReader(`{}`))
	r.RemoteAddr = ipY
	r.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	g.srv.ServeHTTP(w, r)
	wantCode(t, w, http.StatusUnsupportedMediaType, "")

	for _, c := range []struct {
		body map[string]any
		code string
	}{
		{map[string]any{"app": "io.unknown", "platform": "apns", "token": apnsToken(1), "generation": 1}, "unknown_app"},
		{map[string]any{"app": appB, "platform": "fcm", "token": fcmToken(1), "generation": 1}, "platform_not_configured"},
		{map[string]any{"app": appA, "platform": "apns", "token": "abc", "generation": 1}, "bad_token"},
		{map[string]any{"app": appA, "platform": "apns", "token": strings.Repeat("g", 64), "generation": 1}, "bad_token"},
		{map[string]any{"app": appA, "platform": "apns", "token": strings.Repeat("ab", 201), "generation": 1}, "bad_token"},
		{map[string]any{"app": appA, "platform": "fcm", "token": strings.Repeat("a", 1025), "generation": 1}, "bad_token"},
		{map[string]any{"app": appA, "platform": "fcm", "token": strings.Repeat("a", 40) + "/", "generation": 1}, "bad_token"},
		{map[string]any{"app": appA, "platform": "apns", "token": apnsToken(1)}, "bad_generation"},
	} {
		wantCode(t, g.post("/v1/register", ipZ, c.body), http.StatusBadRequest, c.code)
	}
	if g.up.total() != 0 {
		t.Fatalf("%d upstream requests", g.up.total())
	}
}

func TestHandleSealing(t *testing.T) {
	g := newGateway(t)
	cfg, _ := parseConfig([]byte(baseConfig), g.dir)
	k, err := loadHandleKeys(cfg, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := hex.DecodeString(apnsToken(1))
	in := handle{app: appA, plat: platAPNs, issued: 100, expires: 200, gen: 7, src: srcTag{1, 2}, token: tok}
	s, err := k.seal(in)
	if err != nil {
		t.Fatal(err)
	}
	out, ok := k.open(s)
	if !ok || !reflect.DeepEqual(out, in) {
		t.Fatalf("open gave %+v %v", out, ok)
	}
	if s2, _ := k.seal(in); s2 == s {
		t.Fatal("two handles for one token are the same")
	}
	if strings.Contains(s, apnsToken(1)) || strings.Contains(string(mustB64(t, s)), string(tok)) {
		t.Fatal("handle holds the token in clear")
	}

	// A handle of another version does not open, even when properly sealed
	// with that version in its associated data.
	raw := mustB64(t, s)
	n := int(raw[2])
	inner, err := k.aeads[1].Open(nil, raw[3+n:3+n+handleNonce], raw[3+n+handleNonce:], handleAAD(raw[:3+n]))
	if err != nil {
		t.Fatal(err)
	}
	v2 := append([]byte(nil), raw[:3+n+handleNonce]...)
	v2[0] = 2
	v2 = k.aeads[1].Seal(v2, v2[3+n:3+n+handleNonce], inner, handleAAD(v2[:3+n]))
	if _, ok := k.open(base64.RawURLEncoding.EncodeToString(v2)); ok {
		t.Fatal("a version-2 handle opened")
	}

	// Rotation: a new key id 2, with key 1 kept as old.
	rot := strings.Replace(baseConfig, `"handle_key_file": "handle.key",`,
		`"handle_key_file": "handle2.key", "handle_key_id": 2, "old_handle_keys": [{"id": 1, "file": "handle.key"}],`, 1)
	cfg2, err := parseConfig([]byte(rot), g.dir)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := loadHandleKeys(cfg2, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := k2.open(s); !ok {
		t.Fatal("a handle from the old key no longer opens")
	}
	s3, _ := k2.seal(in)
	if mustB64(t, s3)[1] != 2 {
		t.Fatal("new handle not made with key 2")
	}
	if _, ok := k.open(s3); ok {
		t.Fatal("key 1 opened a key-2 handle")
	}
	cfg3, _ := parseConfig([]byte(strings.Replace(rot, `, "old_handle_keys": [{"id": 1, "file": "handle.key"}]`, "", 1)), g.dir)
	k3, _ := loadHandleKeys(cfg3, func(string, ...any) {})
	if _, ok := k3.open(s); ok {
		t.Fatal("a handle from a dropped key still opens")
	}
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
