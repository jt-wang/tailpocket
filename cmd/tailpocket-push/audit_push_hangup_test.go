package main

// Audit, push-phone re-review (f684455). Without local keys, a made-up Play Integrity token is meant
// to cost its source one of 3 failures an hour (PUSH.md §10). The decode budget is charged before
// the call to Google, and the call runs on the request's context, which net/http cancels when the
// client hangs up. A client that sends its request and closes its side so gets 503
// attestation_unavailable: the budget is charged, nothing is counted against the source, and it
// is never blocked. Each source can do that 20 times an hour, so decode_per_hour / 20 = 20 sources
// still use the hour up, sending one request at a time.
//
// The fix: do not let the client's hang-up cancel the verification (context.WithoutCancel under
// the same upstreamTimeout), so the made-up token is judged and counted.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jt-wang/tailpocket/connectpush"
)

func TestAuditHangUpsUseUpThePlayIntegrityDecodes(t *testing.T) {
	const budget = 5
	cfg := strings.Replace(attestedConfig(), `"package_name": "io.example.alpha",`, fmt.Sprintf(`"package_name": "io.example.alpha", "decode_per_hour": %d,`, budget), 1)
	if cfg == attestedConfig() {
		t.Fatal("config not edited")
	}
	g := newGatewayWith(t, cfg)
	const piPath = "/pi/v1/io.example.alpha:decodeIntegrityToken"
	// Google takes a moment to answer, as it does.
	g.up.setReply(func(p string) (int, string) {
		if p == piPath {
			time.Sleep(300 * time.Millisecond)
		}
		return 400, `{"error":{}}`
	})
	front := httptest.NewServer(g.srv)
	defer front.Close()

	// One source (127.0.0.1) sends budget made-up tokens, one at a time, and hangs up after each.
	for i := 0; i < budget; i++ {
		ch := g.challenge("127.0.0.1:1")
		body, _ := json.Marshal(map[string]any{"app": appA, "platform": "fcm", "token": fcmToken(3000), "generation": 1,
			"attest": map[string]any{"challenge": ch, "token": "made-up-" + ch}})
		g.secret(fcmToken(3000))
		c, err := net.Dial("tcp", front.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(c, "POST /v1/register HTTP/1.1\r\nHost: gateway\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
		_ = c.(*net.TCPConn).CloseWrite()
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		answer, _ := io.ReadAll(c)
		c.Close()
		status, _, _ := strings.Cut(string(answer), "\r\n")
		t.Logf("made-up token %d, then hang up: %s", i+1, status)
	}
	t.Logf("Google saw %d decode calls", len(g.up.find(piPath)))

	// A real phone, from its own address, with a token Google vouches for.
	reg := devReq{"register", "fcm", fcmToken(1), 1}
	ch := g.challenge(freshIP())
	good := verdict{hash: connectpush.AttestRequestHash(reg.op, appA, reg.platform, reg.token, reg.gen, ch), pkg: appA, reqPkg: appA,
		recog: "PLAY_RECOGNIZED", certs: []string{base64.RawURLEncoding.EncodeToString(certDigest[:])},
		device: []string{"MEETS_BASIC_INTEGRITY", "MEETS_DEVICE_INTEGRITY"}, ts: g.clock.now().Add(-time.Minute)}
	g.up.setReply(func(p string) (int, string) {
		if p != piPath {
			return 200, ""
		}
		return 200, good.json()
	})
	g.attested(reg, freshIP(), map[string]any{"challenge": ch, "token": "integrity-token-" + ch}).want(t, 200, "")
}
