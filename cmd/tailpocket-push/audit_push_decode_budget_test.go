package main

// Audit, push-phone re-review (c062e32). decode_per_hour (default 400) caps the Play Integrity
// decodeIntegrityToken calls per app, and each register or revoke with a token costs one whether
// the token is real or not. The only limit before it is 20 requests an hour per source address. So
// 400 / 20 = 20 source addresses that send made-up tokens use the hour's decodes up, and every real
// Android phone of that app then gets 503 attestation_unavailable when it registers or revokes, for
// as long as the 20 addresses keep going. (Without the cap the same requests use up Google's daily
// quota instead, which is worse; the cap is right, the limit it leaves is what this test records.)

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/jt-wang/tailpocket/connectpush"
)

func TestAuditMadeUpTokensUseUpThePlayIntegrityDecodes(t *testing.T) {
	g := newGatewayWith(t, attestedConfig())
	const piPath = "/pi/v1/io.example.alpha:decodeIntegrityToken"
	g.up.setReply(func(p string) (int, string) { return 400, `{"error":{}}` })

	sources := defaultDecodePerHour / regPerIPPerHour
	for i := 0; i < sources; i++ {
		ip := fmt.Sprintf("172.20.%d.%d:1", i>>8&255, i&255)
		for j := 0; j < regPerIPPerHour; j++ {
			ch := g.challenge(ip)
			g.attested(devReq{"register", "fcm", fcmToken(1000 + i), 1}, ip, map[string]any{"challenge": ch, "token": "made-up-" + ch})
		}
	}
	t.Logf("%d sources sent %d made-up tokens; Google saw %d decode calls", sources, sources*regPerIPPerHour, len(g.up.find(piPath)))

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
