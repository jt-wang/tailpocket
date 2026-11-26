package main

// Audit, push-phone re-review (23880f6). Without local keys, the failure block is meant to cap a
// source at attestFailLimit (3) Play Integrity decodes an hour, so that decode_per_hour / 3 = 134
// sources are needed to use the budget up (PUSH.md §10). The block is checked before Verify and
// counted after it, and nothing counts the requests in between. A source that sends its 20 requests
// at once gets all 20 past the check while the first is still at Google, so 400 / 20 = 20 sources
// still use up the hour, as before the block. (The same 20 sources sending one request at a time
// cost 60 decodes: TestAuditMadeUpTokensUseUpThePlayIntegrityDecodes.)
//
// The fix: count a source's requests that are at the verifier together with its failures, so no
// source has more than attestFailLimit unanswered or failed at once.

import (
	"encoding/base64"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jt-wang/tailpocket/connectpush"
)

func TestAuditParallelMadeUpTokensUseUpThePlayIntegrityDecodes(t *testing.T) {
	g := newGatewayWith(t, attestedConfig())
	const piPath = "/pi/v1/io.example.alpha:decodeIntegrityToken"
	// Google takes a moment to answer, as it does.
	g.up.setReply(func(p string) (int, string) {
		if p == piPath {
			time.Sleep(300 * time.Millisecond)
		}
		return 400, `{"error":{}}`
	})

	sources := defaultDecodePerHour / regPerIPPerHour
	var wg sync.WaitGroup
	for i := 0; i < sources; i++ {
		ip := fmt.Sprintf("172.21.%d.%d:1", i>>8&255, i&255)
		for j := 0; j < regPerIPPerHour; j++ {
			ch := g.challenge(ip)
			wg.Add(1)
			go func() {
				defer wg.Done()
				g.attested(devReq{"register", "fcm", fcmToken(2000 + i), 1}, ip, map[string]any{"challenge": ch, "token": "made-up-" + ch})
			}()
		}
	}
	wg.Wait()
	calls := len(g.up.find(piPath))
	t.Logf("%d sources sent %d made-up tokens at once; Google saw %d decode calls", sources, sources*regPerIPPerHour, calls)
	if most := sources * attestFailLimit; calls > most {
		t.Errorf("%d decode calls for %d sources, want at most %d (%d a source)", calls, sources, most, attestFailLimit)
	}

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
