package main

// Audit, push-phone re-review (23880f6). The new failure block counts every attestError against the
// request's source address. On the Google path (no local keys), playIntegrity.decodeToken returns
// attestFail("oauth") when the gateway itself cannot get its Google access token: Google's OAuth
// endpoint is down or unreachable, or the service account is wrong. That is the gateway's failure,
// not the phone's, but it is answered 401 attestation_failed and counted. So a real phone that
// tries three times while Google is unreachable has its address (and everyone behind it) blocked
// from register and revoke for an hour, long after Google is back.
//
// The fix: an OAuth failure is not an attestError (503 attestation_unavailable, nothing counted),
// like every other failure to reach Google in decodeToken.

import (
	"strings"
	"testing"
)

func TestAuditGoogleOutageBlocksThePhone(t *testing.T) {
	g := newGatewayWith(t, attestedConfig())
	// Google (OAuth and Play Integrity) is unreachable: the gateway's upstreams point at port 1, where
	// nothing listens and a dial is refused at once. Closing the fake Google instead would leave its
	// freed port to be dialed again and again, and a test running in parallel can be given that port
	// (the relays' fail-closed tests count every connection their victim listener gets).
	g.up.ts.URL = "https://127.0.0.1:1"
	g.srv = g.build(attestedConfig())

	ip := freshIP()
	for i := 0; i < attestFailLimit+1; i++ {
		ch := g.challenge(ip)
		r := g.attested(devReq{"register", "fcm", fcmToken(1), 1}, ip, map[string]any{"challenge": ch, "token": "integrity-token-" + ch})
		if r.code != 503 {
			t.Errorf("try %d while Google is unreachable: got %d %s, want 503 attestation_unavailable", i+1, r.code, strings.TrimSpace(r.body))
		}
	}
}
