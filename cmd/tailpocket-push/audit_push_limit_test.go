package main

// Audit, push-phone review (d2c0020). An app with "attest" answers /v1/register and /v1/revoke only
// with App Attest or Play Integrity evidence. But device() takes one of the app's register_per_hour
// (all sources together) before it looks at the evidence, so requests with no evidence at all use
// the app's registrations up: register_per_hour / 20 source addresses (50 with the defaults; an
// IPv6 /64 counts as one) stop every real phone of that app from registering or revoking for the
// hour, and can keep doing so.
//
// The fix: count a.regLim only after the evidence passed (strict-mode apps keep the count where it
// is; the per-source limit stays first for both).

import (
	"strings"
	"testing"
)

func TestAuditUnattestedRequestsUseUpAttestedAppsRegistrations(t *testing.T) {
	root := newCA(t, "root", nil)
	inter := newCA(t, "inter", root)
	trustCA(t, root)
	g := newGatewayWith(t, strings.Replace(attestedConfig(), `"id": "io.example.alpha",`, `"id": "io.example.alpha", "register_per_hour": 3,`, 1))

	// Three sources that hold no device and no evidence.
	for i := 0; i < 3; i++ {
		g.attested(devReq{"register", "apns", apnsToken(100 + i), 1}, freshIP(), nil).want(t, 401, "attestation_required")
	}
	// A real phone, from its own address, with a valid attestation.
	d := newDevice(inter)
	reg := devReq{"register", "apns", apnsToken(1), 1}
	ch := g.challenge(freshIP())
	ev := map[string]any{"challenge": ch, "key_id": d.keyID(), "attestation": d.attestation(t, reg.hash(ch), attOpts{})}
	g.attested(reg, freshIP(), ev).want(t, 200, "")
}
