package main

// Audit, push-phone re-review (92b5443). With PG2 fixed, an attested app's hourly budget is charged
// only after its evidence passed. The used-challenge table (maxChallenges = 65536, 5 minutes) is
// still filled before the evidence is looked at, and a full table refuses every challenge. So
// 65536 / 20 = 3277 source addresses, each sending its 20 requests an hour with a real challenge
// and no real evidence, make every attested app answer bad_challenge for up to 5 minutes.

import (
	"fmt"
	"testing"
)

func TestAuditUnattestedRequestsFillTheChallengeTable(t *testing.T) {
	root := newCA(t, "root", nil)
	inter := newCA(t, "inter", root)
	trustCA(t, root)
	g := newGatewayWith(t, attestedConfig())
	// A smaller table, so the test is fast; the same requests fill a full-size one.
	g.srv.ch.max = 1000

	// Since PG4 a source is blocked after attestFailLimit failed attestations, before it takes
	// another challenge, so each source fills attestFailLimit entries at most.
	sources := g.srv.ch.max/attestFailLimit + 1
	for i := 0; i < sources; i++ {
		ip := fmt.Sprintf("172.%d.%d.%d:1", 16+i>>16&15, i>>8&255, i&255)
		for j := 0; j < attestFailLimit; j++ {
			ch := g.challenge(ip)
			g.attested(devReq{"register", "apns", apnsToken(100000 + i), 1}, ip, map[string]any{"challenge": ch, "key_id": "AAAA", "attestation": "AA=="})
		}
	}
	// A real phone, from its own address, with a valid attestation.
	d := newDevice(inter)
	reg := devReq{"register", "apns", apnsToken(1), 1}
	ch := g.challenge(freshIP())
	ev := map[string]any{"challenge": ch, "key_id": d.keyID(), "attestation": d.attestation(t, reg.hash(ch), attOpts{})}
	g.attested(reg, freshIP(), ev).want(t, 200, "")
}
