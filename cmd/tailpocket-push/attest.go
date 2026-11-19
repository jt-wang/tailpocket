package main

import (
	"context"
	"encoding/json"
)

// attester checks that a register or revoke request comes from a genuine
// copy of the app on a real device: App Attest on iOS, Play Integrity on
// Android. Without one an app runs in strict mode: token format checks,
// tight per-source and per-app registration limits, and blocking sources
// whose tokens APNs or FCM reject (see badTokens).
type attester interface {
	Verify(ctx context.Context, req attestRequest) error
}

// attestRequest is what a verifier checks. Evidence is the request's
// "attest" field as it came, and must be bound to the rest: a verifier
// must check that the evidence was made for this app, token and
// generation, so it cannot be replayed for another device.
type attestRequest struct {
	App        string
	Platform   string // "apns" or "fcm"
	Op         string // "register" or "revoke"
	Token      string
	Generation uint64
	Evidence   json.RawMessage
}

// attestVerifiers builds a verifier from an app's "attest.ios" or
// "attest.android" config. None is built in: both need Apple's or
// Google's online services and the publisher's own setup, and an app with
// "attest" set refuses to start rather than run unchecked.
//
// TODO(ios): App Attest. Needs a challenge endpoint (a random, short-lived
// nonce the gateway can check without a database, such as one sealed with
// the handle key), then: verify the attestation object's certificate chain
// to Apple's App Attest root CA, that the nonce is SHA-256(authData ||
// SHA-256(clientData)), that the RP ID hash is SHA-256(team id + "." +
// bundle id) and the environment matches apns.env; keep the public key of
// the attested key (one small record per device, in the state file) and
// for later requests check an assertion over the request with its counter.
// clientData must cover op, app, token, generation and the challenge.
//
// TODO(android): Play Integrity. The app asks for an integrity token with
// requestHash = SHA-256 of op, app, token and generation; the gateway
// decodes it with the publisher's service account (playintegrity.googleapis.com
// decodeIntegrityToken, a fourth fixed host) and checks requestHash,
// appIntegrity.packageName and certificateSha256Digest, appRecognitionVerdict
// PLAY_RECOGNIZED, deviceIntegrity and that the timestamp is recent.
var attestVerifiers = map[string]func(config json.RawMessage) (attester, error){}
