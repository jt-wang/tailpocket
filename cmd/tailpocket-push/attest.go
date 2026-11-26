package main

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// attester checks that a register or revoke request comes from a genuine
// copy of the app on a real device: App Attest on iOS (appattest.go), Play
// Integrity on Android (playintegrity.go). An app turns one on per platform
// with "attest": {"ios": {…}, "android": {…}} in the config. Without one the
// platform runs in strict mode: token format checks, tight per-source and
// per-app registration limits, and blocking sources whose tokens APNs or FCM
// reject (see badTokens).
type attester interface {
	Verify(ctx context.Context, req attestRequest) error
}

// attestRequest is what a verifier checks. Evidence is the request's
// "attest" field as it came. The server has already taken its one-time
// challenge; ClientDataHash is connectpush.AttestHash of op, app, platform,
// token, generation and that challenge, which the evidence must be bound to.
type attestRequest struct {
	App            string
	Platform       string // "apns" or "fcm"
	Op             string // "register" or "revoke"
	Token          string
	Generation     uint64
	Evidence       json.RawMessage
	ClientDataHash [32]byte
	Now            time.Time
}

// attestEnv is what a verifier gets when it is built.
type attestEnv struct {
	app   *appConfig
	dir   string // the config file's directory, for relative file names
	up    upstream
	state *genStore
}

// attestError is a refusal. reason is a fixed word for the log; unknownKey
// tells the phone its App Attest key is not (or no longer) known, so it
// attests a new one.
type attestError struct {
	reason     string
	unknownKey bool
}

func (e *attestError) Error() string { return "attestation: " + e.reason }

func attestFail(reason string) error { return &attestError{reason: reason} }

func attestReason(err error) string {
	var e *attestError
	if errors.As(err, &e) {
		return e.reason
	}
	if errors.Is(err, errDecodeBudget) {
		return "decode-budget"
	}
	return "other"
}

func isUnknownKey(err error) bool {
	var e *attestError
	return errors.As(err, &e) && e.unknownKey
}

// attestVerifiers builds a verifier from an app's "attest.ios" or
// "attest.android" config. A config one cannot use stops the start.
var attestVerifiers = map[string]func(config json.RawMessage, env attestEnv) (attester, error){
	"ios":     newAppAttest,
	"android": newPlayIntegrity,
}
