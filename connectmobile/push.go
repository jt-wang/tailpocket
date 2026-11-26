package connectmobile

// Push (docs/PUSH.md §1): register this phone's device token with a tailpocket-push gateway, give the
// resulting push target to a paired computer, and revoke handles when a computer is removed. Opening
// notes is not here: the notification extension does it without the Go library (sdk/apple
// TailPocketPush, sdk/android push), within the extension's memory limit.
//
// Extra error codes: stale-generation (with "minGeneration": register with it or higher),
// attestation-required, attestation-failed, attest-key-unknown (make and attest a new App Attest
// key), rate-limited, push-refused (with "reason" from the computer: push-off, gateway-not-allowed,
// invalid, failed), push-unsupported (the computer has no push), invalid-arguments.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jt-wang/tailpocket/connectphone"
	"github.com/jt-wang/tailpocket/connectpush"
)

func pushFail(err error) string {
	var ge *connectpush.Error
	var refused *connectphone.PushRefusedError
	switch {
	case errors.As(err, &ge):
		switch {
		case ge.Code == "stale_generation":
			body, _ := json.Marshal(map[string]any{"error": "stale-generation", "minGeneration": ge.MinGeneration})
			return string(body)
		case ge.Code == "attestation_required", ge.Code == "bad_challenge":
			return fail("attestation-required")
		case ge.Code == "attest_key_unknown":
			return fail("attest-key-unknown")
		case ge.Status == http.StatusUnauthorized:
			return fail("attestation-failed")
		case ge.Status == http.StatusTooManyRequests:
			return fail("rate-limited")
		case ge.Status == http.StatusBadRequest:
			return fail("invalid-arguments")
		}
		return fail("failed")
	case errors.As(err, &refused):
		body, _ := json.Marshal(map[string]string{"error": "push-refused", "reason": refused.Code})
		return string(body)
	case errors.Is(err, connectphone.ErrPushUnsupported):
		return fail("push-unsupported")
	case errors.Is(err, context.DeadlineExceeded):
		return fail("timeout")
	}
	if code := code(err); code != "failed" {
		return fail(code)
	}
	return fail("unreachable") // a network error talking to the gateway
}

func pushCtx(timeoutMs int) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeoutOf(timeoutMs))
}

// PushNewKey returns a new push key for one computer: {"kid":…,"key":…} (key is 32 bytes base64url).
// Store it where the notification extension can read it, then give it with PushGive.
func PushNewKey() string {
	kid, key, err := connectpush.NewKey()
	if err != nil {
		return fail("failed")
	}
	body, _ := json.Marshal(map[string]string{"kid": kid, "key": base64.RawURLEncoding.EncodeToString(key[:])})
	return string(body)
}

// PushChallenge returns {"challenge":…} for attestation evidence, from a gateway that checks it for
// app. Blocking.
func PushChallenge(gateway, app string, timeoutMs int) string {
	if connectpush.ValidGateway(gateway) != nil {
		return fail("invalid-arguments")
	}
	ctx, cancel := pushCtx(timeoutMs)
	defer cancel()
	ch, err := (&connectpush.Client{URL: gateway}).Challenge(ctx, app)
	if err != nil {
		return pushFail(err)
	}
	body, _ := json.Marshal(map[string]string{"challenge": ch})
	return string(body)
}

func device(app, platform, token string, generation int64, attest string) (connectpush.Device, bool) {
	d := connectpush.Device{App: app, Platform: platform, Token: token, Generation: uint64(generation)}
	if generation < 1 || app == "" || token == "" || (platform != "apns" && platform != "fcm") {
		return d, false
	}
	if attest != "" {
		if !json.Valid([]byte(attest)) {
			return d, false
		}
		d.Attest = json.RawMessage(attest)
	}
	return d, true
}

// PushRegister registers a device token ("apns": hex, "fcm": the FCM token) with the gateway for app
// and returns {"handle":…,"expires":unix seconds}. generation is the phone's counter for this app (from
// 1); attest is the evidence JSON for a gateway that checks it, or "". Register again before expires.
// Blocking.
func PushRegister(gateway, app, platform, token string, generation int64, attest string, timeoutMs int) string {
	d, ok := device(app, platform, token, generation, attest)
	if !ok || connectpush.ValidGateway(gateway) != nil {
		return fail("invalid-arguments")
	}
	ctx, cancel := pushCtx(timeoutMs)
	defer cancel()
	r, err := (&connectpush.Client{URL: gateway}).RegisterDevice(ctx, d)
	if err != nil {
		return pushFail(err)
	}
	body, _ := json.Marshal(r)
	return string(body)
}

// PushRevoke makes every handle for the token with a generation up to generation stop working, and
// returns {}. Call it with the current generation when a computer is removed, then PushRegister with
// generation+1 and give the new handle to the computers that stay. Blocking.
func PushRevoke(gateway, app, platform, token string, generation int64, attest string, timeoutMs int) string {
	d, ok := device(app, platform, token, generation, attest)
	if !ok || connectpush.ValidGateway(gateway) != nil {
		return fail("invalid-arguments")
	}
	ctx, cancel := pushCtx(timeoutMs)
	defer cancel()
	if err := (&connectpush.Client{URL: gateway}).RevokeDevice(ctx, d); err != nil {
		return pushFail(err)
	}
	return "{}"
}

// PushGive gives the computer of a Connect handle this phone's push target JSON ({"gateway", "app",
// "handle", "kid", "key"}) over the authenticated session, and returns {}. Blocking.
func PushGive(handle int64, targetJSON string, timeoutMs int) string {
	c := lookup(handle)
	if c == nil {
		return fail("unknown-handle")
	}
	var t connectpush.Target
	if json.Unmarshal([]byte(targetJSON), &t) != nil || t.Validate() != nil {
		return fail("invalid-arguments")
	}
	ctx, cancel := pushCtx(timeoutMs)
	defer cancel()
	if err := c.session.GivePush(ctx, t); err != nil {
		return pushFail(err)
	}
	return "{}"
}

// PushClear tells the computer of a Connect handle to forget this phone's push target, and returns {}.
// Blocking.
func PushClear(handle int64, timeoutMs int) string {
	c := lookup(handle)
	if c == nil {
		return fail("unknown-handle")
	}
	ctx, cancel := pushCtx(timeoutMs)
	defer cancel()
	if err := c.session.ClearPush(ctx); err != nil {
		return pushFail(err)
	}
	return "{}"
}
