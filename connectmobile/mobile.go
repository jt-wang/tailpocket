// Package connectmobile is the gomobile face of the phone SDK for iOS (xcframework) and Android (AAR).
// Every function takes and returns strings or numbers, never throws, and reports failures as
// {"error":"<code>"} with a fixed code: invalid-invite, invalid-key, invalid-link, expired,
// unauthorized, taken, unreachable, revoked, mismatch, handshake-closed, denied, local-failed,
// cancelled, timeout,
// unknown-operation, unknown-handle, failed. "revoked" comes only from the host's encrypted bye:
// delete the link. Every other code keeps it. Blocking calls (Pair, Pair2, Pair2Finish, LocalPairStart, LocalPairFinish) must run off the main thread;
// pass a caller-chosen op number to cancel them with Cancel(op).
package connectmobile

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jt-wang/tailpocket/connectinvite"
	"github.com/jt-wang/tailpocket/connectlocal"
	"github.com/jt-wang/tailpocket/connectphone"
	"github.com/jt-wang/tailpocket/connectsecure"
)

func fail(code string) string { return `{"error":"` + code + `"}` }

func code(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, connectphone.ErrExpired), errors.Is(err, connectlocal.ErrExpired):
		return "expired"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, connectinvite.ErrInvalid):
		return "invalid-invite"
	case errors.Is(err, connectphone.ErrNoSAS):
		return "failed"
	case errors.Is(err, connectphone.ErrRevoked):
		return "revoked"
	case errors.Is(err, connectphone.ErrUnauthorized):
		return "unauthorized"
	case errors.Is(err, connectsecure.ErrProtoMismatch):
		return "mismatch" // update the app or the computer
	case errors.Is(err, connectsecure.ErrHandshakeClosed):
		return "handshake-closed" // the computer is not running, or pinned another key: check, then pair again
	case errors.Is(err, connectphone.ErrTaken):
		return "taken"
	case errors.Is(err, connectphone.ErrUnreachable):
		return "unreachable"
	case errors.Is(err, connectlocal.ErrDenied):
		return "denied"
	case errors.Is(err, connectlocal.ErrFailed):
		return "local-failed"
	}
	return "failed"
}

// NewKey returns a new phone key ("privkey:…"). Create it once and store it in the Keychain/Keystore.
func NewKey() string { return connectphone.NewKey() }

// PublicKey returns "nodekey:…" for a phone key, or "" if it is invalid.
func PublicKey(private string) string {
	pub, err := connectphone.PublicKey(private)
	if err != nil {
		return ""
	}
	return pub
}

// DecodeInvite parses scanned QR or link text into the invite's JSON.
func DecodeInvite(text, prefix string) string {
	if prefix == "" {
		prefix = connectinvite.DefaultPrefix
	}
	inv, err := connectinvite.Decode(text, prefix)
	if err != nil {
		return fail("invalid-invite")
	}
	body, _ := json.Marshal(inv)
	return string(body)
}

// DecodeInvite2 parses scanned QR or link text into v2 invite JSON for Pair2: a v2 invite with
// prefix ("" for tailpocket2:), or a v1 invite with tailpocket1:, read as one tailcat route.
func DecodeInvite2(text, prefix string) string {
	if prefix == "" {
		prefix = connectinvite.DefaultPrefix2
	}
	inv, err := connectinvite.DecodeV2(text, prefix)
	if err != nil {
		inv, err = connectinvite.DecodeV2(text, connectinvite.DefaultPrefix)
	}
	if err != nil {
		return fail("invalid-invite")
	}
	body, _ := json.Marshal(inv)
	return string(body)
}

// --- cancellable operations -------------------------------------------------------------

type operation struct {
	cancel context.CancelFunc
	code   chan string
	result chan string
}

var (
	opsMu sync.Mutex
	ops   = map[int64]*operation{}
)

func begin(op int64, timeout time.Duration) (context.Context, *operation, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	o := &operation{cancel: cancel, code: make(chan string, 1), result: make(chan string, 1)}
	opsMu.Lock()
	defer opsMu.Unlock()
	if _, busy := ops[op]; busy {
		cancel()
		return nil, nil, false
	}
	ops[op] = o
	return ctx, o, true
}

func end(op int64) *operation {
	opsMu.Lock()
	defer opsMu.Unlock()
	o := ops[op]
	delete(ops, op)
	if o != nil {
		o.cancel()
	}
	return o
}

// Cancel stops a running Pair or local pairing. Unknown ops are ignored.
func Cancel(op int64) {
	opsMu.Lock()
	o := ops[op]
	opsMu.Unlock()
	if o != nil {
		o.cancel()
	}
}

func timeoutOf(ms int) time.Duration {
	if ms <= 0 {
		return 90 * time.Second
	}
	return time.Duration(ms) * time.Millisecond
}

// Pair joins the pairing window in inviteJSON and returns the Link JSON to store. Blocking.
func Pair(op int64, inviteJSON, phoneKey, device, derpMapURL string, timeoutMs int) string {
	inv, err := connectinvite.ParseJSON([]byte(inviteJSON))
	if err != nil {
		return fail("invalid-invite")
	}
	if PublicKey(phoneKey) == "" {
		return fail("invalid-key")
	}
	if inv.Expired(time.Now()) {
		return fail("expired")
	}
	ctx, _, ok := begin(op, timeoutOf(timeoutMs))
	if !ok {
		return fail("failed")
	}
	defer end(op)
	link, err := connectphone.Pair(ctx, inv, phoneKey, connectphone.Options{Device: device, DERPMapURL: derpMapURL})
	if err != nil {
		return fail(code(err))
	}
	text, err := link.Encode()
	if err != nil {
		return fail("failed")
	}
	return text
}

// Pair2 pairs from v2 invite JSON (DecodeInvite2) over whichever of its routes works. Blocking. It
// returns {"emoji":["🐶","🌙","🍕","🔑"]} once the computer waits for its user to compare them: show
// them with "Check that your computer shows the same, then confirm there", then call
// Pair2Finish(op, …) for the Link JSON to store. A phone pairing again after a lost reply gets the
// Link JSON (no "emoji") at once. Errors as {"error":…}; "unauthorized" after the emoji means the
// computer's user said no or the code was spent: show a new code on the computer.
func Pair2(op int64, inviteJSON, phoneKey, device, derpMapURL string, timeoutMs int) string {
	var inv connectinvite.V2
	if json.Unmarshal([]byte(inviteJSON), &inv) != nil || inv.Validate() != nil {
		return fail("invalid-invite")
	}
	if PublicKey(phoneKey) == "" {
		return fail("invalid-key")
	}
	if inv.Expired(time.Now()) {
		return fail("expired")
	}
	ctx, o, ok := begin(op, timeoutOf(timeoutMs)+time.Minute) // the computer's user may take a minute
	if !ok {
		return fail("failed")
	}
	go func() {
		link, err := connectphone.PairV2(ctx, inv, phoneKey, connectphone.Options{Device: device, DERPMapURL: derpMapURL,
			TailcatOnly: tailcatOnly.Load(), OnSAS: func(e []string) {
				body, _ := json.Marshal(map[string][]string{"emoji": e})
				o.code <- string(body)
			}})
		if err != nil {
			o.result <- fail(code(err))
			return
		}
		text, err := link.Encode()
		if err != nil {
			o.result <- fail("failed")
			return
		}
		o.result <- text
	}()
	select {
	case e := <-o.code:
		return e
	case r := <-o.result:
		end(op)
		return r
	}
}

// Pair2Finish waits for the computer's answer after Pair2 returned the emoji and returns the Link
// JSON to store, or {"error":…}.
func Pair2Finish(op int64, timeoutMs int) string { return LocalPairFinish(op, timeoutMs) }

var tailcatOnly atomic.Bool

// SetTailcatOnly is the phone's preference to reach computers over Tailcat only: Pair2, Connect and
// Sync then never use the relay or local network routes a computer lists. Set it before Connect;
// handles already open keep the setting they started with.
func SetTailcatOnly(on bool) { tailcatOnly.Store(on) }

// LocalPairStart connects to a host found over Bonjour ("ip:port") and returns {"code":"123456"}
// for the phone to show. Then call LocalPairFinish(op, …) for the invite.
func LocalPairStart(op int64, address, label, device string) string {
	ctx, o, ok := begin(op, 5*time.Minute)
	if !ok {
		return fail("failed")
	}
	go func() {
		inv, err := connectphone.PairLocal(ctx, address, connectphone.LocalOptions{Label: label, Device: device,
			OnCode: func(c string) { o.code <- c }})
		if err != nil {
			o.result <- fail(code(err))
			return
		}
		body, _ := json.Marshal(inv)
		o.result <- string(body)
	}()
	select {
	case c := <-o.code:
		body, _ := json.Marshal(map[string]string{"code": c})
		return string(body)
	case r := <-o.result:
		end(op)
		return r
	}
}

// LocalPairFinish waits for the host's user to approve and returns the invite JSON for Pair.
// Pair2Finish is the same wait.
func LocalPairFinish(op int64, timeoutMs int) string {
	opsMu.Lock()
	o := ops[op]
	opsMu.Unlock()
	if o == nil {
		return fail("unknown-operation")
	}
	defer end(op)
	select {
	case r := <-o.result:
		return r
	case <-time.After(timeoutOf(timeoutMs)):
		return fail("timeout")
	}
}

// --- connections --------------------------------------------------------------------------

type connection struct {
	session *connectphone.Session
	forward *connectphone.Forward
}

func lookup(handle int64) *connection {
	connMu.Lock()
	defer connMu.Unlock()
	return conns[handle]
}

var (
	connMu     sync.Mutex
	nextHandle int64 = 1
	conns            = map[int64]*connection{}
)

// Connect opens a loopback forward to the Link's host: {"handle":n,"port":p,"token":t,"base":b}. Point the app's
// HTTP or WebSocket client at "http://127.0.0.1:"+p+b (every path under b), or start a raw
// connection with the line "TP-FWD "+t+"\n" (connectphone.Forward). Nothing goes over the network
// until it connects.
func Connect(linkJSON, derpMapURL string) string {
	link, err := connectphone.ParseLink(linkJSON)
	if err != nil {
		return fail("invalid-link")
	}
	s, err := connectphone.Connect(link, connectphone.Options{DERPMapURL: derpMapURL, TailcatOnly: tailcatOnly.Load()})
	if err != nil {
		return fail("invalid-link")
	}
	f, err := s.Forward()
	if err != nil {
		s.Close()
		return fail("failed")
	}
	connMu.Lock()
	h := nextHandle
	nextHandle++
	conns[h] = &connection{session: s, forward: f}
	connMu.Unlock()
	body, _ := json.Marshal(map[string]any{"handle": h, "port": f.Port(), "token": f.Token(), "base": f.BasePath()})
	return string(body)
}

// Link returns the handle's Link JSON as it is now: the host may have sent new routes since Connect.
// Store it in place of the old one when it differs.
func Link(handle int64) string {
	c := lookup(handle)
	if c == nil {
		return fail("unknown-handle")
	}
	text, err := c.session.Link().Encode()
	if err != nil {
		return fail("failed")
	}
	return text
}

// Sync registers this phone's end-to-end key with the host over Tailcat and returns the updated Link
// JSON (host key and routes) to store. A link paired before v0.3 needs it once to use the relay and
// lan routes; no new QR. Blocking.
func Sync(handle int64, timeoutMs int) string {
	c := lookup(handle)
	if c == nil {
		return fail("unknown-handle")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeoutOf(timeoutMs))
	defer cancel()
	link, err := c.session.Sync(ctx)
	if err != nil {
		return fail(code(err))
	}
	text, err := link.Encode()
	if err != nil {
		return fail("failed")
	}
	return text
}

// Path reports how the handle reaches its host: {"route":"direct"|"relay"|"lan","relay":"<name>"} as
// before v0.3.1, and since v0.3.1 "kind" ("lan", "direct", "derp" for Tailcat through DERP, "relay" for
// tailpocket-relay) with, for derp, "derpRegion" (ID), "derpCode" and "derpHost" when known, and for
// relay, "relayHost". Blocking (a Tailcat disco ping, at most timeoutMs). {"error":"revoked"} once the
// host has said the phone is no longer paired: the forward's connections then close at once; delete
// the link.
func Path(handle int64, timeoutMs int) string {
	c := lookup(handle)
	if c == nil {
		return fail("unknown-handle")
	}
	if c.session.Revoked() {
		return fail("revoked")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeoutOf(timeoutMs))
	defer cancel()
	r, err := c.session.Route(ctx)
	if err != nil {
		return fail(code(err))
	}
	route, relay := r.Path()
	body, _ := json.Marshal(map[string]any{"route": route, "relay": relay, "kind": r.Kind,
		"derpRegion": r.DERPRegion, "derpCode": r.DERPCode, "derpHost": r.DERPHost, "relayHost": r.RelayHost})
	return string(body)
}

// Stop closes a Connect handle. Unknown or repeated handles are ignored.
func Stop(handle int64) {
	connMu.Lock()
	c := conns[handle]
	delete(conns, handle)
	connMu.Unlock()
	if c != nil {
		c.forward.Close()
		_ = c.session.Close()
	}
}

func itoa(i int) string { return strconv.Itoa(i) }
