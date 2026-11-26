package connecthost

// Push (docs/PUSH.md). A paired phone hands the host its push target (connectpush.Target: the gateway,
// the app id, its handle there, and a push key with its key id) over the authenticated session only:
// POST /v2/push on the control port for phones on Tailcat, or a {"type":"push"} message on the
// encrypted session's control stream for phones on relay and lan. The host keeps it in State.Push and
// Host.Push seals each note with it and passes it to the gateway.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"tailscale.com/types/key"

	"github.com/jt-wang/tailpocket/connectpush"
	"github.com/jt-wang/tailpocket/connectsecure"
)

// PushTarget is a phone's push target as the host stores it. Seq is the last note sequence number
// used for this phone: it only grows, whichever key id the phone gives, so it is above every number
// the phone has seen for any of its key ids.
type PushTarget struct {
	connectpush.Target
	Seq uint64 `json:"seq"`
}

var (
	// ErrNoPushTarget: the phone has not given this host a push target (or it was dropped).
	ErrNoPushTarget = errors.New("connecthost: this phone gave no push target")
	// ErrPushGone: the gateway said the phone's handle no longer works (410, or 403 expired, revoked
	// or forbidden). The host dropped the target; the phone gives a new one when it registers again.
	ErrPushGone = errors.New("connecthost: the phone's push handle no longer works")

	errPushOff     = errors.New("connecthost: push is off (Config.PushGateways is empty)")
	errPushInvalid = errors.New("connecthost: invalid push target")
	errPushGateway = errors.New("connecthost: push gateway not in Config.PushGateways")
)

// pushCode is the code a phone gets for a refused target.
func pushCode(err error) string {
	switch {
	case errors.Is(err, errPushOff):
		return "push-off"
	case errors.Is(err, errPushInvalid):
		return "invalid"
	case errors.Is(err, errPushGateway):
		return "gateway-not-allowed"
	}
	return "failed"
}

// normGateway is a gateway URL compared with Config.PushGateways: scheme and host lower case, no
// trailing slash.
func normGateway(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + strings.TrimSuffix(u.EscapedPath(), "/")
}

// allowedGateway is the entry of Config.PushGateways that g names, or "". Host.Push dials only
// these entries, never the phone's own spelling of one.
func (h *Host) allowedGateway(g string) string {
	if n := normGateway(g); n != "" && slices.Contains(h.pushGateways, n) {
		return n
	}
	return ""
}

// checkTarget is the check every target gets, from a phone or from Config.Push. It returns the
// target with its gateway replaced by the configured entry it matches.
func (h *Host) checkTarget(t connectpush.Target) (connectpush.Target, error) {
	if len(h.pushGateways) == 0 {
		return t, errPushOff
	}
	if t.Validate() != nil {
		return t, errPushInvalid
	}
	g := h.allowedGateway(t.Gateway)
	if g == "" {
		return t, errPushGateway
	}
	t.Gateway = g
	return t, nil
}

func clonePush(m map[key.NodePublic]PushTarget) map[key.NodePublic]PushTarget {
	out := make(map[key.NodePublic]PushTarget, len(m)+1)
	for k, v := range m {
		out[k] = v
	}
	return out
}

// setPush stores phone k's push target (nil clears it), saving first. A phone not (or no longer)
// paired is refused.
func (h *Host) setPush(k key.NodePublic, t *connectpush.Target) error {
	if t != nil {
		c, err := h.checkTarget(*t)
		if err != nil {
			return err
		}
		t = &c
	} else if len(h.pushGateways) == 0 {
		return errPushOff
	}
	h.op.Lock()
	defer h.op.Unlock()
	h.mu.Lock()
	if h.closed || !slices.Contains(h.allowed, k) {
		h.mu.Unlock()
		return errors.New("connecthost: not paired")
	}
	cur, had := h.push[k]
	next := clonePush(h.push)
	switch {
	case t == nil && !had:
		h.mu.Unlock()
		return nil
	case t == nil:
		delete(next, k)
	case had && cur.Target == *t:
		h.mu.Unlock()
		return nil
	default:
		next[k] = PushTarget{Target: *t, Seq: cur.Seq} // the seq carries over: see PushTarget
	}
	st := h.stateWith(h.id, h.allowed, h.noise, next)
	h.mu.Unlock()
	if err := h.save(st); err != nil {
		return fmt.Errorf("connecthost: saving state: %w", err)
	}
	h.mu.Lock()
	h.push, h.dirty = next, false
	h.mu.Unlock()
	return nil
}

// PushPhones lists the phones that gave this host a push target.
func (h *Host) PushPhones() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := []string{}
	for _, k := range h.allowed {
		if _, ok := h.push[k]; ok {
			out = append(out, k.String())
		}
	}
	return out
}

// HasPush reports whether phone gave this host a push target.
func (h *Host) HasPush(phone string) bool {
	k, err := parsePhone(phone)
	if err != nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.push[k]
	return ok
}

// Push seals n for phone with the push key it gave and sends it through its gateway. It sets n.Seq
// (one above the last, saved with Config.Save before anything is sent, so a crash never reuses one)
// and n.Sent when it is 0. Errors: ErrNoPushTarget; ErrPushGone (the target was dropped);
// connectpush.ErrTooLarge (shorten Body); *connectpush.Error for other refusals, such as 429.
//
// Pushes to one phone are numbered in the order Push is called; two sent at once may arrive the
// other way round, and the phone then drops the older one. Send one at a time to keep both.
func (h *Host) Push(ctx context.Context, phone string, n connectpush.Note, opt connectpush.SendOptions) error {
	k, err := parsePhone(phone)
	if err != nil {
		return err
	}
	h.op.Lock()
	h.mu.Lock()
	t, ok := h.push[k]
	closed := h.closed
	if !ok || closed || !slices.Contains(h.allowed, k) {
		h.mu.Unlock()
		h.op.Unlock()
		if closed {
			return ErrClosed
		}
		return ErrNoPushTarget
	}
	t.Seq++
	next := clonePush(h.push)
	next[k] = t
	st := h.stateWith(h.id, h.allowed, h.noise, next)
	h.mu.Unlock()
	if err := h.save(st); err != nil {
		h.op.Unlock()
		return fmt.Errorf("connecthost: saving state: %w", err)
	}
	h.mu.Lock()
	h.push, h.dirty = next, false
	h.mu.Unlock()
	h.op.Unlock()

	pk, err := t.KeyBytes()
	if err != nil {
		return errPushInvalid
	}
	n.Seq = t.Seq
	if n.Sent == 0 {
		n.Sent = time.Now().Unix()
	}
	ct, err := connectpush.Seal(pk, t.Kid, t.App, n)
	if err != nil {
		return err
	}
	c := connectpush.Client{URL: t.Gateway, HTTP: h.pushClient}
	err = c.Send(ctx, t.Handle, ct, opt)
	var ge *connectpush.Error
	if errors.Is(err, connectpush.ErrGone) || errors.As(err, &ge) && ge.Status == http.StatusForbidden {
		h.dropPush(k, t.Handle)
		return fmt.Errorf("%w: %w", ErrPushGone, err)
	}
	return err
}

// dropPush forgets phone k's target if it still has handle (the phone may have sent a new one).
func (h *Host) dropPush(k key.NodePublic, handle string) {
	h.op.Lock()
	defer h.op.Unlock()
	h.mu.Lock()
	cur, ok := h.push[k]
	if !ok || cur.Handle != handle {
		h.mu.Unlock()
		return
	}
	next := clonePush(h.push)
	delete(next, k)
	st := h.stateWith(h.id, h.allowed, h.noise, next)
	h.mu.Unlock()
	if h.save(st) != nil {
		return // kept; the next Push gets the same answer and tries again
	}
	h.mu.Lock()
	h.push, h.dirty = next, false
	h.mu.Unlock()
}

// pushRequest is the body of POST /v2/push and of a {"type":"push"} control message: a target to
// store, or clear to drop the one stored.
type pushRequest struct {
	Target *connectpush.Target `json:"target"`
	Clear  bool                `json:"clear"`
}

func (q pushRequest) apply(h *Host, k key.NodePublic) error {
	switch {
	case q.Clear && q.Target == nil:
		return h.setPush(k, nil)
	case !q.Clear && q.Target != nil:
		return h.setPush(k, q.Target)
	}
	return errPushInvalid
}

// readControl reads what the phone sends on an encrypted session's control stream, so its queue never
// fills, and answers push messages: {"type":"push","id":n,"target":{…}} or {"type":"push","id":n,
// "clear":true}, answered with {"type":"push-ack","id":n,"ok":true} or ok false and "error".
func (h *Host) readControl(s *connectsecure.Session, k key.NodePublic) {
	for {
		m, err := s.Control().Recv()
		if err != nil {
			return
		}
		if m["type"] != "push" {
			continue
		}
		id, _ := m["id"].(float64)
		var q pushRequest
		err = remarshal(m, &q)
		if err == nil {
			err = q.apply(h, k)
		} else {
			err = errPushInvalid
		}
		reply := map[string]any{"type": "push-ack", "id": id, "ok": err == nil}
		if err != nil {
			reply["error"] = pushCode(err)
		}
		_ = s.Control().Send(reply)
	}
}
