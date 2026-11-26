package connectphone

// Push (docs/PUSH.md §1). The phone gives each paired computer its push target (the gateway, app id,
// handle, key id and push key) only over the authenticated session: POST /v2/push on the control
// port over Tailcat, or a {"type":"push"} message on the encrypted session over relay and lan.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/jt-wang/tailpocket/connectinvite"
	"github.com/jt-wang/tailpocket/connectpush"
)

var (
	// ErrPushUnsupported: the computer runs a TailPocket without push (before v0.3.0-pre.5).
	ErrPushUnsupported = errors.New("connectphone: the computer does not take push targets")
)

// PushRefusedError is the computer saying no to a push target. Code is "push-off" (the computer's app
// set no push gateway), "gateway-not-allowed" (not this gateway), "invalid" or "failed".
type PushRefusedError struct{ Code string }

func (e *PushRefusedError) Error() string {
	return "connectphone: the computer refused the push target: " + e.Code
}

// pushAckWait bounds the wait for a push-ack on an encrypted session.
const pushAckWait = 10 * time.Second

// GivePush gives the computer this phone's push target. It goes over the first route that answers,
// as Dial does, but never over an opaque relay, which does not authenticate the computer.
func (s *Session) GivePush(ctx context.Context, t connectpush.Target) error {
	if err := t.Validate(); err != nil {
		return err
	}
	return s.sendPush(ctx, map[string]any{"target": t})
}

// ClearPush tells the computer to forget this phone's push target.
func (s *Session) ClearPush(ctx context.Context) error {
	return s.sendPush(ctx, map[string]any{"clear": true})
}

func (s *Session) sendPush(ctx context.Context, body map[string]any) error {
	s.mu.Lock()
	revoked, list := s.revoked, s.attemptsLocked()
	s.mu.Unlock()
	if revoked {
		return ErrRevoked
	}
	var errs []error
	tried := 0
	for _, r := range list {
		if r.M == connectinvite.ModeOpaque {
			continue
		}
		tried++
		var err error
		if r.T == connectinvite.RouteTailcat {
			actx, cancel := context.WithTimeout(ctx, perRoute)
			err = s.pushTailcat(actx, body)
			cancel()
		} else {
			err = s.pushSecure(ctx, r, body)
		}
		if err == nil {
			s.mu.Lock()
			s.last = routeKey(r)
			s.mu.Unlock()
			return nil
		}
		var refused *PushRefusedError
		if errors.As(err, &refused) || errors.Is(err, ErrRevoked) || errors.Is(err, ErrPushUnsupported) {
			return err
		}
		errs = append(errs, fmt.Errorf("%s: %w", r.T, err))
		if ctx.Err() != nil {
			break
		}
	}
	if tried == 0 {
		return fmt.Errorf("%w: no authenticated route", ErrUnreachable)
	}
	return fmt.Errorf("%w: %v", ErrUnreachable, errors.Join(errs...))
}

func (s *Session) pushTailcat(ctx context.Context, body map[string]any) error {
	s.mu.Lock()
	client := s.client
	s.mu.Unlock()
	if client == nil {
		return errors.New("connectphone: no Tailcat route")
	}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://control.invalid/v2/push", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := controlHTTP(client).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var r struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal(data, &r)
	switch {
	case resp.StatusCode == http.StatusOK && r.OK:
		return nil
	case resp.StatusCode == http.StatusNotFound:
		return ErrPushUnsupported
	case r.Error != "":
		return &PushRefusedError{Code: r.Error}
	}
	return fmt.Errorf("connectphone: host answered %d", resp.StatusCode)
}

// pushSecure bounds reaching the route by perRoute and, only once the message is sent, the wait for
// its push-ack by pushAckWait: a computer before push never answers, and that silence must read as
// ErrPushUnsupported, not as an unreachable route, also on the call that sets up the session.
func (s *Session) pushSecure(ctx context.Context, r connectinvite.Route, body map[string]any) error {
	sctx, cancel := context.WithTimeout(ctx, perRoute)
	sess, err := s.secure(sctx, r)
	cancel()
	if err != nil {
		return err
	}
	ch := make(chan map[string]any, 1)
	s.mu.Lock()
	if s.acks == nil {
		s.acks = map[float64]chan map[string]any{}
	}
	s.ackNext++
	id := s.ackNext
	s.acks[id] = ch
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.acks, id)
		s.mu.Unlock()
	}()
	msg := map[string]any{"type": "push", "id": id}
	for k, v := range body {
		msg[k] = v
	}
	if err := sess.Control().Send(msg); err != nil {
		return err
	}
	wait := time.NewTimer(pushAckWait)
	defer wait.Stop()
	select {
	case m := <-ch:
		if ok, _ := m["ok"].(bool); ok {
			return nil
		}
		code, _ := m["error"].(string)
		if code == "" {
			code = "failed"
		}
		return &PushRefusedError{Code: code}
	case <-sess.Done():
		return errors.New("connectphone: the session ended before the computer answered")
	case <-wait.C:
		return ErrPushUnsupported // a computer before push reads the message and never answers
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Session) deliverAck(m map[string]any) {
	id, _ := m["id"].(float64)
	s.mu.Lock()
	ch := s.acks[id]
	s.mu.Unlock()
	if ch != nil {
		select {
		case ch <- m:
		default:
		}
	}
}
