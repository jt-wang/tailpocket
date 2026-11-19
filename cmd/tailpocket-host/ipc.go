package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jt-wang/tailpocket/connecthost"
	"github.com/jt-wang/tailpocket/connectinvite"
	"github.com/jt-wang/tailpocket/connectlocal"
)

const (
	protocolVersion  = 1
	lineLimit        = 1 << 20
	saveTimeout      = 10 * time.Second
	authorizeTimeout = 5 * time.Second // an unanswered authorize denies
)

type config struct {
	V             int      `json:"v"`
	Name          string   `json:"name"`
	Identity      string   `json:"identity"`
	Allowed       []string `json:"allowed"`
	Forward       string   `json:"forward"`
	Port          uint16   `json:"port"`
	PairingPort   uint16   `json:"pairingPort"`
	DERPMapURL    string   `json:"derpMapUrl"`
	IdentifyPhone bool     `json:"identifyPhone"`
	// v0.3: end-to-end encrypted routes, and the app's own authorization and audit.
	Keys      map[string]string `json:"keys"`
	Relays    []relay           `json:"relays"`
	Listen    []string          `json:"listen"`
	Authorize bool              `json:"authorize"`
	Audit     bool              `json:"audit"`
	// v0.3.0-pre.4: Tailcat only (no lan listener, no relay), or no lan route.
	TailcatOnly bool `json:"tailcatOnly"`
	NoLAN       bool `json:"noLan"`
}

type relay struct {
	URL    string `json:"url"`
	Token  string `json:"token"`
	Opaque bool   `json:"opaque"`
	// AppAuth must be true with opaque: the app authenticates every connection itself.
	AppAuth bool `json:"appAuth"`
}

type command struct {
	Cmd      string `json:"cmd"`
	ID       string `json:"id"`
	TTL      int    `json:"ttl"`
	Payload  string `json:"payload"`
	QRPrefix string `json:"qrPrefix"`
	// QRPrefix2 is the v2 invite's prefix; default tailpocket2:.
	QRPrefix2 string `json:"qrPrefix2"`
	// Emoji makes a v2 window: the event has qr2 and invite2 (no v1 qr), and every phone that pairs
	// comes as a pairRequest event with the emoji, answered with confirm. Without it the window is v1
	// (qr and invite) as before v0.3.0-pre.4.
	Emoji    bool     `json:"emoji"`
	Service  string   `json:"service"`
	Label    string   `json:"label"`
	Instance string   `json:"instance"`
	Approve  bool     `json:"approve"`
	OK       bool     `json:"ok"`
	Allowed  []string `json:"allowed"`
	Phone    string   `json:"phone"`
}

type runtime struct {
	ctx     context.Context
	cfg     config
	h       *connecthost.Host
	writeMu sync.Mutex
	out     io.Writer

	mu       sync.Mutex
	saves    map[string]chan bool // save and authorize requests waiting for the app's answer
	serial   int
	pairings map[string]*window
	wg       sync.WaitGroup
}

type window struct {
	p       *connecthost.Pairing
	confirm chan bool
	local   bool
}

// Run speaks the helper protocol (docs/HOST-IPC.md): one config line, then commands, until stdin
// closes. stdout carries only events.
func Run(parent context.Context, in io.Reader, out io.Writer) error {
	r := &runtime{out: out, saves: map[string]chan bool{}, pairings: map[string]*window{}}
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), lineLimit)
	fail := func(code string) error {
		r.emit(map[string]any{"event": "error", "code": code})
		return errors.New(code)
	}
	if !sc.Scan() {
		return fail("invalid-config")
	}
	if json.Unmarshal(sc.Bytes(), &r.cfg) != nil {
		return fail("invalid-config")
	}
	if r.cfg.V != protocolVersion {
		return fail("unsupported-version")
	}
	if !validForward(r.cfg.Forward) {
		return fail("invalid-forward")
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	r.ctx = ctx
	hc := connecthost.Config{Name: r.cfg.Name, Port: r.cfg.Port, PairingPort: r.cfg.PairingPort, Identity: r.cfg.Identity,
		Allowed: r.cfg.Allowed, Keys: r.cfg.Keys, DERPMapURL: r.cfg.DERPMapURL, Save: r.save, Listen: r.cfg.Listen,
		TailcatOnly: r.cfg.TailcatOnly, NoLAN: r.cfg.NoLAN}
	for _, rl := range r.cfg.Relays {
		hc.Relays = append(hc.Relays, connecthost.Relay{URL: rl.URL, Token: rl.Token, Opaque: rl.Opaque, AppAuth: rl.AppAuth})
	}
	if r.cfg.Authorize {
		hc.Authorize = r.authorize
	}
	if r.cfg.Audit {
		hc.Audit = func(e connecthost.Event) {
			ev := map[string]any{"event": "audit", "kind": e.Kind, "phone": e.Phone, "route": e.Route,
				"reason": e.Reason, "time": e.Time.UnixMilli()}
			if e.Dropped > 0 {
				ev["dropped"] = e.Dropped
			}
			r.emit(ev)
		}
	}
	h, err := connecthost.New(hc)
	switch {
	case errors.Is(err, connecthost.ErrInvalidIdentity):
		return fail("invalid-identity")
	case errors.Is(err, connecthost.ErrInvalidPhone):
		return fail("invalid-allowed")
	case err != nil:
		return fail("invalid-config")
	}
	r.h = h
	defer func() {
		cancel()
		h.Close()
		r.wg.Wait()
	}()

	commands := make(chan command)
	var readErr error // set before commands closes
	go func() {
		defer close(commands)
		defer func() { readErr = sc.Err() }()
		for sc.Scan() {
			var c command
			if json.Unmarshal(sc.Bytes(), &c) != nil {
				r.emit(map[string]any{"event": "error", "code": "invalid-command"})
				continue
			}
			if c.Cmd == "saved" || c.Cmd == "authorized" { // answered at once: other commands may be waiting on it
				r.ack(c.ID, c.OK)
				continue
			}
			select {
			case commands <- c:
			case <-ctx.Done():
				return
			}
		}
	}()
	started := make(chan error, 1)
	go func() { started <- h.Start(ctx) }()
	go r.forward()
	select {
	case err := <-started:
		if err != nil {
			r.emit(map[string]any{"event": "error", "code": "start-failed"})
			return err
		}
	case <-ctx.Done():
	}
	r.emit(map[string]any{"event": "ready", "address": h.Address()})
	for {
		select {
		case c, ok := <-commands:
			if !ok {
				if readErr != nil { // a line over lineLimit: stop, and say so
					return fail("invalid-command")
				}
				return nil
			}
			r.handle(c)
		case <-ctx.Done():
			return nil
		}
	}
}

func validForward(target string) bool {
	if path, ok := strings.CutPrefix(target, "unix:"); ok {
		return path != ""
	}
	hostPart, port, err := net.SplitHostPort(target)
	if err != nil || hostPart == "" {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n < 65536
}

func (r *runtime) emit(v map[string]any) {
	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	body, err := json.Marshal(v)
	if err != nil {
		return
	}
	_, _ = r.out.Write(append(body, '\n'))
}

// ask emits event with a new id and waits for the app's answer ({"cmd":"saved"|"authorized","id":…,"ok":…}).
func (r *runtime) ask(prefix string, event map[string]any, timeout time.Duration) error {
	r.mu.Lock()
	r.serial++
	id := prefix + strconv.Itoa(r.serial)
	ch := make(chan bool, 1)
	r.saves[id] = ch
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.saves, id)
		r.mu.Unlock()
	}()
	event["id"] = id
	r.emit(event)
	select {
	case ok := <-ch:
		if !ok {
			return errors.New("app refused")
		}
		return nil
	case <-time.After(timeout):
		return errors.New("timeout")
	case <-r.ctx.Done():
		return r.ctx.Err()
	}
}

// save asks the app to store state and waits for {"cmd":"saved","id":…,"ok":true}.
func (r *runtime) save(st connecthost.State) error {
	if st.Allowed == nil {
		st.Allowed = []string{}
	}
	return r.ask("s", map[string]any{"event": "save", "state": st}, saveTimeout)
}

// authorize asks the app about one connection; no answer within authorizeTimeout denies it.
func (r *runtime) authorize(phone, route string) error {
	if phone == "" {
		phone = "opaque" // an opaque relay connection: no known phone
	}
	return r.ask("a", map[string]any{"event": "authorize", "phone": phone, "route": route}, authorizeTimeout)
}

func (r *runtime) ack(id string, ok bool) {
	r.mu.Lock()
	ch := r.saves[id]
	r.mu.Unlock()
	if ch != nil {
		select {
		case ch <- ok:
		default:
		}
	}
}

func (r *runtime) handle(c command) {
	fail := func(code string) { r.emit(map[string]any{"event": "error", "code": code, "id": c.ID}) }
	switch c.Cmd {
	case "pair":
		r.pair(c, fail)
	case "local":
		r.local(c, fail)
	case "confirm":
		r.mu.Lock()
		w := r.pairings[c.ID]
		r.mu.Unlock()
		if w == nil {
			fail("unknown-pairing")
			return
		}
		select {
		case w.confirm <- c.Approve:
		default:
			fail("nothing-to-confirm")
		}
	case "cancel":
		r.mu.Lock()
		w := r.pairings[c.ID]
		r.mu.Unlock()
		if w == nil {
			fail("unknown-pairing")
			return
		}
		w.p.Close()
	case "disconnect":
		r.h.Disconnect(c.Phone)
		r.emit(map[string]any{"event": "disconnected", "id": c.ID, "phone": c.Phone})
	case "status":
		relays := map[string]string{}
		for u, err := range r.h.RelayStatus() {
			relays[u] = "up"
			if err != nil {
				relays[u] = err.Error()
			}
		}
		r.emit(map[string]any{"event": "status", "id": c.ID, "address": r.h.Address(), "routes": r.h.Routes(), "relays": relays})
	case "setAllowed", "revoke":
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			var err error
			if c.Cmd == "revoke" {
				err = r.h.Revoke(r.ctx, c.Phone)
			} else {
				err = r.h.SetAllowed(r.ctx, c.Allowed)
			}
			switch {
			case errors.Is(err, connecthost.ErrInvalidPhone):
				fail("invalid-allowed")
			case err != nil:
				fail("operation-failed")
			default:
				r.emit(map[string]any{"event": "allowed", "id": c.ID, "allowed": r.h.Allowed(), "address": r.h.Address()})
			}
		}()
	default:
		fail("unknown-command")
	}
}

func (r *runtime) pair(c command, fail func(string)) {
	if c.ID == "" {
		fail("invalid-command")
		return
	}
	r.mu.Lock()
	_, dup := r.pairings[c.ID]
	r.mu.Unlock()
	if dup {
		fail("duplicate-id")
		return
	}
	prefix := c.QRPrefix
	if prefix == "" {
		prefix = connectinvite.DefaultPrefix
	}
	opts := connecthost.PairOptions{TTL: time.Duration(c.TTL) * time.Second}
	if c.Payload != "" {
		payload := c.Payload
		opts.Payload = func(connecthost.Phone) (string, error) { return payload, nil }
	}
	w := &window{confirm: make(chan bool)}
	if c.Emoji {
		opts.Confirm = func(ctx context.Context, req connecthost.PairRequest) bool {
			r.emit(map[string]any{"event": "pairRequest", "id": c.ID, "phone": req.Phone, "device": req.Device,
				"route": req.Route, "emoji": req.Emoji})
			select {
			case ok := <-w.confirm:
				return ok
			case <-ctx.Done():
				r.emit(map[string]any{"event": "pairRequestCancelled", "id": c.ID})
				return false
			}
		}
	}
	p, err := r.h.Pair(r.ctx, opts)
	if err != nil {
		fail("pair-failed")
		return
	}
	w.p = p
	ev := map[string]any{"event": "pairing", "id": c.ID, "expiresAt": p.Expires().Unix()}
	if c.Emoji {
		prefix2 := c.QRPrefix2
		if prefix2 == "" {
			prefix2 = connectinvite.DefaultPrefix2
		}
		qr2, err := p.QR2(prefix2)
		if err != nil {
			p.Close()
			fail("invalid-qr-prefix")
			return
		}
		ev["qr2"], ev["invite2"] = qr2, p.InviteV2()
	} else {
		qr, err := p.QR(prefix)
		if err != nil {
			p.Close()
			fail("invalid-qr-prefix")
			return
		}
		ev["qr"], ev["invite"] = qr, p.Invite()
	}
	r.mu.Lock()
	r.pairings[c.ID] = w
	r.mu.Unlock()
	r.emit(ev)
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		phone, err := p.Wait(r.ctx)
		if err == nil {
			r.emit(map[string]any{"event": "paired", "id": c.ID, "phone": phone.Key, "device": phone.Device, "address": r.h.Address()})
		}
		<-p.Done()
		r.mu.Lock()
		delete(r.pairings, c.ID)
		r.mu.Unlock()
		reason := "expired"
		if err == nil {
			reason = "paired"
		} else if r.ctx.Err() != nil {
			reason = "stopped"
		}
		r.emit(map[string]any{"event": "pairingClosed", "id": c.ID, "reason": reason})
	}()
}

func (r *runtime) local(c command, fail func(string)) {
	r.mu.Lock()
	w := r.pairings[c.ID]
	busy := w != nil && w.local
	if w != nil {
		w.local = true
	}
	r.mu.Unlock()
	if w == nil {
		fail("unknown-pairing")
		return
	}
	if busy {
		fail("duplicate-id")
		return
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		err := w.p.ServeLocal(r.ctx, connecthost.LocalOptions{Service: c.Service, Label: c.Label, Instance: c.Instance,
			Confirm: func(ctx context.Context, code, device string) bool {
				r.emit(map[string]any{"event": "localCode", "id": c.ID, "code": code, "device": device})
				select {
				case ok := <-w.confirm:
					return ok
				case <-ctx.Done():
					r.emit(map[string]any{"event": "localCancelled", "id": c.ID})
					return false
				}
			}})
		switch {
		case err == nil:
			r.emit(map[string]any{"event": "localDelivered", "id": c.ID})
		case errors.Is(err, connectlocal.ErrUnavailable):
			fail("local-unavailable")
		case errors.Is(err, connectlocal.ErrTooManyAttempts):
			fail("local-too-many-attempts")
		case errors.Is(err, connectlocal.ErrNotApproved), errors.Is(err, context.Canceled):
			fail("local-not-approved")
		default:
			fail("local-failed")
		}
	}()
}

// forward carries each phone connection to the app's server.
func (r *runtime) forward() {
	for {
		conn, err := r.h.Listener().Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			network, address := "tcp", r.cfg.Forward
			if path, ok := strings.CutPrefix(address, "unix:"); ok {
				network, address = "unix", path
			}
			app, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(r.ctx, network, address)
			if err != nil {
				return
			}
			defer app.Close()
			if r.cfg.IdentifyPhone {
				// An opaque relay connection is no known phone: say so, never "".
				id := connecthost.PhoneOf(conn)
				if id == "" {
					id = "opaque"
				}
				if _, err := io.WriteString(app, id+"\n"); err != nil {
					return
				}
			}
			done := make(chan struct{}, 2)
			go func() { _, _ = io.Copy(app, conn); closeWrite(app); done <- struct{}{} }()
			go func() { _, _ = io.Copy(conn, app); closeWrite(conn); done <- struct{}{} }()
			<-done
			<-done
		}()
	}
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	} else {
		_ = c.Close()
	}
}
