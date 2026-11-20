package connecthost

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/types/key"

	"github.com/jt-wang/tailpocket/connectinvite"
	"github.com/jt-wang/tailpocket/connectsecure"
)

const (
	DefaultTTL = 2 * time.Minute
	MaxTTL     = 15 * time.Minute
	// After a phone pairs, the window stays open this long so a phone whose reply got lost can retry.
	retryGrace = 10 * time.Second
	maxBody    = 4096
)

// Phone is a phone that joined through a pairing window.
type Phone struct {
	Key    string // "nodekey:…"
	Device string // the name the phone gave, cleaned
	Route  string // the route it pairs over: RouteTailcat, RouteRelay or RouteLAN
}

// PairRequest is a phone asking to pair, for PairOptions.Confirm.
type PairRequest struct {
	Phone  string // "nodekey:…"
	Device string // the name the phone gave, cleaned
	Route  string // RouteTailcat, RouteRelay or RouteLAN
	// Emoji are the four the phone shows (connectsecure.SASText). Show them with Device and ask the
	// user whether the phone shows the same. Nil for a phone pairing with a v1 invite (QR, Invite,
	// ServeLocal): an app before v0.3 shows none, so the user can only go by the name.
	Emoji []string
}

type PairOptions struct {
	// TTL bounds the window (default 2 minutes, at most 15).
	TTL time.Duration
	// Payload returns the app's own data for this phone (a token, settings, anything), delivered
	// with the reply inside the tunnel. It runs once per window. Nil sends no payload. An error
	// refuses the phone: this is where an app checks a pairing, for example the route it came over.
	Payload func(Phone) (string, error)
	// Confirm asks the computer's user to let a phone pair. It is required for v2 invites (QR2,
	// InviteV2): every pairing with one shows emoji on both screens and waits for this answer, over any
	// route. With a v1 invite it is optional and gets no emoji. It runs at most once at a time per
	// window; ctx ends when the phone gives up, the window closes or ConfirmTimeout passes. A false,
	// a timeout or a phone that goes away ends the window: show a new code to try again.
	Confirm func(ctx context.Context, req PairRequest) bool
}

// ConfirmTimeout is how long Confirm has.
const ConfirmTimeout = 55 * time.Second

// Pairing is one open window. One phone can join it.
type Pairing struct {
	h       *Host
	inv     connectinvite.Invite
	payload func(Phone) (string, error)
	confirm func(context.Context, PairRequest) bool
	expires time.Time
	node    node
	server  *http.Server
	ln      *chanListener

	code string // the v2 pairing code; its cid names this window on the encrypted routes
	cid  string

	limit *connectsecure.Limiter // Noise pairings over the Tailcat window

	mu      sync.Mutex
	v1      bool // a v1 invite left the host (QR, Invite, ServeLocal): /pair over Tailcat is open
	local   bool // ServeLocal ran on this window (once per window)
	waiting bool // Confirm is running
	bound   string
	noise   *[32]byte // the Noise key the bound phone brought, if any
	reply   *pairReply
	phone   Phone

	joined   chan struct{}
	ended    chan struct{}
	joinOnce sync.Once
	endOnce  sync.Once
	nodeOnce sync.Once
	linger   *time.Timer // closes the node byeLinger after a refusal
	timer    *time.Timer
}

type pairRequest struct {
	PhoneKey string `json:"phoneKey"`
	Device   string `json:"device"`
}

// pairReply is v1's reply; PK and Via are what v0.3 phones read for the encrypted routes, and older
// phones skip.
type pairReply struct {
	V       int                   `json:"v"`
	Address string                `json:"address"`
	Port    int                   `json:"port"`
	Name    string                `json:"name"`
	Payload string                `json:"payload,omitempty"`
	PK      string                `json:"pk,omitempty"`
	Via     []connectinvite.Route `json:"via,omitempty"`
}

// Pair opens a pairing window. Show p.QR(prefix) as a QR code, share it as a link, or call
// p.ServeLocal for same-Wi-Fi discovery; then p.Wait for the phone.
func (h *Host) Pair(ctx context.Context, opts PairOptions) (*Pairing, error) {
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if ttl > MaxTTL {
		ttl = MaxTTL
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil, ErrClosed
	}
	region := h.id.region
	h.mu.Unlock()

	client := key.NewNode()
	clientText, _ := client.MarshalText()
	expires := time.Now().Add(ttl)
	code := connectinvite.NewCode()
	p := &Pairing{h: h, payload: opts.Payload, confirm: opts.Confirm, expires: expires, ln: newChanListener(),
		limit:  connectsecure.NewLimiter(4),
		joined: make(chan struct{}), ended: make(chan struct{}), code: code, cid: connectsecure.CIDFor(code)}
	h.op.Lock()
	err := h.flushLocked() // the v2 invite carries the host's Noise key: it must be saved first
	h.op.Unlock()
	if err != nil {
		return nil, err
	}
	var n node
	n, err = h.start(ctx, nodeSpec{key: key.NewNode(), psk: tailcat.NewPresharedKey(), region: region,
		allowed: []key.NodePublic{client.Public()}, port: h.pairingPort, derpMapURL: h.derpMapURL,
		onTCP: func(port uint16) func(netConn) {
			if port != h.pairingPort {
				return nil
			}
			return p.servePairingConn
		}})
	if err != nil {
		return nil, err
	}
	p.node = n
	p.inv = connectinvite.Invite{Version: connectinvite.Version, Address: n.Address(), Port: int(h.pairingPort), Key: string(clientText),
		Proof: connectinvite.NewProof(), ExpiresAt: expires.Unix(), Name: h.name}
	if err := p.inv.Validate(); err != nil {
		_ = closeNode(n)
		return nil, err
	}
	p.server = &http.Server{Handler: p, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = p.server.Serve(p.ln) }()
	p.mu.Lock()
	p.timer = time.AfterFunc(time.Until(expires), p.Close)
	p.mu.Unlock()
	h.mu.Lock()
	h.pairings[p] = struct{}{}
	h.windows[p.cid] = p
	h.mu.Unlock()
	return p, nil
}

// InviteV2 is the window as a v2 invite: the Tailcat window, every relay and lan route, the host's
// Noise key and the pairing code. A phone may pair over any of them; they all redeem this window.
func (p *Pairing) InviteV2() connectinvite.V2 {
	v1 := p.inv
	via := []connectinvite.Route{{T: connectinvite.RouteTailcat, Inv: &v1}}
	h := p.h
	h.mu.Lock()
	pk := h.id.noisePublic()
	via = append(via, h.extraRoutesLocked()...)
	h.mu.Unlock()
	return connectinvite.V2{Version: connectinvite.Version2, Name: v1.Name, ExpiresAt: v1.ExpiresAt,
		PK: encodeKey(pk), PSK: p.code, Via: via}
}

// QR2 is InviteV2 as text for a QR code or link, e.g. with connectinvite.DefaultPrefix2. It needs
// PairOptions.Confirm.
func (p *Pairing) QR2(prefix string) (string, error) {
	if p.confirm == nil {
		return "", ErrNoConfirm
	}
	return connectinvite.EncodeV2(p.InviteV2(), prefix)
}

// ErrNoConfirm: a v2 invite was asked for a window without PairOptions.Confirm.
var ErrNoConfirm = errors.New("connecthost: v2 invites need PairOptions.Confirm")

// Invite is the v1 invite, for apps before v0.3; holding it lets a phone pair until it expires.
// Handing it out (Invite, QR, ServeLocal) opens /pair on the Tailcat window, which shows no emoji.
func (p *Pairing) Invite() connectinvite.Invite { p.openV1(); return p.inv }

// QR is the v1 invite as text for a QR code or link, e.g. with connectinvite.DefaultPrefix.
func (p *Pairing) QR(prefix string) (string, error) {
	p.openV1()
	return connectinvite.Encode(p.inv, prefix)
}

func (p *Pairing) openV1() {
	p.mu.Lock()
	p.v1 = true
	p.mu.Unlock()
}

// Expires is when the window closes.
func (p *Pairing) Expires() time.Time { return p.expires }

// Wait returns the phone that joined, ErrExpired when the window closed first, or ctx.Err().
func (p *Pairing) Wait(ctx context.Context) (Phone, error) {
	select {
	case <-p.joined:
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.phone, nil
	case <-p.ended:
		select {
		case <-p.joined:
			p.mu.Lock()
			defer p.mu.Unlock()
			return p.phone, nil
		default:
			return Phone{}, ErrExpired
		}
	case <-ctx.Done():
		return Phone{}, ctx.Err()
	}
}

// Done is closed when the window has closed (expired, Close, or after a phone joined).
func (p *Pairing) Done() <-chan struct{} { return p.ended }

// Close ends the window early, and closes its Tailcat node now, also when a refusal left it
// lingering. A phone that already joined stays paired.
func (p *Pairing) Close() {
	p.end(0)
	p.closeNode()
}

// closeNode closes the window's Tailcat node once, and forgets the window on the Host.
func (p *Pairing) closeNode() {
	p.nodeOnce.Do(func() {
		p.mu.Lock()
		if p.linger != nil {
			p.linger.Stop()
		}
		p.mu.Unlock()
		if p.node != nil {
			_ = closeNode(p.node)
		}
		p.h.mu.Lock()
		delete(p.h.linger, p)
		p.h.mu.Unlock()
	})
}

// byeLinger is how long the window's Tailcat node outlives a refusal, so the bye that tells the
// phone goes out over it; the window itself ends at once.
const byeLinger = 3 * time.Second

// end ends the window, and closes its Tailcat node after linger.
func (p *Pairing) end(linger time.Duration) {
	p.endOnce.Do(func() {
		p.mu.Lock()
		if p.timer != nil {
			p.timer.Stop()
		}
		p.mu.Unlock()
		if p.server != nil {
			_ = p.server.Close()
		}
		_ = p.ln.Close()
		p.h.mu.Lock()
		delete(p.h.pairings, p)
		delete(p.h.windows, p.cid)
		if linger > 0 {
			p.h.linger[p] = struct{}{} // Host.Close still reaches the node
		}
		p.h.mu.Unlock()
		if linger > 0 {
			p.mu.Lock()
			p.linger = time.AfterFunc(linger, p.closeNode)
			p.mu.Unlock()
		} else {
			p.closeNode()
		}
		close(p.ended)
	})
}

func (p *Pairing) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.EscapedPath() != "/pair" || r.URL.RawQuery != "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+p.inv.Proof)) != 1 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if len(body) > maxBody {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}
	var req pairRequest
	if json.Unmarshal(body, &req) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	k, err := parsePhone(req.PhoneKey)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	v1 := p.v1
	p.mu.Unlock()
	if !v1 {
		// Only a v2 invite left the host: its holder pairs with the Noise handshake and the emoji, not
		// with the Tailcat window inside it.
		p.h.record(Event{Kind: EventDenied, Phone: k.String(), Route: RouteTailcat, Reason: "v1-not-offered"})
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if !p.confirmed(r.Context(), k, req.Device, RouteTailcat, nil) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	// The pairing node admits the invite's one-time key, so phoneKey is only a claim here: no Noise
	// key is taken with it (pre.2 phones still send one; it is ignored). The phone registers its key
	// with Sync on the main node, where WireGuard proves the nodekey.
	reply, status := p.join(r.Context(), k, req.Device, RouteTailcat, nil)
	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(reply)
}

// join pairs phone k through this window, once: the same phone again (a lost reply) gets the same
// reply. It returns an HTTP status; the encrypted routes map it to a bye.
func (p *Pairing) join(ctx context.Context, k key.NodePublic, device, route string, noise *[32]byte) (*pairReply, int) {
	phone := Phone{Key: k.String(), Device: connectinvite.CleanName(device), Route: route}
	if phone.Device == "" {
		phone.Device = "Phone"
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.bound != "" && (p.bound != phone.Key || (noise != nil && p.noise != nil && *noise != *p.noise)) {
		return nil, http.StatusConflict
	}
	if p.reply == nil {
		if !time.Now().Before(p.expires) {
			return nil, http.StatusGone
		}
		payload := ""
		if p.payload != nil {
			var err error
			if payload, err = p.payload(phone); err != nil {
				return nil, http.StatusServiceUnavailable
			}
		}
		address, err := p.h.addPhone(ctx, k, noise)
		if err != nil || address == "" {
			return nil, http.StatusServiceUnavailable
		}
		p.bound, p.phone, p.noise = phone.Key, phone, noise
		h := p.h
		p.reply = &pairReply{V: 1, Address: address, Port: int(h.port), Name: h.name, Payload: payload}
		h.mu.Lock()
		// The encrypted routes only for a phone whose Noise key the host now holds: a phone that pairs
		// again keeps its old key (addPhone), and must not be told routes that would call it unpaired.
		if cur, ok := h.noise[k]; ok && noise != nil && cur == *noise {
			p.reply.PK, p.reply.Via = encodeKey(h.id.noisePublic()), h.routesLocked()
		}
		h.mu.Unlock()
		p.joinOnce.Do(func() { close(p.joined) })
		if time.Until(p.expires) > retryGrace {
			p.timer.Reset(retryGrace)
		}
		h.record(Event{Kind: EventPaired, Phone: phone.Key, Route: phone.Route})
	}
	return p.reply, http.StatusOK
}

// confirmed asks Confirm about phone k, unless the window has none or already took this phone (a
// lost reply). A no, a timeout, or the phone going away ends the window.
func (p *Pairing) confirmed(ctx context.Context, k key.NodePublic, device, route string, emoji []string) bool {
	if p.confirm == nil {
		return true
	}
	p.mu.Lock()
	if p.bound == k.String() {
		p.mu.Unlock()
		return true
	}
	if p.waiting || p.bound != "" {
		p.mu.Unlock()
		return false
	}
	p.waiting = true
	p.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, ConfirmTimeout)
	defer cancel()
	go func() {
		select {
		case <-p.ended:
			cancel()
		case <-ctx.Done():
		}
	}()
	name := connectinvite.CleanName(device)
	if name == "" {
		name = "Phone"
	}
	ok := p.confirm(ctx, PairRequest{Phone: k.String(), Device: name, Route: route, Emoji: emoji}) && ctx.Err() == nil
	p.mu.Lock()
	p.waiting = false
	p.mu.Unlock()
	if !ok {
		p.h.record(Event{Kind: EventDenied, Phone: k.String(), Route: route, Reason: "not-confirmed"})
		// A no, a timeout or a phone gone: this code is spent. The refusal's bye still has to
		// reach the phone, over the window's node when it came that way.
		p.end(byeLinger)
	}
	return ok
}

// servePairingConn takes a connection to the Tailcat window: a v2 phone's Noise pairing ("TP2P"),
// or a v1 phone's HTTP /pair.
func (p *Pairing) servePairingConn(c netConn) {
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReaderSize(c, 512)
	head, err := br.Peek(4)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		_ = c.Close()
		return
	}
	pc := &peekedConn{netConn: c, r: br}
	if string(head) == "TP2P" {
		go p.h.servePairing(pc, p.limit)
		return
	}
	p.ln.offer(pc)
}

type peekedConn struct {
	netConn
	r *bufio.Reader
}

func (c *peekedConn) Read(b []byte) (int, error) { return c.r.Read(b) }
