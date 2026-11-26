package connectphone

// Routes (v0.3). A Session reaches its host over Tailcat, tailpocket-relay or lan, whichever answers,
// trying the one that worked last first. relay and lan run connectsecure's Noise session to the
// host key the Link pins; an opaque relay hands the app the relay's bytes and leaves encryption to it.
//
// The phone's Noise key is derived from its Tailcat key, so a Link needs no second secret and a link
// paired before v0.3 already has one: Session.Sync registers it with the host over Tailcat.

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/flynn/noise"
	"github.com/tailscale/tailcat"
	"golang.org/x/crypto/curve25519"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"

	"github.com/jt-wang/tailpocket/connectinvite"
	"github.com/jt-wang/tailpocket/connectrelay"
	"github.com/jt-wang/tailpocket/connectsecure"
	"github.com/jt-wang/tailpocket/internal/closing"
	"github.com/jt-wang/tailpocket/internal/testhook"
)

// Version is the library version the phone sends in its encrypted hello.
const Version = "0.4.0"

// ErrRevoked: the host said, encrypted, that this phone is no longer paired. Pair again.
var ErrRevoked = errors.New("connectphone: the host no longer has this phone paired")

// perRoute bounds one route's attempt while others are left to try; the last route has the caller's
// context (Session.Forward bounds a whole Dial with max(20 s, routes × perRoute)), and each route ends by
// itself as well: lan and Tailcat after 10 s, a relay's upgrade after connectrelay.PhoneUpgradeTimeout.
// lanDial bounds each lan address.
// After a Dial, the session looks for a better route in the background (Session.upgrade), each for
// at most upgradeTry, once per upgradeRetry.
const (
	perRoute     = 10 * time.Second
	lanDial      = 3 * time.Second
	upgradeTry   = 5 * time.Second
	upgradeRetry = 30 * time.Second
)

// noiseKeys is the phone's Noise static key pair, derived from its Tailcat key with a label so the two
// protocols never share a key.
func noiseKeys(k key.NodePrivate) noise.DHKey {
	raw := k.Raw32()
	priv := sha256.Sum256(append([]byte("tailpocket2 noise key\n"), raw[:]...))
	pub, _ := curve25519.X25519(priv[:], curve25519.Basepoint)
	return noise.DHKey{Private: priv[:], Public: pub}
}

func noisePublic(k key.NodePrivate) string {
	return base64.RawURLEncoding.EncodeToString(noiseKeys(k).Public)
}

// noiseProof proves to the host with Noise key hostPK that this phone holds its Noise key.
func noiseProof(k key.NodePrivate, hostPK string) (string, error) {
	server, ok := decodeKey(hostPK)
	if !ok {
		return "", errors.New("connectphone: invalid host key")
	}
	p, err := connectsecure.KeyProof(noiseKeys(k).Private, server, connectinvite.ProofNoise,
		connectinvite.NoiseClaim(k.Public().String(), noisePublic(k)))
	return base64.RawURLEncoding.EncodeToString(p), err
}

// nodekeyProof signs a pairing handshake with the phone's nodekey (ProofPair).
func nodekeyProof(k key.NodePrivate, server [32]byte) func([]byte) ([]byte, error) {
	return func(binding []byte) ([]byte, error) {
		raw := k.Raw32()
		return connectsecure.KeyProof(raw[:], server, connectinvite.ProofPair, binding)
	}
}

// setRoutes takes the routes a host sent: its Tailcat address, and the others for Via.
func (l *Link) setRoutes(via []connectinvite.Route) {
	l.Via = nil
	for _, r := range via {
		if r.T == connectinvite.RouteTailcat {
			if len(r.A) == 1 && connectinvite.ValidAddress(r.A[0]) {
				l.Address, l.Port = r.A[0], r.P
			}
			continue
		}
		l.Via = append(l.Via, r)
	}
}

// Session reaches the host of one Link. It is safe for concurrent use.
type Session struct {
	opts    Options
	private key.NodePrivate
	client  *tailcat.Client // nil while the Link has no Tailcat address

	secMu sync.Mutex // one encrypted session is set up at a time

	mu      sync.Mutex
	link    Link
	last    string // the route that worked last (routeKey)
	sec     *connectsecure.Session
	secKey  string
	drained []*connectsecure.Session // replaced sessions still carrying connections (Drain)
	revoked bool

	acks    map[float64]chan map[string]any // push messages waiting for the host's push-ack
	ackNext float64
	closed  bool
	upTry   time.Time    // when Dial last looked for a better route (upgrade)
	failure *DialFailure // the last Dial that failed, nil after one succeeds
}

// DialFailure is why the last Dial of a Session failed (v0.3.4), when, and how each route ended. A
// Dial that succeeds clears it. Err is what Dial returned (errors.Is works: ErrUnreachable,
// connectsecure.ErrHandshakeClosed, ErrRevoked, ...). Route is the route type that decided Reason
// ("lan", "relay", "tailcat"; "" when no route was tried).
//
// Reason sorts a failure to reach the computer into what the user can do about it:
//   - ReasonRefused or ReasonHandshakeClosed: something answered for the computer and did not take
//     this phone. Your relay has no computer in this phone's room, or the computer's address refused
//     the connection, or closed the encrypted handshake. TailPocket is not running there, or the
//     computer was reset and has a new identity (then the phone must pair again). A lan refusal or
//     close counts only when no other route went unanswered (v0.3.5): any device on the phone's
//     network can hold the old lan address and refuse or close, while a network that blocks the phone
//     leaves the other routes unanswered.
//   - ReasonNoAnswer: no route answered at all. The computer is off or asleep, or the network
//     blocks the connection (a plane's or hotel's Wi-Fi).
//   - ReasonRelayDown: your relay answered but would not carry the phone, and nothing else answered.
//   - "": Err is ErrRevoked, ErrUnauthorized, connectsecure.ErrProtoMismatch, or no route was tried.
//
// None of it is authenticated: anything on the network can refuse a connection, close a handshake,
// or pose as the relay's answer. Show it to the user, never act on it alone: it must not delete the
// link, unpair, or replace the pinned host key. Only ErrRevoked comes from the computer itself, over
// the encrypted session (SECURITY.md).
type DialFailure struct {
	Err    error
	At     time.Time
	Route  string
	Reason string
	Routes []RouteFailure // every route the Dial tried, in order
}

// RouteFailure is how one route of a failed Dial ended: Reason is one of the Route* reasons.
type RouteFailure struct {
	Route  string // "lan", "relay", "tailcat"
	Reason string
}

// Reasons of a DialFailure; RouteFailure also uses RouteRefused and RouteNoHost.
const (
	ReasonRefused         = "refused"
	ReasonHandshakeClosed = "handshake-closed"
	ReasonNoAnswer        = "no-answer"
	ReasonRelayDown       = "relay-down"
	RouteRefused          = "refused" // lan: the address refused the TCP connection
	RouteNoHost           = "no-host" // relay: no computer in the phone's room
)

// routeReason sorts the error one route of a Dial ended with.
func routeReason(err error) string {
	switch {
	case errors.Is(err, connectsecure.ErrHandshakeClosed):
		return ReasonHandshakeClosed
	case errors.Is(err, connectrelay.ErrNoHost):
		return RouteNoHost
	case errors.Is(err, connectrelay.ErrRelayAnswered):
		return ReasonRelayDown
	case errors.Is(err, syscall.ECONNREFUSED):
		return RouteRefused
	}
	return ReasonNoAnswer // timeouts, no route to the address, DNS, TLS: nothing that is the computer's
}

// dialReason is a Dial's Reason from its routes, and the route that decided it. What the lan route
// says, a refusal or a closed handshake, is weak evidence: anything on the phone's network can hold
// the computer's old lan address (another device, a captive portal, an attacker on the Wi-Fi), so it
// counts only when no other route went unanswered (on a plane, everything else times out).
func dialReason(routes []RouteFailure) (reason, route string) {
	find := func(want string, lan bool) (string, bool) {
		for _, r := range routes {
			if r.Reason == want && (r.Route == connectinvite.RouteLAN) == lan {
				return r.Route, true
			}
		}
		return "", false
	}
	_, unanswered := find(ReasonNoAnswer, false)
	if _, lan := find(ReasonNoAnswer, true); lan {
		unanswered = true
	}
	if t, ok := find(ReasonHandshakeClosed, false); ok {
		return ReasonHandshakeClosed, t
	}
	if t, ok := find(RouteNoHost, false); ok {
		return ReasonRefused, t
	}
	if !unanswered {
		if t, ok := find(ReasonHandshakeClosed, true); ok {
			return ReasonHandshakeClosed, t
		}
		if t, ok := find(RouteRefused, true); ok {
			return ReasonRefused, t
		}
	}
	if t, ok := find(ReasonRelayDown, false); ok {
		return ReasonRelayDown, t
	}
	if len(routes) == 0 {
		return "", ""
	}
	return ReasonNoAnswer, routes[len(routes)-1].Route
}

// LastFailure returns the last failed Dial, if no Dial has succeeded since.
func (s *Session) LastFailure() (DialFailure, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failure == nil {
		return DialFailure{}, false
	}
	return *s.failure, true
}

// dialed records how a Dial ended. A Dial the caller gave up on counts too, its route still trying
// as no-answer: on a network that drops packets, the app's own timeout is all that ends a Dial.
func (s *Session) dialed(err error, routes []RouteFailure) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		s.failure = nil
		return
	}
	f := &DialFailure{Err: err, At: time.Now(), Routes: routes}
	if !errors.Is(err, ErrRevoked) && !errors.Is(err, ErrUnauthorized) && !errors.Is(err, connectsecure.ErrProtoMismatch) {
		f.Reason, f.Route = dialReason(routes)
	} else if len(routes) > 0 {
		f.Route = routes[len(routes)-1].Route
	}
	s.failure = f
}

// Connect prepares a session; nothing goes over the network until the first Dial.
func Connect(link Link, opts Options) (*Session, error) {
	if err := link.validate(); err != nil {
		return nil, err
	}
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	private, _ := parsePrivate(link.Key)
	s := &Session{link: link, opts: opts, private: private}
	s.setClientLocked()
	return s, nil
}

func (s *Session) setClientLocked() {
	if s.client == nil && s.link.Address != "" && s.opts.allows(connectinvite.RouteTailcat) {
		s.client = newClient(s.link.Address, s.private, s.opts.DERPMapURL)
	}
}

// Link is the session's Link with the routes the host sent since Connect; store it again when
// Options.OnLink reports a change.
func (s *Session) Link() Link {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.link
}

func routeKey(r connectinvite.Route) string {
	switch r.T {
	case connectinvite.RouteTailcat:
		return r.T
	case connectinvite.RouteRelay:
		return r.T + " " + r.U
	}
	return r.T + " " + strings.Join(r.A, ",")
}

// usable reports whether the phone may dial route r of a link that pins hostKey: a type Options
// allows, and an opaque relay or an encrypted relay or lan route with the host's key. Tailcat is not
// in Link.Via (Link.Address), and a type this library does not know is never dialed.
func (o Options) usable(r connectinvite.Route, hostKey string) bool {
	if !o.allows(r.T) {
		return false // the phone's preference: the routes the host lists stay unused
	}
	switch {
	case r.T == connectinvite.RouteRelay && r.M == connectinvite.ModeOpaque:
		return true
	case r.T == connectinvite.RouteRelay || r.T == connectinvite.RouteLAN:
		return hostKey != ""
	}
	return false
}

// reachable reports whether l has any route the phone may dial.
func (o Options) reachable(l Link) bool {
	if l.Address != "" && o.allows(connectinvite.RouteTailcat) {
		return true
	}
	return slices.ContainsFunc(l.Via, func(r connectinvite.Route) bool { return o.usable(r, l.HostKey) })
}

// attemptsLocked lists what Dial tries, in order.
func (s *Session) attemptsLocked() []connectinvite.Route {
	var all []connectinvite.Route
	if s.client != nil {
		all = append(all, connectinvite.Route{T: connectinvite.RouteTailcat})
	}
	for _, r := range s.link.Via {
		if s.opts.usable(r, s.link.HostKey) {
			all = append(all, r)
		}
	}
	for i, r := range all {
		if routeKey(r) == s.last && i > 0 {
			return append([]connectinvite.Route{r}, append(all[:i:i], all[i+1:]...)...)
		}
	}
	return all
}

// Dial opens one connection to the host's app, over the first route that answers.
func (s *Session) Dial(ctx context.Context) (_ net.Conn, err error) {
	var tried []RouteFailure
	defer func() { s.dialed(err, tried) }()
	s.mu.Lock()
	revoked, list, start := s.revoked, s.attemptsLocked(), s.last
	s.mu.Unlock()
	if revoked {
		return nil, ErrRevoked
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("%w: no route this library knows", ErrUnreachable)
	}
	var errs []error
	closedOn := false
	for i, r := range list {
		actx, cancel := ctx, context.CancelFunc(func() {})
		if i < len(list)-1 {
			actx, cancel = context.WithTimeout(ctx, perRoute)
		}
		c, err := s.dialRoute(actx, r)
		cancel()
		if err == nil {
			s.mu.Lock()
			if s.last == start || s.last == "" { // not when upgrade moved the session meanwhile
				s.last = routeKey(r)
			}
			s.mu.Unlock()
			s.upgrade(list, r)
			return c, nil
		}
		tried = append(tried, RouteFailure{Route: r.T, Reason: routeReason(err)})
		if errors.Is(err, ErrRevoked) || errors.Is(err, ErrUnauthorized) || errors.Is(err, connectsecure.ErrProtoMismatch) {
			return nil, err
		}
		errs = append(errs, fmt.Errorf("%s: %w", r.T, err))
		closedOn = closedOn || errors.Is(err, connectsecure.ErrHandshakeClosed)
		if ctx.Err() != nil {
			break
		}
	}
	all := errors.Join(errs...)
	if closedOn { // a route answered but closed: say so
		return nil, fmt.Errorf("%w: %w: %v", ErrUnreachable, connectsecure.ErrHandshakeClosed, all)
	}
	return nil, fmt.Errorf("%w: %v", ErrUnreachable, all)
}

// rank orders routes from best to worst: lan, Tailcat (direct, or DERP until magicsock finds a direct
// path), then tailpocket-relay.
func rank(r connectinvite.Route) int {
	switch r.T {
	case connectinvite.RouteLAN:
		return 0
	case connectinvite.RouteTailcat:
		return 1
	}
	return 2
}

// upgrade looks for a better route than cur, the one a Dial just used, so a phone that reached the
// host over DERP or the relay moves to lan once lan answers, and from the relay to Tailcat. It tries in
// the background, each route for at most upgradeTry, at most once per upgradeRetry. The connections
// already open stay where they are: a replaced encrypted session drains (connectsecure
// Session.Drain); the next Dial takes the better route. When the phone leaves that network, its lan
// session stalls and the next Dial starts again from Tailcat.
func (s *Session) upgrade(list []connectinvite.Route, cur connectinvite.Route) {
	var better []connectinvite.Route
	for _, r := range list {
		if rank(r) < rank(cur) {
			better = append(better, r)
		}
	}
	if len(better) == 0 || testhook.NoUpgrade.Load() {
		return
	}
	slices.SortStableFunc(better, func(a, b connectinvite.Route) int { return rank(a) - rank(b) })
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || time.Since(s.upTry) < upgradeRetry || s.last != routeKey(cur) {
		return
	}
	s.upTry = time.Now()
	go func() {
		for _, r := range better {
			ctx, cancel := context.WithTimeout(context.Background(), upgradeTry)
			err := s.probe(ctx, r)
			cancel()
			if err != nil {
				continue
			}
			s.mu.Lock()
			if s.last == routeKey(cur) {
				s.last = routeKey(r)
			}
			s.mu.Unlock()
			return
		}
	}()
}

// probe checks that route r reaches the host without opening a connection to the app: an encrypted
// route starts its session (which the next Dial uses), Tailcat opens and closes a connection to the
// host's control port.
func (s *Session) probe(ctx context.Context, r connectinvite.Route) error {
	if r.T != connectinvite.RouteTailcat {
		_, err := s.secure(ctx, r)
		return err
	}
	s.mu.Lock()
	client := s.client
	s.mu.Unlock()
	c, err := client.DialTCPPort(ctx, connectinvite.ControlPort)
	if err != nil {
		return err
	}
	return c.Close()
}

func (s *Session) dialRoute(ctx context.Context, r connectinvite.Route) (net.Conn, error) {
	if r.T == connectinvite.RouteTailcat {
		s.mu.Lock()
		client, port := s.client, uint16(s.link.Port)
		s.mu.Unlock()
		c, err := client.DialTCPPort(ctx, port)
		if err != nil {
			// Tailcat returns a failed dial as a nil *gonet.TCPConn inside a non-nil net.Conn
			// (tailcat v0.6.0, tailcat.go:1895), whose Close panics.
			return nil, err
		}
		return c, nil
	}
	if r.T == connectinvite.RouteRelay && r.M == connectinvite.ModeOpaque {
		return connectrelay.DialPhone(ctx, r.U, r.R, s.opts.HTTPClient)
	}
	sess, err := s.secure(ctx, r)
	if err != nil {
		return nil, err
	}
	c, err := sess.Open()
	if err != nil && sess.Err() != nil {
		// The session ended between secure and Open (the host closed it): start a new one once.
		if sess, err = s.secure(ctx, r); err != nil {
			return nil, err
		}
		return sess.Open()
	}
	return c, err
}

// secure returns the encrypted session on route r, starting one if none is live.
func (s *Session) secure(ctx context.Context, r connectinvite.Route) (*connectsecure.Session, error) {
	// A live session on r needs no secMu: a Dial must not wait behind another route's handshake
	// (an upgrade probe of a lan address that never answers).
	s.mu.Lock()
	live, liveKey := s.sec, s.secKey
	s.mu.Unlock()
	if live != nil && liveKey == routeKey(r) && live.Err() == nil {
		return live, nil
	}
	s.secMu.Lock()
	defer s.secMu.Unlock()
	s.mu.Lock()
	cur, curKey, hostKey := s.sec, s.secKey, s.link.HostKey
	s.mu.Unlock()
	if cur != nil && curKey == routeKey(r) {
		select {
		case <-cur.Done():
		default:
			return cur, nil
		}
	}
	server, ok := decodeKey(hostKey)
	if !ok {
		return nil, errors.New("connectphone: no host key for this route")
	}
	raw, err := dialRaw(ctx, r, s.opts.HTTPClient)
	if err != nil {
		return nil, err
	}
	sess, err := dialSecure(ctx, raw, connectsecure.ClientConfig{Static: noiseKeys(s.private), Server: server,
		Phone: s.private.Public().String(), Version: Version})
	if err != nil {
		if errors.Is(err, connectsecure.ErrUnpaired) {
			s.mu.Lock()
			s.revoked = true
			s.mu.Unlock()
			return nil, ErrRevoked
		}
		if errors.Is(err, connectsecure.ErrDenied) {
			return nil, ErrUnauthorized
		}
		return nil, err
	}
	s.mu.Lock()
	if s.closed { // Close ran during the handshake (a background upgrade)
		s.mu.Unlock()
		_ = sess.Close()
		return nil, net.ErrClosed
	}
	old := s.sec
	s.sec, s.secKey = sess, routeKey(r)
	if old != nil {
		s.drained = slices.DeleteFunc(s.drained, func(d *connectsecure.Session) bool { return d.Err() != nil })
		s.drained = append(s.drained, old)
	}
	s.mu.Unlock()
	if old != nil {
		old.Drain() // its open connections go on; it closes when the last one ends
	}
	go s.watch(sess)
	return sess, nil
}

// watch reads the host's control messages: new routes, and a bye.
func (s *Session) watch(sess *connectsecure.Session) {
	for {
		m, err := sess.Control().Recv()
		if err != nil {
			if errors.Is(err, connectsecure.ErrStalled) { // that path went silent: try the others first
				s.mu.Lock()
				if s.sec == sess && s.last == s.secKey {
					s.last = ""
				}
				s.mu.Unlock()
			}
			return
		}
		switch m["type"] {
		case "routes":
			via, ok := routesOf(m)
			if !ok {
				continue
			}
			s.mu.Lock()
			next := s.link
			next.setRoutes(via)
			if s.opts.TailcatOnly {
				next.Via = nil
			}
			if !s.opts.reachable(next) && s.opts.reachable(s.link) {
				// The host has no route for this phone right now: a host without Tailcat whose lan
				// address is gone, or one left with only route types the phone does not use. Keep the
				// routes the phone has. With none it could not come back when the address does (nothing
				// but a route carries the next list), its Link would no longer validate, and it would
				// have to pair again. A stale route is harmless: every dial runs the Noise handshake with
				// the pinned host key.
				s.mu.Unlock()
				continue
			}
			s.link = next
			s.setClientLocked()
			link := s.link
			s.mu.Unlock()
			if s.opts.OnLink != nil {
				s.opts.OnLink(link)
			}
		case "bye":
			// A bye is the host's last word on this session: end it now rather than when the
			// transport's own close arrives, so the next Dial starts a new session.
			if m["code"] == "unpaired" {
				s.mu.Lock()
				s.revoked = true
				s.mu.Unlock()
			}
			_ = sess.Close()
			return
		case "push-ack":
			s.deliverAck(m)
		}
	}
}

func routesOf(m map[string]any) ([]connectinvite.Route, bool) {
	b, _ := json.Marshal(m["via"])
	var via []connectinvite.Route
	if json.Unmarshal(b, &via) != nil || connectinvite.ValidateRoutes(via) != nil {
		return nil, false
	}
	return via, true
}

// dialRaw opens the byte pipe of an encrypted route.
func dialRaw(ctx context.Context, r connectinvite.Route, client *http.Client) (net.Conn, error) {
	if r.T == connectinvite.RouteRelay {
		return connectrelay.DialPhone(ctx, r.U, r.R, client)
	}
	d := net.Dialer{Timeout: lanDial}
	var last error
	for _, a := range r.A {
		c, err := d.DialContext(ctx, "tcp", a)
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, last
}

// dialSecure is connectsecure.Dial that also gives up when ctx ends.
func dialSecure(ctx context.Context, raw net.Conn, cfg connectsecure.ClientConfig) (*connectsecure.Session, error) {
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	return connectsecure.Dial(raw, cfg)
}

func decodeKey(s string) ([32]byte, bool) {
	var k [32]byte
	if !connectinvite.ValidKey(s) {
		return k, false
	}
	b, _ := base64.RawURLEncoding.DecodeString(s)
	copy(k[:], b)
	return k, true
}

// Revoked reports whether the host said, encrypted, that this phone is no longer paired. Delete the
// link: no route will take it again.
func (s *Session) Revoked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revoked
}

// Forward starts a loopback listener whose every connection is a new Dial.
func (s *Session) Forward() (*Forward, error) {
	return startForward(func(ctx context.Context) (net.Conn, error) {
		// A dial the host never answers must still end, so the app's connection closes: 20 s, as in
		// v0.2, or perRoute for each route when there are more.
		s.mu.Lock()
		n := len(s.attemptsLocked())
		s.mu.Unlock()
		ctx, cancel := context.WithTimeout(ctx, max(20*time.Second, time.Duration(n)*perRoute))
		defer cancel()
		return s.Dial(ctx)
	})
}

// Close ends the session's Tailcat client and its encrypted session.
func (s *Session) Close() error {
	s.mu.Lock()
	client, sec, drained := s.client, s.sec, s.drained
	s.sec, s.drained, s.closed = nil, nil, true
	s.mu.Unlock()
	if sec != nil {
		_ = sec.Close()
	}
	for _, d := range drained {
		_ = d.Close()
	}
	if client != nil {
		return closing.Within(client.Close)
	}
	return nil
}

// Route kinds: how a Session reaches its host.
const (
	KindLAN    = "lan"    // the host's lan listener, Noise over TCP
	KindDirect = "direct" // Tailcat, peer to peer (WireGuard over UDP)
	KindDERP   = "derp"   // Tailcat through one of its DERP relays
	KindRelay  = "relay"  // tailpocket-relay
)

// Route says how the session reaches the host now.
type Route struct {
	Kind string
	// Kind derp: the DERP region's ID, its code ("" when the Tailcat address carries the region without
	// one; tailcat then makes up the ID as the code), and the host name of its first DERP server when the
	// address carries the region.
	DERPRegion int
	DERPCode   string
	DERPHost   string
	// Kind relay: the tailpocket-relay's host name.
	RelayHost string
}

// Route reports how the session reaches the host. For Tailcat it sends a disco ping and waits for the
// pong, which also nudges the client to look for a direct path (tailcat v0.6.0 Client.DiscoPing).
func (s *Session) Route(ctx context.Context) (Route, error) {
	s.mu.Lock()
	last, client, address := s.last, s.client, s.link.Address
	s.mu.Unlock()
	switch {
	case strings.HasPrefix(last, connectinvite.RouteRelay+" "):
		return Route{Kind: KindRelay, RelayHost: connectrelay.NormalizeHost(strings.TrimPrefix(last, connectinvite.RouteRelay+" "))}, nil
	case strings.HasPrefix(last, connectinvite.RouteLAN+" "):
		return Route{Kind: KindLAN}, nil
	case client == nil:
		return Route{}, ErrUnreachable
	}
	res, err := client.DiscoPing(ctx)
	return routeOf(res, err, address)
}

// Path is Route as before v0.3.1 (Route.Path).
func (s *Session) Path(ctx context.Context) (route, relay string, err error) {
	r, err := s.Route(ctx)
	if err != nil {
		return "", "", err
	}
	route, relay = r.Path()
	return route, relay, nil
}

// Path is r the way Session.Path reported it before v0.3.1: "direct"; "relay" with the
// tailpocket-relay's host name, or with the DERP region's code, its server's host name, or
// "tailcat-derp" (never "" since v0.3.1); or "lan".
func (r Route) Path() (route, relay string) {
	switch r.Kind {
	case KindDERP:
		return "relay", cmp.Or(r.DERPCode, r.DERPHost, "tailcat-derp")
	case KindRelay:
		return "relay", r.RelayHost
	}
	return r.Kind, ""
}

// routeOf reads a pong: it came over a direct path if it names an endpoint, otherwise through DERP.
func routeOf(res *ipnstate.PingResult, err error, address string) (Route, error) {
	if err != nil {
		return Route{}, err
	}
	if res.Err != "" {
		return Route{}, errors.New("connectphone: " + res.Err)
	}
	if res.Endpoint != "" {
		return Route{Kind: KindDirect}, nil
	}
	r := Route{Kind: KindDERP, DERPRegion: int(res.DERPRegionID), DERPCode: res.DERPRegionCode}
	if r.DERPCode == strconv.Itoa(r.DERPRegion) {
		r.DERPCode = "" // made up by tailcat.ParseAddr (tailcat v0.6.0 tailcat.go:1089)
	}
	if ci, err := tailcat.ParseAddr(tailcat.Addr(address)); err == nil {
		for _, reg := range ci.Region {
			if int(reg.RegionID) == r.DERPRegion && len(reg.Nodes) > 0 {
				r.DERPHost = reg.Nodes[0].HostName
			}
		}
	}
	return r, nil
}

// controlHTTP speaks HTTP to the host's control port over Tailcat.
func controlHTTP(client *tailcat.Client) *http.Client {
	return &http.Client{Transport: &http.Transport{DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			c, err := client.DialTCPPort(ctx, connectinvite.ControlPort)
			if err != nil {
				return nil, err // never a nil *gonet.TCPConn inside a net.Conn (see dialRoute)
			}
			return c, nil
		}}}
}

// Sync registers the phone's Noise key with the host over Tailcat and takes the host's key and
// routes. A phone paired before v0.3 calls it once to use the encrypted routes without a new QR; it
// is also how a phone learns routes the host added. A host older than v0.3 does not answer.
func (s *Session) Sync(ctx context.Context) (Link, error) {
	s.mu.Lock()
	client, link := s.client, s.link
	s.mu.Unlock()
	if s.opts.TailcatOnly {
		return link, nil // nothing to register: the phone uses no route the key is for
	}
	if client == nil {
		if link.HostKey != "" {
			// No Tailcat (the host's routes or Options.Routes leave it out): the key was registered at
			// pairing, and new routes come on every encrypted session.
			return link, nil
		}
		return Link{}, errors.New("connectphone: this link has no Tailcat route")
	}
	httpClient := controlHTTP(client)
	type syncReply struct {
		V   int                   `json:"v"`
		PK  string                `json:"pk"`
		Via []connectinvite.Route `json:"via"`
	}
	post := func(body map[string]string) (syncReply, error) {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://control.invalid/v2/sync", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		resp, err := httpClient.Do(req)
		if err != nil {
			return syncReply{}, fmt.Errorf("%w: %v", ErrUnreachable, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK { // never ErrRevoked: only the encrypted bye unpairs
			return syncReply{}, fmt.Errorf("connectphone: host answered %d", resp.StatusCode)
		}
		var r syncReply
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		if json.Unmarshal(data, &r) != nil || r.V != 2 || !connectinvite.ValidKey(r.PK) || connectinvite.ValidateRoutes(r.Via) != nil {
			return syncReply{}, errors.New("connectphone: invalid host reply")
		}
		return r, nil
	}
	// The proof is keyed with the host's Noise key: a link from before v0.3 asks for it first. Tailcat
	// already authenticates the host, so the key that comes back is the host's.
	s.mu.Lock()
	pk := s.link.HostKey
	s.mu.Unlock()
	if pk == "" {
		r, err := post(map[string]string{})
		if err != nil {
			return Link{}, err
		}
		pk = r.PK
	}
	proof, err := noiseProof(s.private, pk)
	if err != nil {
		return Link{}, err
	}
	r, err := post(map[string]string{"noise": noisePublic(s.private), "proof": proof})
	if err != nil {
		return Link{}, err
	}
	s.mu.Lock()
	s.link.HostKey = r.PK
	s.link.setRoutes(r.Via)
	link = s.link
	s.mu.Unlock()
	if s.opts.OnLink != nil {
		s.opts.OnLink(link)
	}
	return link, nil
}

// PairV2 pairs from a v2 invite (or a v1 invite read with DecodeV2) over the first route that works:
// the Tailcat window, or an encrypted relay or lan route. Every route redeems the same window.
func PairV2(ctx context.Context, inv connectinvite.V2, phoneKey string, opts Options) (Link, error) {
	if err := inv.Validate(); err != nil {
		return Link{}, err
	}
	private, err := parsePrivate(phoneKey)
	if err != nil {
		return Link{}, err
	}
	if inv.Expired(time.Now()) {
		return Link{}, ErrExpired
	}
	if err := opts.Validate(); err != nil {
		return Link{}, err
	}
	if inv.PK == "" {
		// A v1 code read as v2 (one Tailcat route, no Noise key): pair the v1 way, as v0.2 did. A host
		// that wants the emoji check hands out v2 codes, which always name its key.
		for _, r := range inv.Via {
			if r.T == connectinvite.RouteTailcat && r.Inv != nil {
				return Pair(ctx, *r.Inv, phoneKey, opts)
			}
		}
		return Link{}, fmt.Errorf("%w: no route to pair over", ErrUnreachable)
	}
	if opts.OnSAS == nil {
		return Link{}, ErrNoSAS
	}
	ctx, cancel := context.WithDeadline(ctx, time.Unix(inv.ExpiresAt, 0))
	defer cancel()
	var list []connectinvite.Route
	for _, r := range inv.Via {
		tailcatOK := r.T == connectinvite.RouteTailcat && r.Inv != nil && r.Inv.Validate() == nil
		if !opts.allows(r.T) {
			continue
		}
		if tailcatOK || r.T == connectinvite.RouteLAN || (r.T == connectinvite.RouteRelay && r.M != connectinvite.ModeOpaque) {
			list = append(list, r)
		}
	}
	if len(list) == 0 {
		return Link{}, fmt.Errorf("%w: no route to pair over", ErrUnreachable)
	}
	var errs []error
	for i, r := range list {
		actx, acancel := ctx, context.CancelFunc(func() {})
		if i < len(list)-1 {
			actx, acancel = context.WithTimeout(ctx, 30*time.Second)
		}
		// Every route runs the same Noise pairing, Tailcat's inside the window's one-time node, so
		// every route shows the emoji and proves the nodekey.
		l, err := pairSecure(actx, inv, r, private, phoneKey, opts)
		acancel()
		if err == nil {
			return l, nil
		}
		if errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrTaken) {
			return Link{}, err
		}
		errs = append(errs, fmt.Errorf("%s: %w", r.T, err))
		if ctx.Err() != nil {
			break
		}
	}
	if !time.Now().Before(time.Unix(inv.ExpiresAt, 0)) {
		return Link{}, ErrExpired
	}
	return Link{}, fmt.Errorf("%w: %v", ErrUnreachable, errors.Join(errs...))
}

// pairSecure pairs over one encrypted route: Noise IKpsk2 with the code's psk, then the host's paired
// message and its routes. It tries again while the route is up but the host is busy.
func pairSecure(ctx context.Context, inv connectinvite.V2, r connectinvite.Route, private key.NodePrivate, phoneKey string, opts Options) (Link, error) {
	server, _ := decodeKey(inv.PK)
	cfg := connectsecure.ClientConfig{Static: noiseKeys(private), Server: server, Version: Version,
		Pair:   &connectsecure.PairHello{CID: connectsecure.CIDFor(inv.PSK), PSK: connectsecure.PSKFor(inv.PSK)},
		Device: connectinvite.CleanName(opts.Device), Phone: private.Public().String(), Prove: nodekeyProof(private, server),
		OnSAS: opts.OnSAS}
	shown := false
	show := cfg.OnSAS
	cfg.OnSAS = func(e []string) { shown = true; show(e) }
	for {
		l, err := pairOnce(ctx, r, cfg, inv, phoneKey, opts)
		// Once the emoji were up, the computer's user decided (or the connection broke and the
		// computer ended the window): trying again would only show a stranger's.
		if err == nil || errors.Is(err, ErrUnauthorized) || shown {
			if err != nil && shown && !errors.Is(err, ErrUnauthorized) {
				err = fmt.Errorf("%w: %v", ErrUnauthorized, err)
			}
			return l, err
		}
		select {
		case <-ctx.Done():
			return Link{}, err
		case <-time.After(time.Second):
		}
	}
}

func pairOnce(ctx context.Context, r connectinvite.Route, cfg connectsecure.ClientConfig, inv connectinvite.V2, phoneKey string, opts Options) (Link, error) {
	var raw net.Conn
	var err error
	if r.T == connectinvite.RouteTailcat {
		var oneTime key.NodePrivate
		if oneTime.UnmarshalText([]byte(r.Inv.Key)) != nil {
			return Link{}, errors.New("connectphone: invalid invite")
		}
		client := newClient(r.Inv.Address, oneTime, opts.DERPMapURL)
		defer closing.Within(client.Close)
		raw, err = client.DialTCPPort(ctx, uint16(r.Inv.Port))
	} else {
		raw, err = dialRaw(ctx, r, opts.HTTPClient)
	}
	if err != nil {
		return Link{}, err
	}
	sess, err := dialSecure(ctx, raw, cfg)
	if err != nil {
		if errors.Is(err, connectsecure.ErrDenied) {
			return Link{}, ErrUnauthorized // wrong code, used, expired or another phone's
		}
		return Link{}, err
	}
	defer sess.Close()
	stop := context.AfterFunc(ctx, func() { sess.Close() })
	defer stop()
	l := Link{Key: phoneKey, HostKey: inv.PK, Name: inv.Name}
	gotPaired := false
	for {
		m, err := sess.Control().Recv()
		if err != nil {
			return Link{}, err
		}
		switch m["type"] {
		case "paired":
			if m["phone"] != cfg.Phone {
				return Link{}, errors.New("connectphone: the host paired another phone")
			}
			name, _ := m["name"].(string)
			payload, _ := m["payload"].(string)
			if connectinvite.ValidName(name) {
				l.Name = name
			}
			l.Payload, gotPaired = payload, true
		case "routes":
			via, ok := routesOf(m)
			if !gotPaired || !ok {
				return Link{}, errors.New("connectphone: invalid host reply")
			}
			l.setRoutes(via)
			if opts.TailcatOnly {
				l.Via = nil
			}
			if len(l.Via) == 0 && l.Address == "" && r.T != connectinvite.RouteTailcat {
				l.Via = []connectinvite.Route{r}
			}
			return l, l.validate()
		}
	}
}
