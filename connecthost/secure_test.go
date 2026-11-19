package connecthost

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/curve25519"
	"tailscale.com/types/key"

	"github.com/jt-wang/tailpocket/connectinvite"
	"github.com/jt-wang/tailpocket/connectphone"
	"github.com/jt-wang/tailpocket/connectrelay"
	"github.com/jt-wang/tailpocket/connectsecure"
)

const (
	relayToken = "relay-token-for-tests-only"
	marker     = "plaintext-marker-5b1d"
)

func startRelay(t *testing.T) string {
	t.Helper()
	srv, err := connectrelay.NewServer(connectrelay.Config{Token: relayToken, PublicHost: "127.0.0.1", Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(func() { srv.Close(); ts.Close() })
	return "ws" + strings.TrimPrefix(ts.URL, "http")
}

// wire records every byte a phone sends and receives on its TCP connections to the relay.
// With silent set, it acts like Wi-Fi that went away without a FIN: writes still succeed, nothing
// comes back, and new connections fail.
type wire struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	silent atomic.Bool
}

func (w *wire) client() *http.Client {
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, n, a string) (net.Conn, error) {
		if w.silent.Load() {
			return nil, errors.New("network is unreachable")
		}
		c, err := (&net.Dialer{}).DialContext(ctx, n, a)
		if err != nil {
			return nil, err
		}
		return &taped{Conn: c, w: w}, nil
	}}}
}

func (w *wire) has(s string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return bytes.Contains(w.buf.Bytes(), []byte(s))
}

func (w *wire) len() int { w.mu.Lock(); defer w.mu.Unlock(); return w.buf.Len() }

type taped struct {
	net.Conn
	w *wire
}

func (c *taped) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	for err == nil && c.w.silent.Load() {
		n, err = c.Conn.Read(p) // dropped
	}
	c.w.mu.Lock()
	c.w.buf.Write(p[:n])
	c.w.mu.Unlock()
	return n, err
}

func (c *taped) Write(p []byte) (int, error) {
	if c.w.silent.Load() {
		return len(p), nil
	}
	c.w.mu.Lock()
	c.w.buf.Write(p)
	c.w.mu.Unlock()
	return c.Conn.Write(p)
}

// serveApp answers every connection the host hands over with the phone it came from and marker.
func serveApp(t *testing.T, h *Host) {
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Context().Value(phoneCtxKey{}).(string)+" "+marker)
	}), ConnContext: func(ctx context.Context, c net.Conn) context.Context {
		return context.WithValue(ctx, phoneCtxKey{}, PhoneOf(c))
	}}
	go srv.Serve(h.Listener())
	t.Cleanup(func() { srv.Close() })
}

func get(t *testing.T, s *connectphone.Session) (string, error) {
	t.Helper()
	// Long enough for a route that times out (the fake Tailcat address answers nothing) and the next.
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	c, err := s.Dial(ctx)
	if err != nil {
		return "", err
	}
	defer c.Close()
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return "", err
	}
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

func waitRelay(t *testing.T, h *Host) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		ok := true
		for _, err := range h.RelayStatus() {
			ok = ok && err == nil
		}
		if ok {
			return
		}
	}
	t.Fatalf("relay not registered: %v", h.RelayStatus())
}

// relayOnly is the invite with only its relay route, so the phone cannot pair over the fake Tailcat.
func relayOnly(inv connectinvite.V2) connectinvite.V2 {
	var via []connectinvite.Route
	for _, r := range inv.Via {
		if r.T == connectinvite.RouteRelay {
			via = append(via, r)
		}
	}
	inv.Via = via
	return inv
}

// pairOverRelay pairs a new phone through the relay and returns its session, with the fake Tailcat
// address taken out of its link so every Dial goes through the relay.
func pairOverRelay(t *testing.T, h *Host, w *wire, payload string) (*connectphone.Session, connectphone.Link) {
	t.Helper()
	p, err := h.Pair(context.Background(), PairOptions{Payload: func(ph Phone) (string, error) {
		if ph.Route != RouteRelay {
			t.Errorf("pairing route %q", ph.Route)
		}
		return payload, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	phoneKey := connectphone.NewKey()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	link, err := connectphone.PairV2(ctx, relayOnly(p.InviteV2()), phoneKey, connectphone.Options{Device: "Test Phone", HTTPClient: w.client()})
	if err != nil {
		t.Fatalf("pair over relay: %v", err)
	}
	if link.Payload != payload || link.HostKey == "" || link.Address == "" {
		t.Fatalf("link %+v", link)
	}
	link.Address, link.Port = "", 0
	s, err := connectphone.Connect(link, connectphone.Options{HTTPClient: w.client()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, link
}

func TestPairAndConnectOverRelay(t *testing.T) {
	url := startRelay(t)
	h, _, saved := newTestHost(t, Config{Relays: []Relay{{URL: url, Token: relayToken}}})
	waitRelay(t, h)
	serveApp(t, h)
	w := &wire{}
	s, link := pairOverRelay(t, h, w, "app-token-secret-7")
	pub, _ := connectphone.PublicKey(link.Key)

	body, err := get(t, s)
	if err != nil || body != pub+" "+marker {
		t.Fatalf("over the relay: %q %v", body, err)
	}
	if route, relay, _ := s.Path(context.Background()); route != "relay" || relay != "127.0.0.1" {
		t.Fatalf("path %q %q", route, relay)
	}
	if w.has(marker) || w.has("app-token-secret-7") || w.has(pub) || w.len() == 0 {
		t.Fatalf("the relay saw plaintext (%d bytes recorded)", w.len())
	}
	if st := saved.last(); st.Keys[pub] == "" {
		t.Fatalf("the phone's Noise key was not saved: %+v", st)
	}
}

// The same relay in opaque mode passes the app's bytes as they are: with plain bytes the marker is
// visible (the recording check works), with the app's own TLS it is not.
func TestOpaqueRelay(t *testing.T) {
	url := startRelay(t)
	h, _, _ := newTestHost(t, Config{Relays: []Relay{{URL: url, Token: relayToken, Opaque: true}}})
	waitRelay(t, h)
	routes := h.Routes()
	if len(routes) != 1 || routes[0].M != connectinvite.ModeOpaque {
		t.Fatalf("routes %+v", routes)
	}
	app := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, marker) }))
	app.StartTLS()
	defer app.Close()
	go func() { // the app: plain bytes on one connection, TLS on the rest
		first := true
		for {
			c, err := h.Listener().Accept()
			if err != nil {
				return
			}
			if PhoneOf(c) != "" {
				t.Error("an opaque connection named a phone")
			}
			if first {
				first = false
				go func() { io.WriteString(c, marker); c.Close() }()
				continue
			}
			go func() {
				d, _ := net.Dial("tcp", app.Listener.Addr().String())
				go io.Copy(d, c)
				io.Copy(c, d)
			}()
		}
	}()
	link := connectphone.Link{Name: "Mac", Key: connectphone.NewKey(), Via: routes}
	plain, cipher := &wire{}, &wire{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, _ := connectphone.Connect(link, connectphone.Options{HTTPClient: plain.client()})
	c, err := s.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(c)
	c.Close()
	if !plain.has(marker) {
		t.Fatal("control: plain bytes were not visible on the relay")
	}
	s2, _ := connectphone.Connect(link, connectphone.Options{HTTPClient: cipher.client()})
	pool := x509.NewCertPool()
	pool.AddCert(app.Certificate())
	raw, err := s2.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(raw, &tls.Config{RootCAs: pool, ServerName: "example.com"})
	io.WriteString(tc, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if string(b) != marker || cipher.has(marker) {
		t.Fatalf("body %q, marker on the relay: %v", b, cipher.has(marker))
	}
}

// A phone paired over Tailcat before v0.3 registers its Noise key on the control port, then reaches
// the host over the relay: no new QR.
func TestOldPhoneMovesToRelayWithoutPairing(t *testing.T) {
	url := startRelay(t)
	k, phone := phoneKey(t)
	h, f, saved := newTestHost(t, Config{Allowed: []string{phone}, Relays: []Relay{{URL: url, Token: relayToken}}})
	waitRelay(t, h)
	serveApp(t, h)
	main := f.live(DefaultPort)
	privText, _ := k.MarshalText()

	// The phone's Noise key, as connectphone derives it: register it over Tailcat's control port.
	noise := noisePublicOf(k)
	body := syncBody(h, k, phone, noise)
	req, _ := http.NewRequest(http.MethodPost, "http://control.invalid/v2/sync", bytes.NewReader(body))
	resp, err := controlClient(main, phone).Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("sync: %v %v", resp, err)
	}
	var reply struct {
		PK  string                `json:"pk"`
		Via []connectinvite.Route `json:"via"`
	}
	json.NewDecoder(resp.Body).Decode(&reply)
	if saved.last().Keys[phone] != noise {
		t.Fatal("Noise key not saved")
	}
	var relayRoute connectinvite.Route
	for _, r := range reply.Via {
		if r.T == connectinvite.RouteRelay {
			relayRoute = r
		}
	}
	w := &wire{}
	s, _ := connectphone.Connect(connectphone.Link{Name: "Mac", Key: string(privText), HostKey: reply.PK,
		Via: []connectinvite.Route{relayRoute}}, connectphone.Options{HTTPClient: w.client()})
	defer s.Close()
	got, err := get(t, s)
	if err != nil || got != phone+" "+marker {
		t.Fatalf("old phone over the relay: %q %v", got, err)
	}

	// A phone not paired gets nothing on the control port.
	_, stranger := phoneKey(t)
	req, _ = http.NewRequest(http.MethodPost, "http://control.invalid/v2/sync", bytes.NewReader(body))
	if resp, err := controlClient(main, stranger).Do(req); err == nil && resp.StatusCode == http.StatusOK {
		t.Fatal("an unknown phone synced")
	}
}

func TestRevokeOverRelay(t *testing.T) {
	url := startRelay(t)
	var events []Event
	var mu sync.Mutex
	h, _, _ := newTestHost(t, Config{Relays: []Relay{{URL: url, Token: relayToken}},
		Audit: func(e Event) { mu.Lock(); events = append(events, e); mu.Unlock() }})
	waitRelay(t, h)
	serveApp(t, h)
	w := &wire{}
	a, linkA := pairOverRelay(t, h, w, "a")
	b, _ := pairOverRelay(t, h, w, "b")
	if _, err := get(t, a); err != nil {
		t.Fatal(err)
	}
	if _, err := get(t, b); err != nil {
		t.Fatal(err)
	}
	// An open stream of a, and one of b.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ca, _ := a.Dial(ctx)
	cb, _ := b.Dial(ctx)
	defer cb.Close()
	pubA, _ := connectphone.PublicKey(linkA.Key)
	if err := h.Revoke(ctx, pubA); err != nil {
		t.Fatal(err)
	}
	ca.SetReadDeadline(time.Now().Add(5 * time.Second))
	var ne net.Error
	if _, err := ca.Read(make([]byte, 1)); err == nil || errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("revoked phone's open stream: %v", err)
	}
	// A Dial racing the bye may get a stream that then fails; none may succeed, and the phone ends
	// at ErrRevoked once it has read the bye.
	var err error
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		var body string
		if body, err = get(t, a); err == nil {
			t.Fatalf("revoked phone got %q", body)
		}
		if errors.Is(err, connectphone.ErrRevoked) {
			break
		}
	}
	if !errors.Is(err, connectphone.ErrRevoked) {
		t.Fatalf("revoked phone dials: %v, want ErrRevoked", err)
	}
	// A new session with the revoked key is turned away with bye unpaired, too.
	fresh, _ := connectphone.Connect(linkA, connectphone.Options{HTTPClient: w.client()})
	defer fresh.Close()
	if _, err := get(t, fresh); !errors.Is(err, connectphone.ErrRevoked) {
		t.Fatalf("revoked phone, new session: %v, want ErrRevoked", err)
	}
	// b kept its open stream.
	io.WriteString(cb, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	cb.SetReadDeadline(time.Now().Add(5 * time.Second))
	if resp, err := http.ReadResponse(bufio.NewReader(cb), nil); err != nil || resp.StatusCode != 200 {
		t.Fatalf("other phone's stream after the revoke: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	kinds := map[string]bool{}
	for _, e := range events {
		kinds[e.Kind] = true
	}
	if !kinds[EventPaired] || !kinds[EventRevoked] || !kinds[EventConnOpen] || !kinds[EventDenied] {
		t.Fatalf("audit events %v", kinds)
	}
}

func TestAuthorizeDenies(t *testing.T) {
	url := startRelay(t)
	var deny sync.Map
	h, _, _ := newTestHost(t, Config{Relays: []Relay{{URL: url, Token: relayToken}},
		Authorize: func(phone, route string) error {
			if _, ok := deny.Load(phone); ok {
				return errors.New("signed out")
			}
			return nil
		}})
	waitRelay(t, h)
	serveApp(t, h)
	s, link := pairOverRelay(t, h, &wire{}, "x")
	if _, err := get(t, s); err != nil {
		t.Fatal(err)
	}
	pub, _ := connectphone.PublicKey(link.Key)
	deny.Store(pub, true)
	h.Disconnect(pub)
	// The phone ends its session on the host's bye; until that arrives a Dial may still use it.
	var err error
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if _, err = get(t, s); errors.Is(err, connectphone.ErrUnauthorized) {
			break
		}
	}
	if !errors.Is(err, connectphone.ErrUnauthorized) {
		t.Fatalf("denied phone: %v, want ErrUnauthorized", err)
	}
	deny.Delete(pub)
	if _, err := get(t, s); err != nil {
		t.Fatalf("allowed again: %v", err)
	}
}

// A state from before v0.3 gets its Noise and relay keys once, saved before any phone sees them; a
// restart keeps them, so the room and the pinned key stay the same.
func TestOldStateGetsKeysOnce(t *testing.T) {
	old := newIdentity()
	old.noise, old.relay = [32]byte{}, nil
	_, phone := phoneKey(t)
	h, _, saved := newTestHost(t, Config{Identity: old.String(), Allowed: []string{phone}})
	st := saved.last()
	id, err := parseIdentity(st.Identity)
	if err != nil || id.noise == ([32]byte{}) || id.relay == nil || id.key.Public() != old.key.Public() || id.psk != old.psk {
		t.Fatalf("saved identity: %v", err)
	}
	if len(st.Allowed) != 1 || st.Allowed[0] != phone {
		t.Fatal("phones lost")
	}
	room := connectrelay.RoomFor(id.relayPublic())
	h.Close()
	h2, _, saved2 := newTestHost(t, Config{Identity: st.Identity, Allowed: st.Allowed, Keys: st.Keys})
	for _, again := range saved2.states { // starting the main node saves the state; it must not change
		if again.Identity != st.Identity {
			t.Fatal("a v0.3 identity changed at start")
		}
	}
	if connectrelay.RoomFor(h2.id.relayPublic()) != room || h2.id.noisePublic() != id.noisePublic() {
		t.Fatal("keys changed across a restart")
	}
}

func controlClient(n *fakeNode, phone string) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			c, s := net.Pipe()
			go n.spec.onTCP(DefaultControlPort)(&addrConn{Conn: s, remote: &net.TCPAddr{IP: clientIP(mustPhone(phone)).AsSlice(), Port: 40000}})
			return c, nil
		}}}
}

func mustPhone(phone string) key.NodePublic {
	var k key.NodePublic
	if err := k.UnmarshalText([]byte(phone)); err != nil {
		panic(err)
	}
	return k
}

// noisePublicOf derives a phone's Noise public key from its Tailcat key the way PROTOCOL.md says:
// X25519(SHA-256("tailpocket2 noise key\n" || raw private key)).
// syncBody is a /v2/sync request reporting noise for phone, with a proof signed by signer's Noise
// key: the phone's own key for a real sync, another one for a forged claim.
func syncBody(h *Host, signer key.NodePrivate, phone, noise string) []byte {
	raw := signer.Raw32()
	priv := sha256.Sum256(append([]byte("tailpocket2 noise key\n"), raw[:]...))
	proof, err := connectsecure.KeyProof(priv[:], h.id.noisePublic(), connectinvite.ProofNoise, connectinvite.NoiseClaim(phone, noise))
	if err != nil {
		panic(err)
	}
	body, _ := json.Marshal(map[string]string{"noise": noise, "proof": base64.RawURLEncoding.EncodeToString(proof)})
	return body
}

func noisePublicOf(k key.NodePrivate) string {
	raw := k.Raw32()
	priv := sha256.Sum256(append([]byte("tailpocket2 noise key\n"), raw[:]...))
	pub, _ := curve25519.X25519(priv[:], curve25519.Basepoint)
	return base64.RawURLEncoding.EncodeToString(pub)
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// When the relay goes away, a paired phone's next connection takes the lan route.
func TestRelayDownFallsBackToLAN(t *testing.T) {
	srv, err := connectrelay.NewServer(connectrelay.Config{Token: relayToken, PublicHost: "127.0.0.1", Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	url := "ws" + strings.TrimPrefix(ts.URL, "http")
	h, _, _ := newTestHost(t, Config{Relays: []Relay{{URL: url, Token: relayToken}}, Listen: []string{freeAddr(t)}})
	waitRelay(t, h)
	serveApp(t, h)
	s, _ := pairOverRelay(t, h, &wire{}, "x")
	if _, err := get(t, s); err != nil {
		t.Fatal(err)
	}
	if route, _, _ := s.Path(context.Background()); route != "relay" {
		t.Fatalf("path %q before the relay stopped", route)
	}
	srv.Close()
	ts.Close()
	if _, err := get(t, s); err != nil {
		t.Fatalf("after the relay stopped: %v", err)
	}
	if route, _, _ := s.Path(context.Background()); route != "lan" {
		t.Fatalf("path %q, want lan", route)
	}
}

// The relay path goes silent (no FIN, writes still succeed): the phone's stall check gets no pong and
// ends the session within 2×Timing.Stall, so the request in flight fails instead of hanging until
// the TCP timeout or Timing.Idle, and the next Dial goes over lan.
func TestSilentRelayFallsBackToLAN(t *testing.T) {
	h, _, _ := newTestHost(t, Config{Relays: []Relay{{URL: startRelay(t), Token: relayToken}}, Listen: []string{freeAddr(t)}})
	waitRelay(t, h)
	serveApp(t, h)
	w := &wire{}
	s, _ := pairOverRelay(t, h, w, "x")
	if _, err := get(t, s); err != nil {
		t.Fatal(err)
	}
	w.silent.Store(true)

	start := time.Now()
	c, err := s.Dial(context.Background()) // reuses the relay session, which looks fine
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(8 * time.Second))
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	_, err = http.ReadResponse(bufio.NewReader(c), nil)
	c.Close()
	if took := time.Since(start); err == nil || errors.Is(err, os.ErrDeadlineExceeded) || took > 7*time.Second {
		t.Fatalf("request on the silent path: %v after %v, want the session closed within about 6 s", err, took)
	}
	if body, err := get(t, s); err != nil || !strings.Contains(body, marker) {
		t.Fatalf("next request: %q %v", body, err)
	}
	if route, _, _ := s.Path(context.Background()); route != "lan" {
		t.Fatalf("next request went over %q, want lan", route)
	}
}

// A close code on the relay is not encrypted, so anyone on the path can send one: a 4401 from a fake
// relay is unreachable, never unpaired, and the phone goes on to its next route.
func TestForgedCloseCodeDoesNotUnpair(t *testing.T) {
	url := startRelay(t)
	h, _, _ := newTestHost(t, Config{Relays: []Relay{{URL: url, Token: relayToken}}, Listen: []string{freeAddr(t)}})
	waitRelay(t, h)
	serveApp(t, h)
	_, link := pairOverRelay(t, h, &wire{}, "x")
	forger := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err == nil {
			c.Close(4401, "unpaired")
		}
	}))
	defer forger.Close()
	fake := "ws" + strings.TrimPrefix(forger.URL, "http")
	var via []connectinvite.Route
	for _, r := range link.Via {
		if r.T == connectinvite.RouteRelay {
			r.U = fake
		}
		via = append(via, r)
	}
	if via[0].T != connectinvite.RouteRelay {
		t.Fatalf("routes %+v", via)
	}
	onlyFake := link
	onlyFake.Via = via[:1]
	s, _ := connectphone.Connect(onlyFake, connectphone.Options{})
	defer s.Close()
	if _, err := get(t, s); !errors.Is(err, connectphone.ErrUnreachable) || errors.Is(err, connectphone.ErrRevoked) {
		t.Fatalf("forged 4401: %v, want ErrUnreachable", err)
	}
	link.Via = via
	s2, _ := connectphone.Connect(link, connectphone.Options{})
	defer s2.Close()
	if _, err := get(t, s2); err != nil {
		t.Fatalf("next route after a forged 4401: %v", err)
	}
	if route, _, _ := s2.Path(context.Background()); route != "lan" {
		t.Fatalf("path %q, want lan", route)
	}
}

// A phone holds at most maxSessionsPerPhone encrypted sessions: a fifth closes its oldest.
func TestFifthSessionClosesTheOldest(t *testing.T) {
	url := startRelay(t) // pairs over the relay; the sessions use lan, as the relay lets one address hold 4 phones
	h, _, _ := newTestHost(t, Config{Relays: []Relay{{URL: url, Token: relayToken}}, Listen: []string{freeAddr(t)}})
	waitRelay(t, h)
	serveApp(t, h)
	first, link := pairOverRelay(t, h, &wire{}, "x")
	if _, err := get(t, first); err != nil {
		t.Fatal(err)
	}
	var lan []connectinvite.Route
	for _, r := range h.Routes() {
		if r.T == connectinvite.RouteLAN {
			lan = append(lan, r)
		}
	}
	link.Via = lan
	for i := 0; i < maxSessionsPerPhone; i++ {
		s, _ := connectphone.Connect(link, connectphone.Options{})
		t.Cleanup(func() { s.Close() })
		if _, err := get(t, s); err != nil {
			t.Fatal(err)
		}
	}
	pub, _ := connectphone.PublicKey(link.Key)
	h.mu.Lock()
	n := 0
	for _, p := range h.sessions {
		if p == pub {
			n++
		}
	}
	h.mu.Unlock()
	if n != maxSessionsPerPhone {
		t.Fatalf("%d sessions, want %d", n, maxSessionsPerPhone)
	}
}

func TestRelayURLMustBeEncryptedOffLoopback(t *testing.T) {
	_, err := New(Config{Name: "Mac", Save: func(State) error { return nil }, Relays: []Relay{{URL: "ws://192.0.2.1:8080", Token: relayToken}}})
	if err == nil || !strings.Contains(err.Error(), "wss://") {
		t.Fatalf("ws:// to a remote relay: %v", err)
	}
	_, err = New(Config{Name: "Mac", Save: func(State) error { return nil }, Listen: []string{"0.0.0.0:7681"}})
	if err == nil {
		t.Fatal("Listen on 0.0.0.0 accepted")
	}
}

// A host without relays dials no relay and offers none.
func TestNoRelayNoRelayRoute(t *testing.T) {
	_, phone := phoneKey(t)
	h, _, _ := newTestHost(t, Config{Allowed: []string{phone}})
	for _, r := range h.Routes() {
		if r.T != connectinvite.RouteTailcat {
			t.Fatalf("routes %+v", h.Routes())
		}
	}
	if len(h.RelayStatus()) != 0 {
		t.Fatal("relay status without relays")
	}
}

// A paired phone that reports another phone's Noise key over sync does not get it: it cannot sign
// for that key. The host would otherwise take the other phone's sessions for its own.
func TestSyncCannotTakeAnotherPhonesKey(t *testing.T) {
	a, phoneA := phoneKey(t)
	b, phoneB := phoneKey(t)
	h, f, saved := newTestHost(t, Config{Allowed: []string{phoneA, phoneB}})
	main := f.live(DefaultPort)
	signer := map[string]key.NodePrivate{phoneA: a, phoneB: b}
	sync := func(phone, noise string) int {
		body := syncBody(h, signer[phone], phone, noise)
		req, _ := http.NewRequest(http.MethodPost, "http://control.invalid/v2/sync", bytes.NewReader(body))
		resp, err := controlClient(main, phone).Do(req)
		if err != nil {
			return 0
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	noiseA := noisePublicOf(a)
	if got := sync(phoneA, noiseA); got != http.StatusOK {
		t.Fatalf("A's own sync: %d", got)
	}
	if got := sync(phoneB, noiseA); got != http.StatusForbidden {
		t.Fatalf("B reporting A's key: %d, want 403", got)
	}
	keys := saved.last().Keys
	if keys[phoneB] != "" || keys[phoneA] != noiseA {
		t.Fatalf("keys after B's attempt: %v", keys)
	}
}

// A phone the app turned away cannot add its Noise key either.
func TestAuthorizeCoversSync(t *testing.T) {
	k, phone := phoneKey(t)
	h, f, saved := newTestHost(t, Config{Allowed: []string{phone}, Authorize: func(string, string) error { return errors.New("signed out") }})
	body := syncBody(h, k, phone, noisePublicOf(k))
	req, _ := http.NewRequest(http.MethodPost, "http://control.invalid/v2/sync", bytes.NewReader(body))
	if resp, err := controlClient(f.live(DefaultPort), phone).Do(req); err == nil {
		t.Fatalf("sync while denied: %d", resp.StatusCode)
	}
	if saved.last().Keys[phone] != "" {
		t.Fatal("a denied phone's key was saved")
	}
}

// A link pinning another host key reaches a host that cannot read its handshake: handshake-closed,
// not revoked.
func TestWrongHostKeyIsHandshakeClosed(t *testing.T) {
	url := startRelay(t)
	h, _, _ := newTestHost(t, Config{Relays: []Relay{{URL: url, Token: relayToken}}, Listen: []string{freeAddr(t)}})
	waitRelay(t, h)
	_, link := pairOverRelay(t, h, &wire{}, "x")
	var lan []connectinvite.Route
	for _, r := range h.Routes() {
		if r.T == connectinvite.RouteLAN {
			lan = append(lan, r)
		}
	}
	other := newIdentity().noisePublic()
	link.HostKey, link.Via = encodeKey(other), lan
	s, _ := connectphone.Connect(link, connectphone.Options{})
	defer s.Close()
	_, err := get(t, s)
	if !errors.Is(err, connectsecure.ErrHandshakeClosed) || errors.Is(err, connectphone.ErrRevoked) {
		t.Fatalf("wrong host key: %v", err)
	}
}

// tap is a TCP proxy on the lan path, as an attacker on the same Wi-Fi sees it: it records what each
// connection carries, both ways, and what the phone sent on it (for replay).
type tap struct {
	addr  string
	mu    sync.Mutex
	all   bytes.Buffer
	sent  [][]byte // per connection, phone to host
	conns int
}

func newTap(t *testing.T, target string) *tap {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	p := &tap{addr: ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			p.mu.Lock()
			i := len(p.sent)
			p.sent = append(p.sent, nil)
			p.conns++
			p.mu.Unlock()
			go func() {
				defer c.Close()
				d, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer d.Close()
				copyRec := func(dst, src net.Conn, phone bool) {
					buf := make([]byte, 32*1024)
					for {
						n, err := src.Read(buf)
						if n > 0 {
							p.mu.Lock()
							p.all.Write(buf[:n])
							if phone {
								p.sent[i] = append(p.sent[i], buf[:n]...)
							}
							p.mu.Unlock()
							dst.Write(buf[:n])
						}
						if err != nil {
							dst.Close()
							return
						}
					}
				}
				go copyRec(c, d, false)
				copyRec(d, c, true)
			}()
		}
	}()
	return p
}

func (p *tap) has(s string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return bytes.Contains(p.all.Bytes(), []byte(s))
}

func (p *tap) phoneBytes(i int) []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]byte(nil), p.sent[i]...)
}

// seenApp counts the requests the host's app gets, per phone.
type seenApp struct {
	mu   sync.Mutex
	from map[string]int
}

func serveCounting(t *testing.T, h *Host) *seenApp {
	a := &seenApp{from: map[string]int{}}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		phone := r.Context().Value(phoneCtxKey{}).(string)
		a.mu.Lock()
		a.from[phone]++
		a.mu.Unlock()
		io.WriteString(w, phone+" "+marker)
	}), ConnContext: func(ctx context.Context, c net.Conn) context.Context {
		return context.WithValue(ctx, phoneCtxKey{}, PhoneOf(c))
	}}
	go srv.Serve(h.Listener())
	t.Cleanup(func() { srv.Close() })
	return a
}

func (a *seenApp) total() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, c := range a.from {
		n += c
	}
	return n
}

func lanVia(addr string) []connectinvite.Route {
	return []connectinvite.Route{{T: connectinvite.RouteLAN, A: []string{addr}}}
}

// Someone on the same Wi-Fi sees every byte of the lan route, can dial it, can answer in the
// computer's place, and can replay what the phone sent. None of it gets them anywhere.
func TestLANAttacker(t *testing.T) {
	hostAddr := freeAddr(t)
	h, _, _ := newTestHost(t, Config{Listen: []string{hostAddr}})
	app := serveCounting(t, h)
	wifi := newTap(t, hostAddr)

	// Pair and connect through the tap.
	p, err := h.Pair(context.Background(), PairOptions{Payload: func(Phone) (string, error) { return "app-token-secret-7", nil }})
	if err != nil {
		t.Fatal(err)
	}
	inv := p.InviteV2()
	inv.Via = lanVia(wifi.addr)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	link, err := connectphone.PairV2(ctx, inv, connectphone.NewKey(), connectphone.Options{Device: "Test Phone"})
	if err != nil {
		t.Fatalf("pair over lan: %v", err)
	}
	pub, _ := connectphone.PublicKey(link.Key)
	link.Address, link.Port, link.Via = "", 0, lanVia(wifi.addr)
	s, _ := connectphone.Connect(link, connectphone.Options{})
	defer s.Close()
	if body, err := get(t, s); err != nil || body != pub+" "+marker {
		t.Fatalf("over lan: %q %v", body, err)
	}
	s.Close()

	// 1. Sniffing: nothing readable. Control: plain bytes through the same tap are recorded.
	for _, secret := range []string{marker, "app-token-secret-7", inv.PSK, pub, "Test Phone"} {
		if wifi.has(secret) {
			t.Fatalf("the Wi-Fi saw %q", secret)
		}
	}
	if c, err := net.Dial("tcp", wifi.addr); err == nil {
		io.WriteString(c, "control-"+marker)
		time.Sleep(50 * time.Millisecond)
		c.Close()
	}
	for deadline := time.Now().Add(2 * time.Second); !wifi.has("control-"+marker) && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if !wifi.has("control-" + marker) {
		t.Fatal("control: the tap records nothing")
	}
	requests := app.total()

	// 2. A phone key that was never paired, with the computer's public key from the QR: turned away.
	stranger := connectphone.Link{Name: "Mac", Key: connectphone.NewKey(), HostKey: inv.PK, Via: lanVia(hostAddr)}
	ss, _ := connectphone.Connect(stranger, connectphone.Options{})
	defer ss.Close()
	if _, err := get(t, ss); err == nil {
		t.Fatal("an unpaired key got in")
	}

	// 3. Posing as the computer: another host answers at the lan address the phone dials.
	fakeAddr := freeAddr(t)
	fake, _, _ := newTestHost(t, Config{Listen: []string{fakeAddr}})
	fakeApp := serveCounting(t, fake)
	posed := link
	posed.Via = lanVia(fakeAddr)
	ps, _ := connectphone.Connect(posed, connectphone.Options{})
	defer ps.Close()
	if _, err := get(t, ps); !errors.Is(err, connectsecure.ErrHandshakeClosed) || errors.Is(err, connectphone.ErrRevoked) {
		t.Fatalf("phone at a fake computer: %v, want handshake-closed", err)
	}
	if fakeApp.total() != 0 {
		t.Fatal("the fake computer got a request")
	}

	// 4. Replay: the pairing connection and the connect connection, byte for byte, to the computer.
	before := len(h.Allowed())
	for i := 0; i < 2; i++ {
		c, err := net.Dial("tcp", hostAddr)
		if err != nil {
			t.Fatal(err)
		}
		c.Write(wifi.phoneBytes(i))
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		io.Copy(io.Discard, c)
		c.Close()
	}
	if len(h.Allowed()) != before {
		t.Fatalf("a replayed pairing added a phone: %v", h.Allowed())
	}
	if app.total() != requests {
		t.Fatalf("a replay reached the app: %d requests, had %d", app.total(), requests)
	}
	// A fresh window does not take the old code either: the replayed pairing names a cid no window has.
	if _, err := h.Pair(context.Background(), PairOptions{}); err != nil {
		t.Fatal(err)
	}
	c, _ := net.Dial("tcp", hostAddr)
	c.Write(wifi.phoneBytes(0))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	io.Copy(io.Discard, c)
	c.Close()
	if len(h.Allowed()) != before {
		t.Fatal("the old code paired into a new window")
	}
}

// One address on the local network gets 4 handshakes at once; a fifth from it is closed at once, and a
// phone at another address still connects.
func TestLANHandshakesPerAddress(t *testing.T) {
	hostAddr := freeAddr(t)
	h, _, _ := newTestHost(t, Config{Listen: []string{hostAddr}})
	serveApp(t, h)
	p, err := h.Pair(context.Background(), PairOptions{})
	if err != nil {
		t.Fatal(err)
	}
	inv := p.InviteV2()
	inv.Via = lanVia(hostAddr)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	link, err := connectphone.PairV2(ctx, inv, connectphone.NewKey(), connectphone.Options{Device: "Test Phone"})
	if err != nil {
		t.Fatal(err)
	}
	link.Address, link.Port, link.Via = "", 0, lanVia(hostAddr)

	other := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}
	for i := 0; i < handshakesPerAddr; i++ {
		c, err := other.Dial("tcp", hostAddr)
		if err != nil {
			t.Skipf("no 127.0.0.2 here: %v", err)
		}
		t.Cleanup(func() { c.Close() })
		c.Write([]byte("TP2C"))
	}
	time.Sleep(200 * time.Millisecond)
	fifth, err := other.Dial("tcp", hostAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer fifth.Close()
	fifth.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := fifth.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a fifth handshake from one address was not closed at once: %v", err)
	}
	s, _ := connectphone.Connect(link, connectphone.Options{})
	defer s.Close()
	if _, err := get(t, s); err != nil {
		t.Fatalf("a phone at another address while one address holds its 4: %v", err)
	}
}

// A link with the host's key has no unencrypted way to the host: a route type the phone does not
// know (an app's old plain address, say) is skipped, never dialled, and when the encrypted routes
// fail the phone reports unreachable (PROTOCOL.md, the MUST for phones paired before v0.3).
func TestLinkWithKeyNeverDialsAPlainRoute(t *testing.T) {
	plain, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	var dialled atomic.Int32
	go func() {
		for {
			c, err := plain.Accept()
			if err != nil {
				return
			}
			dialled.Add(1)
			c.Close()
		}
	}()
	h, _, _ := newTestHost(t, Config{Listen: []string{freeAddr(t)}})
	pk := encodeKey(h.id.noisePublic())
	link := connectphone.Link{Name: "Mac", Key: connectphone.NewKey(), HostKey: pk, Via: []connectinvite.Route{
		{T: "http", A: []string{plain.Addr().String()}}, {T: connectinvite.RouteLAN, A: []string{freeAddr(t)}}}}
	s, err := connectphone.Connect(link, connectphone.Options{})
	if err == nil {
		defer s.Close()
		_, err = get(t, s)
	}
	if err == nil {
		t.Fatal("reached the host with every encrypted route down")
	}
	time.Sleep(100 * time.Millisecond)
	if n := dialled.Load(); n != 0 {
		t.Fatalf("the phone dialled the plain address %d times", n)
	}
}
