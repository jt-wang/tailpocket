package connectrelay_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/jt-wang/tailpocket/connectrelay"
)

// Made-up values; nothing here comes from a real deployment.
const testToken = "test-relay-token-k9QwZx"

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type env struct {
	t    *testing.T
	srv  *connectrelay.Server
	ts   *httptest.Server
	logs *syncBuf
	pub  string // Config.PublicHost
}

// testPublicHost is the made-up name test relays run as.
const testPublicHost = "relay-b.example.net"

func newEnv(t *testing.T, mod func(*connectrelay.Config)) *env {
	t.Helper()
	logs := &syncBuf{}
	cfg := connectrelay.Config{
		Token:      testToken,
		PublicHost: testPublicHost,
		Logger:     log.New(logs, "", 0),
	}
	if mod != nil {
		mod(&cfg)
	}
	srv, err := connectrelay.NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(func() {
		srv.Close()
		ts.Close()
	})
	return &env{t: t, srv: srv, ts: ts, logs: logs, pub: cfg.PublicHost}
}

func (e *env) wsURL(path string) string {
	return "ws" + strings.TrimPrefix(e.ts.URL, "http") + path
}

func ctxT(t *testing.T, d time.Duration) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

func bearer(tok string) http.Header {
	h := http.Header{}
	if tok != "" {
		h.Set("Authorization", "Bearer "+tok)
	}
	return h
}

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func dial(ctx context.Context, url string, h http.Header) (*websocket.Conn, *http.Response, error) {
	return dialHost(ctx, url, h, "")
}

// dialHost dials with hostHeader as the Host header ("" keeps the URL's).
func dialHost(ctx context.Context, url string, h http.Header, hostHeader string) (*websocket.Conn, *http.Response, error) {
	c, resp, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: h, Host: hostHeader})
	if c != nil {
		c.SetReadLimit(4 << 20)
	}
	return c, resp, err
}

func readJSON(ctx context.Context, c *websocket.Conn, v any) error {
	typ, b, err := c.Read(ctx)
	if err != nil {
		return err
	}
	if typ != websocket.MessageText {
		return fmt.Errorf("got message type %v, want text", typ)
	}
	return json.Unmarshal(b, v)
}

func writeJSON(ctx context.Context, c *websocket.Conn, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.Write(ctx, websocket.MessageText, b)
}

// hostOpts changes what a test host sends while registering.
type hostOpts struct {
	token   string
	room    string // URL room; defaults to RoomFor(pub)
	pub     ed25519.PublicKey
	priv    ed25519.PrivateKey
	tamper  func(sig []byte) // flips the signature
	sendPub ed25519.PublicKey
	host    string // host sent in register and signed; default: the relay's PublicHost
	signAs  string // host signed over, when it should differ from host
	header  string // Host header to dial with; default: the URL's
}

// host is the relay's host name as a the host configured for it has it.
func (e *env) host() string { return connectrelay.NormalizeHost(e.pub) }

// openHost dials /v1/host, answers the challenge and returns the connection
// with the first message after register (ready, or the close error).
func (e *env) openHost(ctx context.Context, o hostOpts) (*websocket.Conn, string, error) {
	if o.pub == nil {
		o.pub, o.priv = newKey(e.t)
	}
	room := o.room
	if room == "" {
		room = connectrelay.RoomFor(o.pub)
	}
	c, resp, err := dialHost(ctx, e.wsURL(connectrelay.PathHost+"?room="+room), bearer(o.token), o.header)
	if err != nil {
		if resp != nil {
			return nil, room, fmt.Errorf("dial: status %d: %w", resp.StatusCode, err)
		}
		return nil, room, err
	}
	var ch connectrelay.Challenge
	if err := readJSON(ctx, c, &ch); err != nil {
		c.CloseNow()
		return nil, room, fmt.Errorf("challenge: %w", err)
	}
	if ch.Type != connectrelay.TypeChallenge {
		c.CloseNow()
		return nil, room, fmt.Errorf("first message type %q", ch.Type)
	}
	if o.host == "" {
		o.host = e.host()
	}
	signAs := o.host
	if o.signAs != "" {
		signAs = o.signAs
	}
	sig := connectrelay.SignChallenge(o.priv, signAs, room, ch.Nonce)
	if o.tamper != nil {
		o.tamper(sig)
	}
	sendPub := o.pub
	if o.sendPub != nil {
		sendPub = o.sendPub
	}
	reg := connectrelay.Register{
		Type: connectrelay.TypeRegister,
		Pub:  base64.RawURLEncoding.EncodeToString(sendPub),
		Host: o.host,
		Sig:  base64.RawURLEncoding.EncodeToString(sig),
	}
	if err := writeJSON(ctx, c, reg); err != nil {
		c.CloseNow()
		return nil, room, err
	}
	var ready struct {
		Type string `json:"type"`
	}
	if err := readJSON(ctx, c, &ready); err != nil {
		c.CloseNow()
		return nil, room, err
	}
	if ready.Type != connectrelay.TypeReady {
		c.CloseNow()
		return nil, room, fmt.Errorf("after register got %q", ready.Type)
	}
	return c, room, nil
}

func (e *env) mustHost(ctx context.Context) (*websocket.Conn, string) {
	e.t.Helper()
	c, room, err := e.openHost(ctx, hostOpts{token: testToken})
	if err != nil {
		e.t.Fatalf("register host: %v", err)
	}
	return c, room
}

func (e *env) phone(ctx context.Context, room string) (*websocket.Conn, *http.Response, error) {
	return dial(ctx, e.wsURL(connectrelay.PathPhone+"?room="+room), nil)
}

// nextIncoming reads one incoming message off the host connection.
func nextIncoming(ctx context.Context, host *websocket.Conn) (string, error) {
	var in connectrelay.Incoming
	if err := readJSON(ctx, host, &in); err != nil {
		return "", err
	}
	if in.Type != connectrelay.TypeIncoming {
		return "", fmt.Errorf("host got %q, want incoming", in.Type)
	}
	return in.ID, nil
}

func (e *env) accept(ctx context.Context, room, id, tok string) (*websocket.Conn, *http.Response, error) {
	return dial(ctx, e.wsURL(connectrelay.PathAccept+"?room="+room+"&id="+id), bearer(tok))
}

// pair connects a phone and has the host accept it.
func (e *env) pair(ctx context.Context, host *websocket.Conn, room string) (phone, acc *websocket.Conn) {
	e.t.Helper()
	phone, _, err := e.phone(ctx, room)
	if err != nil {
		e.t.Fatalf("phone dial: %v", err)
	}
	id, err := nextIncoming(ctx, host)
	if err != nil {
		e.t.Fatalf("incoming: %v", err)
	}
	acc, _, err = e.accept(ctx, room, id, testToken)
	if err != nil {
		e.t.Fatalf("accept dial: %v", err)
	}
	return phone, acc
}

func randBytes(t *testing.T, n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func statusOf(err error) websocket.StatusCode { return websocket.CloseStatus(err) }

// waitClosed reads until the connection ends and returns the close code.
func waitClosed(ctx context.Context, c *websocket.Conn) (websocket.StatusCode, error) {
	for {
		_, _, err := c.Read(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return -1, fmt.Errorf("still open: %w", ctx.Err())
			}
			return statusOf(err), err
		}
	}
}

// fakeClock is a Now that a test moves by hand.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// behindProxy makes the relay believe X-Forwarded-For from this process, so
// a test can stand in for several source addresses.
func behindProxy(c *connectrelay.Config) {
	c.TrustProxy = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}
}

func fromAddr(a string) http.Header {
	h := http.Header{}
	h.Set("X-Forwarded-For", a)
	return h
}

func (e *env) phoneFrom(ctx context.Context, room, addr string) (*websocket.Conn, *http.Response, error) {
	return dial(ctx, e.wsURL(connectrelay.PathPhone+"?room="+room), fromAddr(addr))
}

// readsForever answers pings on c, like a live the host.
func readsForever(ctx context.Context, c *websocket.Conn) {
	go func() {
		for {
			if _, _, err := c.Read(ctx); err != nil {
				return
			}
		}
	}()
}

// 1. One phone and one the host exchange 1 MiB each way, byte for byte.
func TestRoundTrip(t *testing.T) {
	e := newEnv(t, nil)
	ctx := ctxT(t, 20*time.Second)
	host, room := e.mustHost(ctx)
	defer host.CloseNow()
	phone, acc := e.pair(ctx, host, room)
	defer phone.CloseNow()
	defer acc.CloseNow()

	up := randBytes(t, connectrelay.MaxMessage)
	if err := phone.Write(ctx, websocket.MessageBinary, up); err != nil {
		t.Fatal(err)
	}
	typ, got, err := acc.Read(ctx)
	if err != nil {
		t.Fatalf("companion read: %v", err)
	}
	if typ != websocket.MessageBinary || !bytes.Equal(got, up) {
		t.Fatalf("companion got %d bytes (type %v), want the phone's %d bytes", len(got), typ, len(up))
	}

	down := randBytes(t, connectrelay.MaxMessage)
	if err := acc.Write(ctx, websocket.MessageBinary, down); err != nil {
		t.Fatal(err)
	}
	typ, got, err = phone.Read(ctx)
	if err != nil {
		t.Fatalf("phone read: %v", err)
	}
	if typ != websocket.MessageBinary || !bytes.Equal(got, down) {
		t.Fatalf("phone got %d bytes, want the companion's %d bytes", len(got), len(down))
	}

	// Several small messages keep their order.
	for i := 0; i < 20; i++ {
		if err := phone.Write(ctx, websocket.MessageBinary, []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 20; i++ {
		_, b, err := acc.Read(ctx)
		if err != nil || len(b) != 1 || b[0] != byte(i) {
			t.Fatalf("message %d: %v %v", i, b, err)
		}
	}

	// The phone leaving closes the the host's side too.
	phone.Close(websocket.StatusNormalClosure, "")
	if _, err := waitClosed(ctxT(t, 3*time.Second), acc); err != nil && strings.Contains(err.Error(), "still open") {
		t.Fatal("accept connection still open after the phone left")
	}
}

func TestRoomAndSignature(t *testing.T) {
	pub, priv := newKey(t)
	room := connectrelay.RoomFor(pub)
	if len(room) != 22 {
		t.Fatalf("room %q has %d characters, want 22", room, len(room))
	}
	if connectrelay.RoomFor(pub) != room {
		t.Fatal("RoomFor is not stable")
	}
	nonce := base64.RawURLEncoding.EncodeToString(randBytes(t, 16))
	const host = "relay.example.com"
	sig := connectrelay.SignChallenge(priv, host, room, nonce)
	if !ed25519.Verify(pub, []byte("tailpocket-relay host v1\n"+host+"\n"+room+"\n"+nonce), sig) {
		t.Fatal("SignChallenge does not sign \"tailpocket-relay host v1\\n\" + host + \"\\n\" + room + \"\\n\" + nonce")
	}
	if !connectrelay.VerifyChallenge(pub, host, room, nonce, sig) {
		t.Fatal("VerifyChallenge rejects a good signature")
	}
	if connectrelay.VerifyChallenge(pub, host, room, nonce+"x", sig) {
		t.Fatal("VerifyChallenge accepts a signature over another nonce")
	}
	if connectrelay.VerifyChallenge(pub, "relay-a.example.net", room, nonce, sig) {
		t.Fatal("VerifyChallenge accepts a signature made for another relay")
	}
	if !connectrelay.VerifyChallenge(pub, "Relay.Example.com.:443", room, nonce, sig) {
		t.Fatal("VerifyChallenge does not normalize the host")
	}
	pub2, _ := newKey(t)
	if connectrelay.RoomFor(pub2) == room {
		t.Fatal("two keys give one room")
	}
}

// 2. A bad signature or a room the key does not give is refused with 4403.
func TestBadRegister(t *testing.T) {
	e := newEnv(t, nil)
	ctx := ctxT(t, 10*time.Second)

	_, _, err := e.openHost(ctx, hostOpts{token: testToken, tamper: func(sig []byte) { sig[7] ^= 1 }})
	if got := statusOf(err); got != connectrelay.CloseBadRegister {
		t.Fatalf("flipped signature: close %v (%v), want %d", got, err, connectrelay.CloseBadRegister)
	}

	pubA, privA := newKey(t)
	pubB, _ := newKey(t)
	_, _, err = e.openHost(ctx, hostOpts{token: testToken, pub: pubA, priv: privA, room: connectrelay.RoomFor(pubB)})
	if got := statusOf(err); got != connectrelay.CloseBadRegister {
		t.Fatalf("room of another key: close %v (%v), want %d", got, err, connectrelay.CloseBadRegister)
	}

	// Signed with A over B's room, but sending B's key: signature fails.
	_, _, err = e.openHost(ctx, hostOpts{token: testToken, pub: pubA, priv: privA, room: connectrelay.RoomFor(pubB), sendPub: pubB})
	if got := statusOf(err); got != connectrelay.CloseBadRegister {
		t.Fatalf("someone else's key: close %v (%v), want %d", got, err, connectrelay.CloseBadRegister)
	}

	// Control: the same key, unchanged, registers.
	c, _, err := e.openHost(ctx, hostOpts{token: testToken, pub: pubA, priv: privA})
	if err != nil {
		t.Fatalf("good register after bad ones: %v", err)
	}
	c.CloseNow()
}

// 3. One the host per room; the room frees up once it leaves.
func TestOneHostPerRoom(t *testing.T) {
	e := newEnv(t, nil)
	ctx := ctxT(t, 10*time.Second)
	pub, priv := newKey(t)
	first, _, err := e.openHost(ctx, hostOpts{token: testToken, pub: pub, priv: priv})
	if err != nil {
		t.Fatal(err)
	}
	readsForever(ctx, first) // alive: it answers pings
	_, _, err = e.openHost(ctx, hostOpts{token: testToken, pub: pub, priv: priv})
	if got := statusOf(err); got != connectrelay.CloseRoomTaken {
		t.Fatalf("second host: close %v (%v), want %d", got, err, connectrelay.CloseRoomTaken)
	}
	first.Close(websocket.StatusNormalClosure, "")

	deadline := time.Now().Add(3 * time.Second)
	for {
		c, _, err := e.openHost(ctx, hostOpts{token: testToken, pub: pub, priv: priv})
		if err == nil {
			c.CloseNow()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("room still taken after the first host left: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// 4. A phone for a room with no the host gets 4404.
func TestPhoneNoHost(t *testing.T) {
	e := newEnv(t, nil)
	ctx := ctxT(t, 5*time.Second)
	pub, _ := newKey(t)
	c, _, err := e.phone(ctx, connectrelay.RoomFor(pub))
	if err != nil {
		t.Fatalf("phone dial: %v", err)
	}
	code, _ := waitClosed(ctx, c)
	if code != connectrelay.CloseNoHost {
		t.Fatalf("close %v, want %d", code, connectrelay.CloseNoHost)
	}
}

// 5. A the host that never accepts leaves the phone closed with 4408.
func TestAcceptTimeout(t *testing.T) {
	e := newEnv(t, func(c *connectrelay.Config) { c.AcceptTimeout = 100 * time.Millisecond })
	ctx := ctxT(t, 5*time.Second)
	host, room := e.mustHost(ctx)
	defer host.CloseNow()
	phone, _, err := e.phone(ctx, room)
	if err != nil {
		t.Fatal(err)
	}
	id, err := nextIncoming(ctx, host)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	code, _ := waitClosed(ctx, phone)
	if code != connectrelay.CloseAcceptTimeout {
		t.Fatalf("close %v, want %d", code, connectrelay.CloseAcceptTimeout)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("closed after %v, want about 100 ms", el)
	}
	// A late accept finds nothing.
	_, resp, err := e.accept(ctx, room, id, testToken)
	if err == nil || resp == nil || resp.StatusCode != http.StatusNotFound {
		t.Fatalf("late accept: %v %v, want 404", resp, err)
	}
}

func dialStatus(resp *http.Response) int {
	if resp == nil {
		return 0
	}
	return resp.StatusCode
}

// 6. register and accept need the token unless the relay is open.
func TestToken(t *testing.T) {
	e := newEnv(t, nil)
	ctx := ctxT(t, 10*time.Second)
	pub, _ := newKey(t)
	room := connectrelay.RoomFor(pub)
	for _, tok := range []string{"", "wrong-token", testToken + "x", testToken[:len(testToken)-1]} {
		c, resp, err := dial(ctx, e.wsURL(connectrelay.PathHost+"?room="+room), bearer(tok))
		if err == nil {
			c.CloseNow()
		}
		if dialStatus(resp) != http.StatusUnauthorized {
			t.Fatalf("host with token %q: status %d, want 401", tok, dialStatus(resp))
		}
	}

	host, room := e.mustHost(ctx)
	defer host.CloseNow()
	phone, _, err := e.phone(ctx, room)
	if err != nil {
		t.Fatal(err)
	}
	defer phone.CloseNow()
	id, err := nextIncoming(ctx, host)
	if err != nil {
		t.Fatal(err)
	}
	for _, tok := range []string{"", "wrong-token"} {
		c, resp, err := e.accept(ctx, room, id, tok)
		if err == nil {
			c.CloseNow()
		}
		if dialStatus(resp) != http.StatusUnauthorized {
			t.Fatalf("accept with token %q: status %d, want 401", tok, dialStatus(resp))
		}
	}
	// The refused accepts did not use up the pending phone.
	acc, _, err := e.accept(ctx, room, id, testToken)
	if err != nil {
		t.Fatalf("accept with the token: %v", err)
	}
	acc.CloseNow()

}

// There is no open relay: without a token anyone could register a room and use the relay to
// pass anything between any two parties.
func TestNoTokenNotOpen(t *testing.T) {
	if _, err := connectrelay.NewServer(connectrelay.Config{PublicHost: testPublicHost}); !errors.Is(err, connectrelay.ErrNoToken) {
		t.Fatalf("NewServer with no token: %v, want ErrNoToken", err)
	}
}

// autoAccept accepts every incoming phone until ctx ends.
func (e *env) autoAccept(ctx context.Context, host *websocket.Conn, room string) <-chan *websocket.Conn {
	out := make(chan *websocket.Conn, 64)
	go func() {
		for {
			id, err := nextIncoming(ctx, host)
			if err != nil {
				return
			}
			acc, _, err := e.accept(ctx, room, id, testToken)
			if err != nil {
				return
			}
			// Like a the host, keep reading so closes complete.
			go func() {
				for {
					if _, _, err := acc.Read(ctx); err != nil {
						return
					}
				}
			}()
			out <- acc
		}
	}()
	return out
}

// 7a. The 17th phone in a room is refused.
func TestPhonesPerRoom(t *testing.T) {
	e := newEnv(t, behindProxy)
	ctx := ctxT(t, 20*time.Second)
	host, room := e.mustHost(ctx)
	defer host.CloseNow()
	accs := e.autoAccept(ctx, host, room)
	var phones []*websocket.Conn
	defer func() {
		for _, p := range phones {
			p.CloseNow()
		}
	}()
	for i := 0; i < 16; i++ {
		p, _, err := e.phoneFrom(ctx, room, fmt.Sprintf("192.0.2.%d", i+1))
		if err != nil {
			t.Fatalf("phone %d: %v", i+1, err)
		}
		phones = append(phones, p)
		select {
		case <-accs:
		case <-ctx.Done():
			t.Fatalf("phone %d not accepted", i+1)
		}
	}
	p, resp, err := e.phoneFrom(ctx, room, "192.0.2.100")
	if err == nil {
		p.CloseNow()
	}
	if dialStatus(resp) != http.StatusServiceUnavailable {
		t.Fatalf("17th phone: status %d (%v), want 503", dialStatus(resp), err)
	}
	// One leaves, a new one fits.
	phones[0].Close(websocket.StatusNormalClosure, "")
	phones = phones[1:]
	deadline := time.Now().Add(3 * time.Second)
	for {
		p, _, err := e.phoneFrom(ctx, room, "192.0.2.101")
		if err == nil {
			phones = append(phones, p)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no room for a phone after one left: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// 7b. At most 30 /v1/phone per source address in any 60 s, and the
// allowance comes back once the window has passed.
func TestPhoneRate(t *testing.T) {
	clk := newClock()
	e := newEnv(t, func(c *connectrelay.Config) { c.Now = clk.Now })
	ctx := ctxT(t, 20*time.Second)
	pub, _ := newKey(t)
	room := connectrelay.RoomFor(pub)
	try := func() int {
		c, resp, err := e.phone(ctx, room)
		if err == nil {
			waitClosed(ctx, c)
			return 101
		}
		return dialStatus(resp)
	}
	for i := 0; i < 30; i++ {
		if got := try(); got != 101 {
			t.Fatalf("request %d at 0 s: status %d", i+1, got)
		}
	}
	if got := try(); got != http.StatusTooManyRequests {
		t.Fatalf("31st request at 0 s: status %d, want 429", got)
	}
	clk.Add(59 * time.Second)
	if got := try(); got != http.StatusTooManyRequests {
		t.Fatalf("request at 59 s: status %d, want 429 (30 already in the last 60 s)", got)
	}
	clk.Add(2 * time.Second)
	if got := try(); got != 101 {
		t.Fatalf("request at 61 s: status %d, want it let through", got)
	}
}

// Two IPv6 addresses in one /64 share an allowance; another /64 does not.
func TestPhoneRateIPv6Prefix(t *testing.T) {
	e := newEnv(t, behindProxy)
	ctx := ctxT(t, 20*time.Second)
	pub, _ := newKey(t)
	room := connectrelay.RoomFor(pub)
	for i := 0; i < 30; i++ {
		c, resp, err := e.phoneFrom(ctx, room, fmt.Sprintf("2001:db8:1:1::%x", i+1))
		if err != nil {
			t.Fatalf("request %d: %d %v", i+1, dialStatus(resp), err)
		}
		waitClosed(ctx, c)
	}
	c, resp, err := e.phoneFrom(ctx, room, "2001:db8:1:1:ffff::1")
	if err == nil {
		c.CloseNow()
	}
	if dialStatus(resp) != http.StatusTooManyRequests {
		t.Fatalf("31st request from the same /64: status %d, want 429", dialStatus(resp))
	}
	c, _, err = e.phoneFrom(ctx, room, "2001:db8:1:2::1")
	if err != nil {
		t.Fatalf("first request from another /64: %v", err)
	}
	c.CloseNow()
}

// One source address holds at most 4 of a room's phone places; another
// address still gets in. IPv6 counts by /64.
func TestPhonesPerAddress(t *testing.T) {
	e := newEnv(t, behindProxy)
	ctx := ctxT(t, 20*time.Second)
	host, room := e.mustHost(ctx)
	defer host.CloseNow()
	accs := e.autoAccept(ctx, host, room)
	var open []*websocket.Conn
	defer func() {
		for _, c := range open {
			c.CloseNow()
		}
	}()
	join := func(addr string) int {
		c, resp, err := e.phoneFrom(ctx, room, addr)
		if err != nil {
			return dialStatus(resp)
		}
		open = append(open, c)
		select {
		case <-accs:
		case <-ctx.Done():
			t.Fatalf("phone from %s not accepted", addr)
		}
		return 101
	}
	for i := 0; i < 4; i++ {
		if got := join("192.0.2.7"); got != 101 {
			t.Fatalf("phone %d from one IPv4: %d", i+1, got)
		}
	}
	if got := join("192.0.2.7"); got != http.StatusServiceUnavailable {
		t.Fatalf("5th phone from one IPv4: %d, want 503", got)
	}
	if got := join("192.0.2.8"); got != 101 {
		t.Fatalf("phone from another IPv4: %d, want it let in", got)
	}
	for i := 0; i < 4; i++ {
		if got := join(fmt.Sprintf("2001:db8:5:5::%x", i+1)); got != 101 {
			t.Fatalf("phone %d from one /64: %d", i+1, got)
		}
	}
	if got := join("2001:db8:5:5:abcd::9"); got != http.StatusServiceUnavailable {
		t.Fatalf("5th phone from the same /64: %d, want 503", got)
	}
	if got := join("2001:db8:5:6::1"); got != 101 {
		t.Fatalf("phone from another /64: %d, want it let in", got)
	}
}

// 7c. The 101st room is refused.
func TestMaxRooms(t *testing.T) {
	e := newEnv(t, func(c *connectrelay.Config) { c.HostRate = 1000 }) // 100 hosts from one test address
	ctx := ctxT(t, 30*time.Second)
	var hosts []*websocket.Conn
	defer func() {
		for _, h := range hosts {
			h.CloseNow()
		}
	}()
	for i := 0; i < 100; i++ {
		h, _, err := e.openHost(ctx, hostOpts{token: testToken})
		if err != nil {
			t.Fatalf("room %d: %v", i+1, err)
		}
		hosts = append(hosts, h)
	}
	_, _, err := e.openHost(ctx, hostOpts{token: testToken})
	if err == nil || !strings.Contains(err.Error(), "status 503") {
		t.Fatalf("101st room: %v, want status 503", err)
	}
	// One leaves; a connection that has not registered yet takes its place
	// and counts, so the next one is still refused.
	hosts[0].Close(websocket.StatusNormalClosure, "")
	hosts = hosts[1:]
	pub, _ := newKey(t)
	var pending *websocket.Conn
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, _, err := dial(ctx, e.wsURL(connectrelay.PathHost+"?room="+connectrelay.RoomFor(pub)), bearer(testToken))
		if err == nil {
			pending = c
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no room after one left: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer pending.CloseNow()
	_, _, err = e.openHost(ctx, hostOpts{token: testToken})
	if err == nil || !strings.Contains(err.Error(), "status 503") {
		t.Fatalf("while one registration is pending: %v, want status 503", err)
	}
}

// 7d. A message over 1 MiB closes the sender with 1009 before any of it is
// passed on: the other side gets no message and is closed with 1001.
func TestMessageTooBig(t *testing.T) {
	for _, n := range []int{connectrelay.MaxMessage + 1, 3 * connectrelay.MaxMessage} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			e := newEnv(t, nil)
			ctx := ctxT(t, 10*time.Second)
			host, room := e.mustHost(ctx)
			defer host.CloseNow()
			phone, acc := e.pair(ctx, host, room)
			defer phone.CloseNow()
			defer acc.CloseNow()

			type got struct {
				msgs int
				code websocket.StatusCode
			}
			accEnd := make(chan got, 1)
			go func() {
				actx := ctxT(t, 5*time.Second)
				var g got
				for {
					_, _, err := acc.Read(actx)
					if err != nil {
						g.code = statusOf(err)
						accEnd <- g
						return
					}
					g.msgs++
				}
			}()
			_ = phone.Write(ctx, websocket.MessageBinary, randBytes(t, n))
			code, err := waitClosed(ctxT(t, 5*time.Second), phone)
			if err != nil && strings.Contains(err.Error(), "still open") {
				t.Fatal("phone still open after a too-big message")
			}
			if code != websocket.StatusMessageTooBig {
				t.Fatalf("phone close %v, want %d", code, websocket.StatusMessageTooBig)
			}
			g := <-accEnd
			if g.msgs != 0 {
				t.Fatalf("accept got %d message(s) of a too-big message, want none", g.msgs)
			}
			if g.code != websocket.StatusGoingAway {
				t.Fatalf("accept closed with %v, want 1001", g.code)
			}
			// The host's control connection stays up.
			p2, a2 := e.pair(ctx, host, room)
			p2.CloseNow()
			a2.CloseNow()
		})
	}
}

// 8. When the the host's control connection drops, its phones are closed.
func TestHostGoneClosesPhones(t *testing.T) {
	e := newEnv(t, nil)
	ctx := ctxT(t, 10*time.Second)
	host, room := e.mustHost(ctx)
	p1, a1 := e.pair(ctx, host, room)
	p2, a2 := e.pair(ctx, host, room)
	defer a1.CloseNow()
	defer a2.CloseNow()
	// A third one waits for accept that never comes.
	p3, _, err := e.phone(ctx, room)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nextIncoming(ctx, host); err != nil {
		t.Fatal(err)
	}

	host.CloseNow()
	for i, p := range []*websocket.Conn{p1, p2, p3} {
		code, err := waitClosed(ctxT(t, 3*time.Second), p)
		if err != nil && strings.Contains(err.Error(), "still open") {
			t.Fatalf("phone %d still open after the companion left", i+1)
		}
		// The phone learns why: no the host in this room any more.
		if code != connectrelay.CloseNoHost {
			t.Fatalf("phone %d closed with %v, want %d", i+1, code, connectrelay.CloseNoHost)
		}
	}
	// And the room is free: a phone now gets 4404.
	c, _, err := e.phone(ctx, room)
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := waitClosed(ctx, c); code != connectrelay.CloseNoHost {
		t.Fatalf("phone after host left: %v, want %d", code, connectrelay.CloseNoHost)
	}
}

// 9. The log has events but no token, full room, or payload.
func TestLogsNoSecrets(t *testing.T) {
	e := newEnv(t, nil)
	ctx := ctxT(t, 10*time.Second)
	host, room := e.mustHost(ctx)
	phone, acc := e.pair(ctx, host, room)

	marker := []byte("MARKER-q7Zp2-made-up-payload")
	payload := append(append(randBytes(t, 1000), marker...), randBytes(t, 1000)...)
	if err := phone.Write(ctx, websocket.MessageBinary, payload); err != nil {
		t.Fatal(err)
	}
	if _, _, err := acc.Read(ctx); err != nil {
		t.Fatal(err)
	}
	if err := acc.Write(ctx, websocket.MessageBinary, payload); err != nil {
		t.Fatal(err)
	}
	if _, _, err := phone.Read(ctx); err != nil {
		t.Fatal(err)
	}
	phone.Close(websocket.StatusNormalClosure, "")
	waitClosed(ctxT(t, 3*time.Second), acc)
	host.Close(websocket.StatusNormalClosure, "")

	// phone-out and host-down come from two handlers in either order; wait
	// for both so the check sees the whole log.
	deadline := time.Now().Add(3 * time.Second)
	for !(strings.Contains(e.logs.String(), "host-down") && strings.Contains(e.logs.String(), "phone-out")) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	logs := e.logs.String()
	for _, ev := range []string{"host-up", "phone-in", "phone-paired", "phone-out", "host-down"} {
		if !strings.Contains(logs, ev) {
			t.Fatalf("log has no %s event:\n%s", ev, logs)
		}
	}
	if !strings.Contains(logs, "room="+room[:6]) {
		t.Fatalf("log does not name the room by its first 6 characters:\n%s", logs)
	}
	if !strings.Contains(logs, " phone-out room="+room[:6]+" code=1000 bytes=") {
		t.Fatalf("phone-out line does not give the close code as a number:\n%s", logs)
	}
	if !strings.Contains(logs, fmt.Sprintf("bytes=%d", 2*len(payload))) {
		t.Fatalf("phone-out does not count %d bytes:\n%s", 2*len(payload), logs)
	}
	for name, secret := range map[string]string{"token": testToken, "room": room, "payload": string(marker)} {
		if strings.Contains(logs, secret) {
			t.Fatalf("log contains the %s:\n%s", name, logs)
		}
	}
	// Short pieces of the token show up neither.
	if strings.Contains(logs, testToken[:10]) {
		t.Fatalf("log contains part of the token:\n%s", logs)
	}
}

// 10. Without --trust-proxy, X-Forwarded-For does not get around the
// per-IP limit; with it, the header from a trusted proxy is used.
func TestForwardedFor(t *testing.T) {
	run := func(e *env) (refusedAt int) {
		ctx := ctxT(t, 20*time.Second)
		pub, _ := newKey(t)
		room := connectrelay.RoomFor(pub)
		for i := 0; i < 31; i++ {
			h := http.Header{}
			h.Set("X-Forwarded-For", fmt.Sprintf("192.0.2.%d", i+1))
			c, resp, err := dial(ctx, e.wsURL(connectrelay.PathPhone+"?room="+room), h)
			if err != nil {
				if dialStatus(resp) == http.StatusTooManyRequests {
					return i + 1
				}
				t.Fatalf("request %d: %d %v", i+1, dialStatus(resp), err)
			}
			waitClosed(ctx, c)
		}
		return 0
	}
	if got := run(newEnv(t, nil)); got != 31 {
		t.Fatalf("untrusted X-Forwarded-For: refused at request %d, want 31", got)
	}
	trusted := newEnv(t, func(c *connectrelay.Config) {
		c.TrustProxy = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}
	})
	if got := run(trusted); got != 0 {
		t.Fatalf("trusted proxy with 31 different clients: refused at request %d, want none", got)
	}
}

func TestClientIP(t *testing.T) {
	// Documentation addresses only (RFC 5737): 192.0.2.0/28 plays the proxy.
	trust := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/28")}
	cases := []struct {
		remote, xff string
		trust       []netip.Prefix
		want        string
	}{
		{"192.0.2.99:5000", "", nil, "192.0.2.99"},
		{"192.0.2.99:5000", "192.0.2.200", nil, "192.0.2.99"},
		{"192.0.2.1:5000", "192.0.2.200", trust, "192.0.2.200"},
		// The client can prepend whatever it likes; the rightmost untrusted hop counts.
		{"192.0.2.1:5000", "192.0.2.150, 192.0.2.200", trust, "192.0.2.200"},
		{"192.0.2.1:5000", "192.0.2.200, 192.0.2.2", trust, "192.0.2.200"},
		{"192.0.2.1:5000", "garbage", trust, "192.0.2.1"},
		{"192.0.2.99:5000", "192.0.2.200", trust, "192.0.2.99"},
		{"[::ffff:192.0.2.99]:5000", "", nil, "192.0.2.99"},
		{"[::1]:5000", "", nil, "::1"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/v1/phone", nil)
		r.RemoteAddr = c.remote
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := connectrelay.ClientIP(r, c.trust).String(); got != c.want {
			t.Errorf("remote %s xff %q: got %s, want %s", c.remote, c.xff, got, c.want)
		}
	}
}

// The relay pings; a the host that stops answering loses its room.
func TestPingDropsDeadHost(t *testing.T) {
	e := newEnv(t, func(c *connectrelay.Config) { c.PingInterval = 100 * time.Millisecond })
	ctx := ctxT(t, 10*time.Second)
	host, room := e.mustHost(ctx)
	defer host.CloseNow()
	// The host never reads again, so it never answers a ping.
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, _, err := e.phone(ctx, room)
		if err != nil {
			t.Fatal(err)
		}
		pctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
		code, _ := waitClosed(pctx, c)
		cancel()
		c.CloseNow()
		if code == connectrelay.CloseNoHost {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("a host that answers no pings still holds its room")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// A host that keeps reading answers pings and keeps its room.
func TestPingKeepsLiveHost(t *testing.T) {
	e := newEnv(t, func(c *connectrelay.Config) { c.PingInterval = 50 * time.Millisecond })
	ctx := ctxT(t, 10*time.Second)
	host, room := e.mustHost(ctx)
	defer host.CloseNow()
	accs := e.autoAccept(ctx, host, room) // reads the host connection
	time.Sleep(500 * time.Millisecond)
	p, _, err := e.phone(ctx, room)
	if err != nil {
		t.Fatal(err)
	}
	defer p.CloseNow()
	select {
	case a := <-accs:
		a.CloseNow()
	case <-time.After(3 * time.Second):
		t.Fatal("live host lost its room")
	}
}

func TestHealthz(t *testing.T) {
	e := newEnv(t, nil)
	resp, err := http.Get(e.ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || strings.TrimSpace(string(b)) != "ok" {
		t.Fatalf("healthz: %d %q", resp.StatusCode, b)
	}
}

func TestBadRoomQuery(t *testing.T) {
	e := newEnv(t, nil)
	ctx := ctxT(t, 5*time.Second)
	for _, q := range []string{"", "short", strings.Repeat("A", 23), "!!!!!!!!!!!!!!!!!!!!!!"} {
		c, resp, err := dial(ctx, e.wsURL(connectrelay.PathPhone+"?room="+q), nil)
		if err == nil {
			c.CloseNow()
		}
		if dialStatus(resp) != http.StatusBadRequest {
			t.Errorf("room %q: status %d, want 400", q, dialStatus(resp))
		}
	}
}

// Whatever code one end closes with, the relay closes the other end with
// 1001 "peer-gone": a close code on a relay connection is not encrypted, so
// passing on 4401 would let anyone fake "this phone was unpaired".
func TestPeerGone(t *testing.T) {
	for _, tc := range []struct {
		name   string
		closer string
		code   websocket.StatusCode
	}{
		{"companion sends 4401", "acc", 4401},
		{"phone sends 4403", "phone", 4403},
		{"phone closes normally", "phone", websocket.StatusNormalClosure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, nil)
			ctx := ctxT(t, 10*time.Second)
			host, room := e.mustHost(ctx)
			defer host.CloseNow()
			phone, acc := e.pair(ctx, host, room)
			defer phone.CloseNow()
			defer acc.CloseNow()
			closer, other := acc, phone
			if tc.closer == "phone" {
				closer, other = phone, acc
			}
			go closer.Close(tc.code, "made-up reason")
			_, _, err := other.Read(ctxT(t, 5*time.Second))
			var ce websocket.CloseError
			if !errors.As(err, &ce) {
				t.Fatalf("other end: %v, want a close frame", err)
			}
			if ce.Code != websocket.StatusGoingAway || ce.Reason != "peer-gone" {
				t.Fatalf("other end got %d %q, want 1001 \"peer-gone\"", ce.Code, ce.Reason)
			}
		})
	}
	// The host shutting down may close its accept connection just before
	// its registration: the phone then also learns the the host left.
	t.Run("accept then registration ends", func(t *testing.T) {
		e := newEnv(t, nil)
		ctx := ctxT(t, 10*time.Second)
		host, room := e.mustHost(ctx)
		defer host.CloseNow()
		phone, acc := e.pair(ctx, host, room)
		defer phone.CloseNow()
		go func() {
			acc.Close(websocket.StatusNormalClosure, "")
			time.Sleep(50 * time.Millisecond)
			host.Close(websocket.StatusNormalClosure, "")
		}()
		_, _, err := phone.Read(ctxT(t, 5*time.Second))
		var ce websocket.CloseError
		if !errors.As(err, &ce) {
			t.Fatalf("phone: %v, want a close frame", err)
		}
		if ce.Code != connectrelay.CloseNoHost {
			t.Fatalf("phone got %d %q when the accept closed 50 ms before the registration, want 4404", ce.Code, ce.Reason)
		}
	})
	// The registration ending is not a pair end: the room is gone, so its
	// phones get 4404, whatever code the host sent.
	t.Run("registration ends", func(t *testing.T) {
		e := newEnv(t, nil)
		ctx := ctxT(t, 10*time.Second)
		host, room := e.mustHost(ctx)
		phone, acc := e.pair(ctx, host, room)
		defer phone.CloseNow()
		defer acc.CloseNow()
		go host.Close(4401, "made-up reason")
		_, _, err := phone.Read(ctxT(t, 5*time.Second))
		var ce websocket.CloseError
		if !errors.As(err, &ce) {
			t.Fatalf("phone: %v, want a close frame", err)
		}
		if ce.Code != connectrelay.CloseNoHost {
			t.Fatalf("phone got %d %q after the registration ended, want 4404", ce.Code, ce.Reason)
		}
	})
}

// A the host that dropped off the network without closing (no pongs) does
// not hold its room against itself coming back with the same key.
func TestStaleHostReplaced(t *testing.T) {
	e := newEnv(t, func(c *connectrelay.Config) { c.StaleCheck = 200 * time.Millisecond })
	ctx := ctxT(t, 10*time.Second)
	pub, priv := newKey(t)
	first, room, err := e.openHost(ctx, hostOpts{token: testToken, pub: pub, priv: priv})
	if err != nil {
		t.Fatal(err)
	}
	defer first.CloseNow() // never read: it cannot answer a ping
	start := time.Now()
	second, _, err := e.openHost(ctx, hostOpts{token: testToken, pub: pub, priv: priv})
	if err != nil {
		t.Fatalf("same key after the first went silent: %v, want it registered", err)
	}
	defer second.CloseNow()
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("took %v, want about the 200 ms check", el)
	}
	phone, acc := e.pair(ctx, second, room)
	phone.CloseNow()
	acc.CloseNow()
}

// A register message recorded from one connection does not work on another:
// each challenge has a fresh nonce.
func TestReplayedRegister(t *testing.T) {
	e := newEnv(t, nil)
	ctx := ctxT(t, 10*time.Second)
	pub, priv := newKey(t)
	room := connectrelay.RoomFor(pub)
	url := e.wsURL(connectrelay.PathHost + "?room=" + room)

	c1, _, err := dial(ctx, url, bearer(testToken))
	if err != nil {
		t.Fatal(err)
	}
	var ch connectrelay.Challenge
	if err := readJSON(ctx, c1, &ch); err != nil {
		t.Fatal(err)
	}
	reg := connectrelay.Register{
		Type: connectrelay.TypeRegister,
		Pub:  base64.RawURLEncoding.EncodeToString(pub),
		Host: e.host(),
		Sig:  base64.RawURLEncoding.EncodeToString(connectrelay.SignChallenge(priv, e.host(), room, ch.Nonce)),
	}
	if err := writeJSON(ctx, c1, reg); err != nil {
		t.Fatal(err)
	}
	var ready connectrelay.Ready
	if err := readJSON(ctx, c1, &ready); err != nil || ready.Type != connectrelay.TypeReady {
		t.Fatalf("first register: %v %q", err, ready.Type)
	}
	c1.Close(websocket.StatusNormalClosure, "")

	c2, _, err := dial(ctx, url, bearer(testToken))
	if err != nil {
		t.Fatal(err)
	}
	defer c2.CloseNow()
	var ch2 connectrelay.Challenge
	if err := readJSON(ctx, c2, &ch2); err != nil {
		t.Fatal(err)
	}
	if ch2.Nonce == ch.Nonce {
		t.Fatal("two challenges with one nonce")
	}
	if err := writeJSON(ctx, c2, reg); err != nil {
		t.Fatal(err)
	}
	_, _, err = c2.Read(ctx)
	if got := statusOf(err); got != connectrelay.CloseBadRegister {
		t.Fatalf("replayed register: %v (%v), want %d", got, err, connectrelay.CloseBadRegister)
	}
}

// The refusal paths log too, and still no token, full room or address.
func TestLogsNoSecretsOnRefusals(t *testing.T) {
	e := newEnv(t, nil)
	ctx := ctxT(t, 20*time.Second)
	const wrong = "wrong-token-Qm81vX-made-up"

	pubA, privA := newKey(t)
	roomA := connectrelay.RoomFor(pubA)
	if c, _, err := dial(ctx, e.wsURL(connectrelay.PathHost+"?room="+roomA), bearer(wrong)); err == nil {
		c.CloseNow()
	}
	if _, _, err := e.openHost(ctx, hostOpts{token: testToken, tamper: func(s []byte) { s[0] ^= 1 }}); statusOf(err) != connectrelay.CloseBadRegister {
		t.Fatalf("bad signature: %v", err)
	}
	host, _, err := e.openHost(ctx, hostOpts{token: testToken, pub: pubA, priv: privA})
	if err != nil {
		t.Fatal(err)
	}
	defer host.CloseNow()
	readsForever(ctx, host)
	if _, _, err := e.openHost(ctx, hostOpts{token: testToken, pub: pubA, priv: privA}); statusOf(err) != connectrelay.CloseRoomTaken {
		t.Fatalf("second host: %v", err)
	}
	if c, _, err := e.accept(ctx, roomA, base64.RawURLEncoding.EncodeToString(randBytes(t, 16)), wrong); err == nil {
		c.CloseNow()
	}
	pubB, _ := newKey(t)
	roomB := connectrelay.RoomFor(pubB)
	for i := 0; i < 31; i++ {
		if c, _, err := e.phone(ctx, roomB); err == nil {
			waitClosed(ctx, c)
		}
	}

	logs := e.logs.String()
	for _, code := range []string{"code=401", "code=4403", "code=4409", "code=4404", "code=429"} {
		if !strings.Contains(logs, "refused room=") || !strings.Contains(logs, code) {
			t.Fatalf("log has no refused line with %s:\n%s", code, logs)
		}
	}
	for name, secret := range map[string]string{
		"token": testToken, "wrong token": wrong, "room A": roomA, "room B": roomB,
		"IPv4 address": "127.0.0.1", "IPv6 address": "::1",
	} {
		if strings.Contains(logs, secret) {
			t.Fatalf("log contains the %s:\n%s", name, logs)
		}
	}
}

// A flood of refusals writes a bounded number of lines per minute, then one
// line with how many were left out.
func TestRefusedLogLimited(t *testing.T) {
	clk := newClock()
	// HostRate also counts /v1/accept; raised so all 50 reach the token check and get 401.
	e := newEnv(t, func(c *connectrelay.Config) { c.Now = clk.Now; c.HostRate = 100 })
	cl := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	get := func() {
		resp, err := cl.Get(e.ts.URL + connectrelay.PathAccept + "?room=AAAAAAAAAAAAAAAAAAAAAA&id=AAAAAAAAAAAAAAAAAAAAAA")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status %d, want 401", resp.StatusCode)
		}
	}
	for i := 0; i < 50; i++ {
		get()
	}
	count := func(sub string) int { return strings.Count(e.logs.String(), sub) }
	if n := count("refused room="); n > 10 || n == 0 {
		t.Fatalf("%d refused lines for 50 refusals in one minute, want 1 to 10:\n%s", n, e.logs.String())
	}
	logged := count("refused room=")
	clk.Add(61 * time.Second)
	get()
	if !strings.Contains(e.logs.String(), fmt.Sprintf("refused-dropped code=401 count=%d", 50-logged)) {
		t.Fatalf("no line counting the %d dropped refusals:\n%s", 50-logged, e.logs.String())
	}
}

// /v1/host is limited per address too, before the token check.
func TestHostRate(t *testing.T) {
	e := newEnv(t, nil)
	cl := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	pub, _ := newKey(t)
	u := e.ts.URL + connectrelay.PathHost + "?room=" + connectrelay.RoomFor(pub)
	for i := 0; i < 31; i++ {
		req, _ := http.NewRequest("GET", u, nil)
		req.Header.Set("Authorization", "Bearer guess-"+fmt.Sprint(i))
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		want := http.StatusUnauthorized
		if i == 30 {
			want = http.StatusTooManyRequests
		}
		if resp.StatusCode != want {
			t.Fatalf("request %d: %d, want %d", i+1, resp.StatusCode, want)
		}
	}
}

// An accept whose WebSocket upgrade fails leaves no goroutine behind.
func TestAcceptUpgradeFailureNoLeak(t *testing.T) {
	e := newEnv(t, nil)
	ctx := ctxT(t, 20*time.Second)
	host, room := e.mustHost(ctx)
	defer host.CloseNow()
	cl := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	settle := func() int {
		time.Sleep(200 * time.Millisecond)
		return runtime.NumGoroutine()
	}
	base := settle()
	for i := 0; i < 5; i++ {
		phone, _, err := e.phone(ctx, room)
		if err != nil {
			t.Fatal(err)
		}
		id, err := nextIncoming(ctx, host)
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest("GET", e.ts.URL+connectrelay.PathAccept+"?room="+room+"&id="+id, nil)
		req.Header.Set("Authorization", "Bearer "+testToken)
		resp, err := cl.Do(req) // a plain GET: not an upgrade
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusSwitchingProtocols {
			t.Fatal("plain GET was upgraded")
		}
		waitClosed(ctxT(t, 3*time.Second), phone)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		n := settle()
		if n <= base+1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d goroutines after 5 failed accepts, %d before", n, base)
		}
	}
}

func TestNormalizeHost(t *testing.T) {
	for in, want := range map[string]string{
		"relay.example.com":                       "relay.example.com",
		"Relay.Example.COM":                       "relay.example.com",
		"relay.example.com:443":                   "relay.example.com",
		"relay.example.com.":                      "relay.example.com",
		"Relay.Example.com.:8443":                 "relay.example.com",
		"wss://Relay.Example.com:443/":            "relay.example.com",
		"wss://relay.example.com/v1/host?room=ab": "relay.example.com",
		"[2001:db8::1]:443":                       "2001:db8::1",
		"[2001:DB8::1]":                           "2001:db8::1",
		"wss://[2001:db8::1]:8443/":               "2001:db8::1",
		"192.0.2.7:8080":                          "192.0.2.7",
		"":                                        "",
	} {
		if got := connectrelay.NormalizeHost(in); got != want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// A relay that got a the host's signature for itself cannot use it to
// register that the host on another relay: relay B's nonce, signed with
// relay A's host name, is refused by B.
func TestWrongHost(t *testing.T) {
	e := newEnv(t, nil)
	ctx := ctxT(t, 10*time.Second)
	_, _, err := e.openHost(ctx, hostOpts{token: testToken, host: "relay-a.example.net"})
	if got := statusOf(err); got != connectrelay.CloseBadRegister {
		t.Fatalf("register for relay A on relay B: %v (%v), want 4403", got, err)
	}
	waitLog(t, e, "wrong-host")
	if strings.Contains(e.logs.String(), "relay-a") {
		t.Fatalf("log has the host name the register sent:\n%s", e.logs.String())
	}
	// B's own name in the message but A's in the signature: a bad signature.
	_, _, err = e.openHost(ctx, hostOpts{token: testToken, signAs: "relay-a.example.net"})
	if got := statusOf(err); got != connectrelay.CloseBadRegister {
		t.Fatalf("signature over relay A's name: %v (%v), want 4403", got, err)
	}
	// Control: the same steps with B's name register.
	c, _ := e.mustHost(ctx)
	c.CloseNow()
}

// The register host and PublicHost are compared after NormalizeHost.
func TestHostNormalizedOnRegister(t *testing.T) {
	for _, tc := range []struct{ public, host string }{
		{"Relay-B.Example.net:8443", "relay-b.example.net"},
		{"relay-b.example.net", "RELAY-B.example.net:443"},
		{"relay-b.example.net", "relay-b.example.net."},
		{"relay-b.example.net.", "wss://Relay-B.Example.net/"},
	} {
		e := newEnv(t, func(c *connectrelay.Config) { c.PublicHost = tc.public })
		ctx := ctxT(t, 10*time.Second)
		c, _, err := e.openHost(ctx, hostOpts{token: testToken, host: tc.host})
		if err != nil {
			t.Errorf("PublicHost %q, register host %q: %v, want registered", tc.public, tc.host, err)
			continue
		}
		c.CloseNow()
	}
}

// The Host header is written by whoever dials, so it never counts: only
// PublicHost does.
func TestHostHeaderIgnored(t *testing.T) {
	e := newEnv(t, nil)
	ctx := ctxT(t, 10*time.Second)
	c, _, err := e.openHost(ctx, hostOpts{token: testToken, header: "relay-a.example.net"})
	if err != nil {
		t.Fatalf("register for %s with Host relay-a.example.net: %v, want registered", e.host(), err)
	}
	c.CloseNow()
	for _, header := range []string{"", "relay-a.example.net", testPublicHost} {
		_, _, err := e.openHost(ctx, hostOpts{token: testToken, header: header, host: "relay-a.example.net"})
		if got := statusOf(err); got != connectrelay.CloseBadRegister {
			t.Errorf("register for relay-a.example.net with Host %q on %s: %v (%v), want 4403", header, testPublicHost, got, err)
		}
	}
}

// Relay A forwards B's nonce to the the host, which signs for A; A then
// registers on B with both the Host header and host naming A. A relay with
// no PublicHost has nothing but that header to compare with, so it must not
// start at all.
func TestNoPublicHost(t *testing.T) {
	srv, err := connectrelay.NewServer(connectrelay.Config{Token: testToken})
	if err == nil {
		ts := httptest.NewServer(srv)
		defer func() { srv.Close(); ts.Close() }()
		e := &env{t: t, srv: srv, ts: ts, logs: &syncBuf{}, pub: "relay-a.example.net"}
		c, _, rerr := e.openHost(ctxT(t, 10*time.Second), hostOpts{token: testToken, header: "relay-a.example.net"})
		if rerr == nil {
			c.CloseNow()
			t.Fatal("a relay with no PublicHost took a register whose Host header and host both name relay A")
		}
		t.Fatalf("NewServer with no PublicHost: no error, want one (register got %v)", rerr)
	}
	for _, public := range []string{":443", " ", "[]"} {
		if _, err := connectrelay.NewServer(connectrelay.Config{Token: testToken, PublicHost: public}); err == nil {
			t.Errorf("NewServer with PublicHost %q: no error, want one", public)
		}
	}
}

func waitLog(t *testing.T, e *env, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(e.logs.String(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("log has no %q:\n%s", want, e.logs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}
