package connectrelay_test

// Fail-closed checks for the relay: it is not a proxy, an amplifier or an SSRF hop, rooms stay
// apart, and anything it cannot parse ends the connection. Helpers come from relay_test.go.

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/jt-wang/tailpocket/connectrelay"
)

// victim is a TCP listener that counts every connection made to it.
type victim struct {
	ln net.Listener
	n  atomic.Int64
}

func newVictim(t *testing.T) *victim {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	v := &victim{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			v.n.Add(1)
			c.Close()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return v
}

func (v *victim) addr() string { return v.ln.Addr().String() }

// rawExchange sends req on a fresh TCP connection to addr and returns every byte the relay sent
// back before closing or going quiet for 500 ms.
func rawExchange(t *testing.T, addr, req string) []byte {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := io.WriteString(c, req); err != nil {
		t.Fatal(err)
	}
	var out []byte
	buf := make([]byte, 4096)
	for {
		c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := c.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			return out
		}
	}
}

func statusLine(b []byte) string {
	line, _, _ := strings.Cut(string(b), "\r\n")
	return line
}

// newServedEnv is newEnv with the http.Server set up as tailpocket-relay sets it up.
func newServedEnv(t *testing.T, mod func(*connectrelay.Config)) *env {
	t.Helper()
	logs := &syncBuf{}
	cfg := connectrelay.Config{Token: testToken, PublicHost: testPublicHost, Logger: log.New(logs, "", 0)}
	if mod != nil {
		mod(&cfg)
	}
	srv, err := connectrelay.NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(srv)
	ts.Config.DisableGeneralOptionsHandler = true
	ts.Config.MaxHeaderBytes = 8 << 10
	ts.Start()
	t.Cleanup(func() { srv.Close(); ts.Close() })
	return &env{t: t, srv: srv, ts: ts, logs: logs, pub: cfg.PublicHost}
}

// Proxy-style requests are never forwarded, and the ones only a proxy takes (CONNECT, an
// absolute-form URL, OPTIONS *) get 400 and no upgrade, even when their path names a relay
// endpoint. None reaches the victim.
func TestFailClosedNotAProxy(t *testing.T) {
	e := newServedEnv(t, nil)
	v := newVictim(t)
	relay := strings.TrimPrefix(e.ts.URL, "http://")
	va := v.addr()
	room := connectrelay.RoomFor(mustPub(t))
	ws := "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
	reqs := map[string]struct{ req, status string }{
		"CONNECT":             {"CONNECT " + va + " HTTP/1.1\r\nHost: " + va + "\r\n\r\n", "400"},
		"CONNECT localhost":   {"CONNECT localhost:" + strings.Split(va, ":")[1] + " HTTP/1.1\r\nHost: " + va + "\r\n\r\n", "400"},
		"CONNECT a path":      {"CONNECT " + connectrelay.PathPhone + "?room=" + room + " HTTP/1.1\r\nHost: x\r\n" + ws + "\r\n", "400"},
		"absolute GET":        {"GET http://" + va + "/ HTTP/1.1\r\nHost: " + va + "\r\nConnection: close\r\n\r\n", "400"},
		"absolute POST":       {"POST http://" + va + "/x HTTP/1.1\r\nHost: " + va + "\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi", "400"},
		"absolute healthz":    {"GET http://" + va + "/healthz HTTP/1.1\r\nHost: " + va + "\r\nConnection: close\r\n\r\n", "400"},
		"absolute host path":  {"GET http://" + va + connectrelay.PathHost + "?room=" + room + " HTTP/1.1\r\nHost: " + va + "\r\nAuthorization: Bearer " + testToken + "\r\n" + ws + "\r\n", "400"},
		"absolute phone path": {"GET http://" + va + connectrelay.PathPhone + "?room=" + room + " HTTP/1.1\r\nHost: " + va + "\r\n" + ws + "\r\n", "400"},
		"absolute wss":        {"GET wss://" + va + connectrelay.PathPhone + "?room=" + room + " HTTP/1.1\r\nHost: " + va + "\r\n" + ws + "\r\n", "400"},
		"OPTIONS *":           {"OPTIONS * HTTP/1.1\r\nHost: " + va + "\r\nConnection: close\r\n\r\n", "400"},
		"proxy auth":          {"GET http://" + va + "/ HTTP/1.1\r\nHost: " + va + "\r\nProxy-Authorization: Basic eDp4\r\nConnection: close\r\n\r\n", "400"},
		"HTTP/1.0 absolute":   {"GET http://" + va + "/ HTTP/1.0\r\n\r\n", "400"},
		// Origin-form: answered for the relay itself, whatever Host and forwarding headers say.
		"foreign Host":          {"GET / HTTP/1.1\r\nHost: " + va + "\r\nConnection: close\r\n\r\n", "404"},
		"foreign Host phone":    {"GET " + connectrelay.PathPhone + "?room=" + room + " HTTP/1.1\r\nHost: " + va + "\r\n" + ws + "\r\n", "101"}, // then 4404: no host
		"forwarding headers":    {"GET / HTTP/1.1\r\nHost: x\r\nX-Forwarded-Host: " + va + "\r\nForwarded: host=" + va + "\r\nX-Original-URL: http://" + va + "/\r\nConnection: close\r\n\r\n", "404"},
		"h2c upgrade":           {"GET / HTTP/1.1\r\nHost: " + va + "\r\nUpgrade: h2c\r\nConnection: Upgrade, HTTP2-Settings\r\nHTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n\r\n", "404"},
		"websocket elsewhere":   {"GET /ws HTTP/1.1\r\nHost: " + va + "\r\n" + ws + "\r\n", "404"},
		"path names an address": {"GET /" + va + "/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", "404"},
	}
	for name, tc := range reqs {
		if line := statusLine(rawExchange(t, relay, tc.req)); !strings.Contains(line, " "+tc.status+" ") {
			t.Errorf("%s: relay answered %q, want %s", name, line, tc.status)
		}
	}
	time.Sleep(200 * time.Millisecond)
	if n := v.n.Load(); n != 0 {
		t.Fatalf("the victim got %d connection(s) through the relay, want 0", n)
	}
	// The handler refuses them itself, also behind an http.Server that answers OPTIONS * for it.
	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodOptions, "*", nil),
		httptest.NewRequest(http.MethodGet, "http://"+va+connectrelay.PathHealth, nil),
		httptest.NewRequest(http.MethodConnect, va, nil),
	} {
		rec := httptest.NewRecorder()
		e.srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("ServeHTTP %s %s: %d, want 400", req.Method, req.RequestURI, rec.Code)
		}
	}
}

// No field of a request is ever resolved or dialled: a room, a register host, an accept id, an
// X-Forwarded-For hop or a query parameter that names the victim reaches nobody.
func TestFailClosedRequestFieldsAreNeverDialled(t *testing.T) {
	e := newEnv(t, behindProxy)
	v := newVictim(t)
	va := v.addr()
	ctx := ctxT(t, 20*time.Second)
	esc := func(s string) string { return strings.NewReplacer(":", "%3A", "/", "%2F").Replace(s) }

	for _, q := range []string{"room=" + esc(va), "room=" + esc("http://"+va+"/"), "room=x&url=" + esc("http://"+va), "room=x&host=" + esc(va)} {
		for _, path := range []string{connectrelay.PathPhone, connectrelay.PathHost, connectrelay.PathAccept} {
			c, resp, err := dial(ctx, e.wsURL(path+"?"+q), bearer(testToken))
			if err == nil {
				c.CloseNow()
				t.Errorf("%s?%s upgraded", path, q)
			} else if dialStatus(resp) != http.StatusBadRequest {
				t.Errorf("%s?%s: status %d, want 400", path, q, dialStatus(resp))
			}
		}
	}
	// A register naming the victim as the relay's host is refused with 4403.
	_, _, err := e.openHost(ctx, hostOpts{token: testToken, host: va})
	if got := statusOf(err); got != connectrelay.CloseBadRegister {
		t.Errorf("register for host %s: %v (%v), want 4403", va, got, err)
	}
	_, _, err = e.openHost(ctx, hostOpts{token: testToken, host: "http://" + va + "/"})
	if got := statusOf(err); got != connectrelay.CloseBadRegister {
		t.Errorf("register for host http://%s/: %v, want 4403", va, got)
	}
	// X-Forwarded-For only picks the address limits count against.
	c, _, err := e.phoneFrom(ctx, connectrelay.RoomFor(mustPub(t)), va)
	if err == nil {
		waitClosed(ctx, c)
	}
	h := fromAddr(va)
	h.Set("Authorization", "Bearer "+testToken)
	if c, _, err := dial(ctx, e.wsURL(connectrelay.PathHost+"?room="+esc(va)), h); err == nil {
		c.CloseNow()
	}
	time.Sleep(200 * time.Millisecond)
	if n := v.n.Load(); n != 0 {
		t.Fatalf("the victim got %d connection(s), want 0", n)
	}
}

// Every refusal before authentication is a short fixed answer: it does not grow with the request,
// and it is never more than a small multiple of the smallest request that gets it.
func TestFailClosedNoAmplificationBeforeAuth(t *testing.T) {
	e := newEnv(t, nil)
	relay := strings.TrimPrefix(e.ts.URL, "http://")
	room := connectrelay.RoomFor(mustPub(t))
	id := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	pad := "X-Pad: " + strings.Repeat("a", 4000) + "\r\n"
	const maxReply = 256 // bytes, status line, headers and body
	cases := []struct {
		name, req string
		status    string
	}{
		{"host without token", "GET " + connectrelay.PathHost + "?room=" + room + " HTTP/1.1\r\nHost: x\r\n%s\r\n", "401"},
		{"host wrong token", "GET " + connectrelay.PathHost + "?room=" + room + " HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer nope\r\n%s\r\n", "401"},
		{"accept without token", "GET " + connectrelay.PathAccept + "?room=" + room + "&id=" + id + " HTTP/1.1\r\nHost: x\r\n%s\r\n", "401"},
		{"accept unknown id", "GET " + connectrelay.PathAccept + "?room=" + room + "&id=" + id + " HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + testToken + "\r\n%s\r\n", "404"},
		{"unknown path", "GET /nope HTTP/1.1\r\nHost: x\r\n%s\r\n", "404"},
		{"CONNECT", "CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: x\r\n%s\r\n", "400"},
		{"absolute-form", "GET http://127.0.0.1:1/ HTTP/1.1\r\nHost: x\r\n%s\r\n", "400"},
		{"phone POST", "POST " + connectrelay.PathPhone + "?room=" + room + " HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n%s\r\n", "405"},
		{"phone bad room", "GET " + connectrelay.PathPhone + "?room=short HTTP/1.1\r\nHost: x\r\n%s\r\n", "400"},
	}
	for _, tc := range cases {
		for _, extra := range []string{"Connection: close\r\n", pad + "Connection: close\r\n"} {
			req := fmt.Sprintf(tc.req, extra)
			resp := rawExchange(t, relay, req)
			if line := statusLine(resp); !strings.Contains(line, " "+tc.status+" ") {
				t.Errorf("%s: %q, want %s", tc.name, line, tc.status)
			}
			if len(resp) > maxReply || len(resp) > 8*len(req) {
				t.Errorf("%s: %d-byte request got %d bytes back, want at most min(%d, 8x)", tc.name, len(req), len(resp), maxReply)
			}
		}
	}
}

// countingClient counts the bytes each way on every TCP connection it dials.
type counted struct{ in, out atomic.Int64 }

type countConn struct {
	net.Conn
	c *counted
}

func (c *countConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.c.in.Add(int64(n))
	return n, err
}

func (c *countConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.c.out.Add(int64(n))
	return n, err
}

func (c *counted) client() *http.Client {
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, n, a string) (net.Conn, error) {
		nc, err := (&net.Dialer{}).DialContext(ctx, n, a)
		if err != nil {
			return nil, err
		}
		return &countConn{Conn: nc, c: c}, nil
	}}}
}

// A phone in a room without a host is closed at once, with a reply no bigger than its request.
func TestFailClosedPhoneWithoutHostClosesAtOnce(t *testing.T) {
	e := newEnv(t, nil)
	ctx := ctxT(t, 10*time.Second)
	var cnt counted
	start := time.Now()
	c, _, err := websocket.Dial(ctx, e.wsURL(connectrelay.PathPhone+"?room="+connectrelay.RoomFor(mustPub(t))), &websocket.DialOptions{HTTPClient: cnt.client()})
	if err != nil {
		t.Fatal(err)
	}
	code, _ := waitClosed(ctx, c)
	if code != connectrelay.CloseNoHost {
		t.Fatalf("close %v, want 4404", code)
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("closed after %v, want at once", el)
	}
	c.CloseNow()
	if in, out := cnt.in.Load(), cnt.out.Load(); in > out {
		t.Fatalf("phone sent %d bytes and got %d back, want no more than it sent", out, in)
	}
}

// readAll collects every message on c until it closes or is quiet for quiet.
func readAll(c *websocket.Conn, quiet time.Duration) (msgs [][]byte, typs []websocket.MessageType) {
	for {
		ctx, cancel := context.WithTimeout(context.Background(), quiet)
		typ, b, err := c.Read(ctx)
		cancel()
		if err != nil {
			return msgs, typs
		}
		msgs = append(msgs, b)
		typs = append(typs, typ)
	}
}

// Each message goes once, unchanged, to the paired end only: not back to its sender, not to another
// phone of the same room, not to another room, and not on a registration connection.
func TestFailClosedForwardOnceToThePairOnly(t *testing.T) {
	e := newEnv(t, nil)
	ctx := ctxT(t, 20*time.Second)
	hostA, roomA := e.mustHost(ctx)
	defer hostA.CloseNow()
	hostB, roomB := e.mustHost(ctx)
	defer hostB.CloseNow()
	phoneA1, accA1 := e.pair(ctx, hostA, roomA)
	phoneA2, accA2 := e.pair(ctx, hostA, roomA)
	phoneB, accB := e.pair(ctx, hostB, roomB)
	for _, c := range []*websocket.Conn{phoneA1, accA1, phoneA2, accA2, phoneB, accB} {
		defer c.CloseNow()
	}

	const n = 50
	var sent [][]byte
	for i := 0; i < n; i++ {
		m := randBytes(t, 1+i*37)
		sent = append(sent, m)
		if err := phoneA1.Write(ctx, websocket.MessageBinary, m); err != nil {
			t.Fatal(err)
		}
	}
	down := randBytes(t, 999)
	if err := accA1.Write(ctx, websocket.MessageBinary, down); err != nil {
		t.Fatal(err)
	}

	type result struct {
		name string
		msgs [][]byte
	}
	var wg sync.WaitGroup
	results := make(chan result, 8)
	for name, c := range map[string]*websocket.Conn{"accA1": accA1, "phoneA1": phoneA1, "phoneA2": phoneA2, "accA2": accA2, "phoneB": phoneB, "accB": accB, "hostA": hostA, "hostB": hostB} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			msgs, _ := readAll(c, 500*time.Millisecond)
			results <- result{name, msgs}
		}()
	}
	wg.Wait()
	close(results)
	for r := range results {
		switch r.name {
		case "accA1":
			if len(r.msgs) != n {
				t.Fatalf("accA1 got %d messages, want exactly %d", len(r.msgs), n)
			}
			for i := range sent {
				if string(r.msgs[i]) != string(sent[i]) {
					t.Fatalf("accA1 message %d differs", i)
				}
			}
		case "phoneA1":
			if len(r.msgs) != 1 || string(r.msgs[0]) != string(down) {
				t.Fatalf("phoneA1 got %d messages, want only accA1's one", len(r.msgs))
			}
		default:
			if len(r.msgs) != 0 {
				t.Fatalf("%s got %d message(s) it was never sent", r.name, len(r.msgs))
			}
		}
	}
}

// A phone cannot stand in for a host: accept needs the token and the id the relay sent on that
// room's registration, and an id works once, in its own room only. (Token-less registration,
// one host per room and signature checks are TestToken, TestOneHostPerRoom and TestBadRegister.)
func TestFailClosedAcceptOnlyItsOwnPhone(t *testing.T) {
	e := newEnv(t, nil)
	ctx := ctxT(t, 20*time.Second)
	hostA, roomA := e.mustHost(ctx)
	defer hostA.CloseNow()
	hostB, roomB := e.mustHost(ctx)
	defer hostB.CloseNow()
	phone, _, err := e.phone(ctx, roomA)
	if err != nil {
		t.Fatal(err)
	}
	defer phone.CloseNow()
	id, err := nextIncoming(ctx, hostA)
	if err != nil {
		t.Fatal(err)
	}
	var made [16]byte
	rand.Read(made[:])
	for name, try := range map[string][2]string{
		"A's id in room B":   {roomB, id},
		"made-up id":         {roomA, base64.RawURLEncoding.EncodeToString(made[:])},
		"A's id, no room":    {"", id},
		"A's id, lower-case": {roomA, strings.ToLower(id)},
	} {
		c, resp, err := e.accept(ctx, try[0], try[1], testToken)
		if err == nil {
			c.CloseNow()
			t.Fatalf("%s: accepted", name)
		}
		if s := dialStatus(resp); s != http.StatusNotFound && s != http.StatusBadRequest {
			t.Fatalf("%s: status %d, want 404 or 400", name, s)
		}
	}
	// A phone dialling /v1/accept as itself has no token.
	if c, resp, err := e.accept(ctx, roomA, id, ""); err == nil || dialStatus(resp) != http.StatusUnauthorized {
		if c != nil {
			c.CloseNow()
		}
		t.Fatalf("accept without token: %d", dialStatus(resp))
	}
	acc, _, err := e.accept(ctx, roomA, id, testToken)
	if err != nil {
		t.Fatalf("the right accept: %v", err)
	}
	defer acc.CloseNow()
	if c, resp, err := e.accept(ctx, roomA, id, testToken); err == nil || dialStatus(resp) != http.StatusNotFound {
		if c != nil {
			c.CloseNow()
		}
		t.Fatalf("second accept of one id: %d, want 404", dialStatus(resp))
	}
	// Host B was told nothing about A's phone.
	if msgs, _ := readAll(hostB, 300*time.Millisecond); len(msgs) != 0 {
		t.Fatalf("host B got %d message(s) about room A", len(msgs))
	}
}

// Anything the relay cannot parse while a host registers ends that connection without a room.
func TestFailClosedBadRegisterMessages(t *testing.T) {
	e := newEnv(t, nil)
	ctx := ctxT(t, 30*time.Second)
	cases := map[string]struct {
		typ websocket.MessageType
		msg []byte
	}{
		"binary":       {websocket.MessageBinary, []byte(`{"type":"register"}`)},
		"not json":     {websocket.MessageText, []byte("register please")},
		"unknown type": {websocket.MessageText, []byte(`{"type":"incoming","id":"AAAAAAAAAAAAAAAAAAAAAA"}`)},
		"ready":        {websocket.MessageText, []byte(`{"type":"ready"}`)},
		"bad base64":   {websocket.MessageText, []byte(`{"type":"register","pub":"!!","host":"` + testPublicHost + `","sig":"!!"}`)},
		"short pub":    {websocket.MessageText, []byte(`{"type":"register","pub":"AAAA","host":"` + testPublicHost + `","sig":"AAAA"}`)},
		"json array":   {websocket.MessageText, []byte(`[{"type":"register"}]`)},
		"too big":      {websocket.MessageText, append([]byte(`{"type":"register","pub":"`), make([]byte, connectrelay.MaxMessage+2)...)},
	}
	for name, tc := range cases {
		pub := mustPub(t)
		room := connectrelay.RoomFor(pub)
		c, _, err := dial(ctx, e.wsURL(connectrelay.PathHost+"?room="+room), bearer(testToken))
		if err != nil {
			t.Fatal(err)
		}
		var ch connectrelay.Challenge
		if err := readJSON(ctx, c, &ch); err != nil {
			t.Fatal(err)
		}
		_ = c.Write(ctx, tc.typ, tc.msg)
		code, err := waitClosed(ctxT(t, 5*time.Second), c)
		if err != nil && strings.Contains(err.Error(), "still open") {
			t.Fatalf("%s: still open", name)
		}
		if code != connectrelay.CloseBadRegister && code != websocket.StatusMessageTooBig {
			t.Errorf("%s: close %v, want 4403 (or 1009 for too big)", name, code)
		}
		p, _, err := e.phone(ctx, room)
		if err != nil {
			t.Fatal(err)
		}
		if code, _ := waitClosed(ctx, p); code != connectrelay.CloseNoHost {
			t.Errorf("%s: a phone in the room got %v, want 4404: the room was registered", name, code)
		}
	}
}

// After ready the relay expects nothing from the host; a message ends the registration and frees
// the room instead of being skipped.
func TestFailClosedMessageOnRegistration(t *testing.T) {
	e := newEnv(t, nil)
	ctx := ctxT(t, 10*time.Second)
	for _, typ := range []websocket.MessageType{websocket.MessageText, websocket.MessageBinary} {
		host, room := e.mustHost(ctx)
		phone, acc := e.pair(ctx, host, room)
		_ = host.Write(ctx, typ, []byte(`{"type":"incoming","id":"AAAAAAAAAAAAAAAAAAAAAA"}`))
		if code, _ := waitClosed(ctxT(t, 5*time.Second), host); code != websocket.StatusPolicyViolation {
			t.Fatalf("%v on the registration: host closed with %v, want 1008", typ, code)
		}
		if code, _ := waitClosed(ctxT(t, 5*time.Second), phone); code != connectrelay.CloseNoHost {
			t.Fatalf("its phone closed with %v, want 4404", code)
		}
		acc.CloseNow()
	}
}

// A pair carries binary messages only. A text message, or a frame the WebSocket parser rejects,
// ends the pair; the other end gets 1001 peer-gone and not a byte of it.
func TestFailClosedBadFramesInAPair(t *testing.T) {
	// Client frames: FIN set, masked with a zero key so the payload is as written.
	masked := func(b0 byte, payload []byte) []byte {
		f := []byte{b0, 0x80 | byte(len(payload)), 0, 0, 0, 0}
		return append(f, payload...)
	}
	cases := map[string][]byte{
		"text message":                  masked(0x81, []byte("hello")),
		"reserved opcode 3":             masked(0x83, []byte("hello")),
		"reserved opcode 0xB":           masked(0x8B, nil),
		"RSV1 set":                      masked(0xC2, []byte("hello")),
		"unmasked":                      {0x82, 0x05, 'h', 'e', 'l', 'l', 'o'},
		"continuation first":            masked(0x80, []byte("hello")),
		"fragmented ping":               masked(0x09, nil),
		"ping over 125":                 append([]byte{0x89, 0x80 | 126, 0, 200, 0, 0, 0, 0}, make([]byte, 200)...),
		"64-bit length 2^63":            {0x82, 0x80 | 127, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		"1 MiB text frame, cut short":   append([]byte{0x81, 0x80 | 127, 0, 0, 0, 0, 0, 0x10, 0, 0, 0, 0, 0, 0}, "hel"...),
		"1 MiB frame, cut at the limit": append([]byte{0x82, 0x80 | 127, 0, 0, 0, 0, 0, 0x10, 0, 0, 0, 0, 0, 0}, make([]byte, connectrelay.MaxMessage+1)...),
		"binary after bad text":         append(masked(0x01, []byte("hel")), masked(0x82, []byte("x"))...),
	}
	for name, frame := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, nil)
			ctx := ctxT(t, 15*time.Second)
			host, room := e.mustHost(ctx)
			defer host.CloseNow()
			raw, br := rawPhone(t, e, room)
			defer raw.Close()
			id, err := nextIncoming(ctx, host)
			if err != nil {
				t.Fatal(err)
			}
			acc, _, err := e.accept(ctx, room, id, testToken)
			if err != nil {
				t.Fatal(err)
			}
			defer acc.CloseNow()
			// A good message first proves the pair is up.
			if _, err := raw.Write(masked(0x82, []byte("ok"))); err != nil {
				t.Fatal(err)
			}
			if _, b, err := acc.Read(ctx); err != nil || string(b) != "ok" {
				t.Fatalf("good message: %q %v", b, err)
			}
			raw.Write(frame)
			_, _, err = acc.Read(ctxT(t, 5*time.Second))
			var ce websocket.CloseError
			if !errors.As(err, &ce) || ce.Code != websocket.StatusGoingAway || ce.Reason != connectrelay.ReasonPeerGone {
				t.Fatalf("accept end: %v, want 1001 peer-gone and no message", err)
			}
			// And the phone's TCP connection ends.
			// At most the relay's 5 s close wait, even when the phone stopped partway through a frame.
			raw.SetReadDeadline(time.Now().Add(8 * time.Second))
			if _, err := io.Copy(io.Discard, br); err != nil {
				t.Fatalf("phone connection still open: %v", err)
			}
		})
	}
}

// rawPhone opens /v1/phone with a hand-written upgrade and returns the TCP connection.
func rawPhone(t *testing.T, e *env, room string) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("tcp", strings.TrimPrefix(e.ts.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(c, "GET "+connectrelay.PathPhone+"?room="+room+" HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v %v", resp, err)
	}
	return c, br
}

// /v1/accept draws on the same per-address budget as /v1/host, before its token check, so guessing
// the token there is no faster; and without the token every room and id gets the same 401.
func TestFailClosedAcceptRateAndTokenFirst(t *testing.T) {
	e := newEnv(t, func(c *connectrelay.Config) { behindProxy(c); c.HostRate = 4 })
	ctx := ctxT(t, 20*time.Second)
	host, room := e.mustHost(ctx) // one of the 4 from 127.0.0.1
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
	get := func(path, tok, from string) (int, string) {
		req, _ := http.NewRequest(http.MethodGet, e.ts.URL+path, nil)
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		req.Header.Set("X-Forwarded-For", from)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	other := connectrelay.RoomFor(mustPub(t))
	made := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	accept := func(r, i string) string { return connectrelay.PathAccept + "?room=" + r + "&id=" + i }
	// Wrong token: the waiting phone, an empty room, a made-up id and a malformed room look alike.
	var first string
	for i, path := range []string{accept(room, id), accept(other, made), accept(room, made), accept("x", "y")} {
		code, body := get(path, "wrong-token", "203.0.113.1")
		if code != http.StatusUnauthorized || (i > 0 && body != first) {
			t.Fatalf("wrong token, %s: %d %q, want the same 401 for all", path, code, body)
		}
		first = body
	}
	// The 5th request from that address in the minute is refused before the token is looked at,
	// and so is a registration from it: one budget.
	if code, _ := get(accept(room, id), testToken, "203.0.113.1"); code != http.StatusTooManyRequests {
		t.Fatalf("5th accept from one address: %d, want 429", code)
	}
	if code, _ := get(connectrelay.PathHost+"?room="+other, testToken, "203.0.113.1"); code != http.StatusTooManyRequests {
		t.Fatalf("host after 4 accepts from one address: %d, want 429", code)
	}
	// With the token, only now do room and id matter.
	if code, _ := get(accept("x", "y"), testToken, "203.0.113.2"); code != http.StatusBadRequest {
		t.Fatalf("right token, malformed room: %d, want 400", code)
	}
	if code, _ := get(accept(other, made), testToken, "203.0.113.2"); code != http.StatusNotFound {
		t.Fatalf("right token, unknown room: %d, want 404", code)
	}
	// The waiting phone was not used up by any of it.
	acc, _, err := dial(ctx, e.wsURL(accept(room, id)), func() http.Header {
		h := fromAddr("203.0.113.3")
		h.Set("Authorization", "Bearer "+testToken)
		return h
	}())
	if err != nil {
		t.Fatalf("the right accept: %v", err)
	}
	acc.CloseNow()
}
