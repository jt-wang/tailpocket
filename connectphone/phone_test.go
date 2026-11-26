package connectphone

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jt-wang/tailpocket/connectinvite"
	"github.com/jt-wang/tailpocket/internal/testhook"
)

func TestKeys(t *testing.T) {
	k := NewKey()
	if !strings.HasPrefix(k, "privkey:") {
		t.Fatalf("key %q", k)
	}
	pub, err := PublicKey(k)
	if err != nil || !strings.HasPrefix(pub, "nodekey:") {
		t.Fatalf("public %q %v", pub, err)
	}
	if again, _ := PublicKey(k); again != pub {
		t.Fatal("public key not stable")
	}
	for _, bad := range []string{"", "privkey:00", pub} {
		if _, err := PublicKey(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestPairRefusesExpiredOrInvalidInviteWithoutNetwork(t *testing.T) {
	inv := connectinvite.Invite{Version: 1, Address: "tcAAAA", Port: 48932, Key: NewKey(), Proof: connectinvite.NewProof(), ExpiresAt: time.Now().Add(time.Minute).Unix()}
	if _, err := Pair(context.Background(), inv, NewKey(), Options{}); !errors.Is(err, connectinvite.ErrInvalid) {
		t.Fatalf("invalid invite: %v", err)
	}
	if _, err := Pair(context.Background(), inv, "privkey:00", Options{}); err == nil {
		t.Fatal("bad phone key accepted")
	}
}

func TestReplyValidation(t *testing.T) {
	good := reply{V: 1, Address: testAddress(t), Port: 48931, Name: "Mac"}
	if _, err := good.link("privkey:x"); err != nil {
		t.Fatal(err)
	}
	for name, r := range map[string]reply{
		"version": {V: 2, Address: good.Address, Port: 1},
		"address": {V: 1, Address: "nope", Port: 1},
		"port":    {V: 1, Address: good.Address, Port: 0},
		"name":    {V: 1, Address: good.Address, Port: 1, Name: "a\nb"},
	} {
		if _, err := r.link("privkey:x"); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestLinkJSONRoundTrip(t *testing.T) {
	l := Link{Address: testAddress(t), Port: 48931, Name: "Mac", Payload: "p", Key: NewKey()}
	text, err := l.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseLink(text)
	if err != nil || !reflect.DeepEqual(back, l) {
		t.Fatalf("%+v %v", back, err)
	}
	if _, err := ParseLink(`{"address":"x"}`); err == nil {
		t.Fatal("invalid link parsed")
	}
}

// echoDialer stands in for a Tailcat session.
func echoDialer() (func(context.Context) (net.Conn, error), *atomic.Int32) {
	n := &atomic.Int32{}
	return func(context.Context) (net.Conn, error) {
		n.Add(1)
		a, b := net.Pipe()
		go func() { _, _ = io.Copy(b, b) }()
		return a, nil
	}, n
}

func TestForwardBridgesEachConnectionLazily(t *testing.T) {
	dial, dials := echoDialer()
	f, err := startForward(dial)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if dials.Load() != 0 {
		t.Fatal("dialed before any local connection")
	}
	if !strings.HasPrefix(f.Addr(), "127.0.0.1:") {
		t.Fatalf("addr %s", f.Addr())
	}
	for i := 0; i < 2; i++ {
		c, err := dialForward(f)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write([]byte("ping"))
		buf := make([]byte, 4)
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
			t.Fatalf("%q %v", buf, err)
		}
		c.Close()
	}
	if dials.Load() != 2 {
		t.Fatalf("dials %d", dials.Load())
	}
}

func TestForwardCloseCutsOpenConnections(t *testing.T) {
	dial, _ := echoDialer()
	f, _ := startForward(dial)
	c, err := dialForward(f)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("x"))
	time.Sleep(50 * time.Millisecond)
	f.Close()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 8)
	for {
		if _, err := c.Read(buf); err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				t.Fatal("connection still open after Close")
			}
			break
		}
	}
	if _, err := net.DialTimeout("tcp", f.Addr(), time.Second); err == nil {
		t.Fatal("still listening")
	}
}

func TestForwardDialFailureClosesLocalConnection(t *testing.T) {
	f, _ := startForward(func(context.Context) (net.Conn, error) { return nil, errors.New("unreachable") })
	defer f.Close()
	c, _ := dialForward(f)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("read succeeded")
	}
}

// nilConn stands in for gonet.TCPConn: its methods dereference the receiver, so calling Close on a
// nil one panics, like (*gonet.TCPConn)(nil).Close() does.
type nilConn struct {
	net.Conn
	ep io.Closer
}

func (c *nilConn) Close() error { return c.ep.Close() }

// Tailcat's dialer returns a failed netstack dial as a nil *gonet.TCPConn inside a non-nil net.Conn
// (tailcat v0.6.0, tailcat.go:1895 returns ns.DialContextTCP as is). A revoked phone or an
// offline computer must not crash the app.
func TestForwardDialFailureWithTypedNilConnDoesNotPanic(t *testing.T) {
	f, _ := startForward(func(context.Context) (net.Conn, error) {
		var c *nilConn
		return c, errors.New("connection refused")
	})
	defer f.Close()
	c, _ := dialForward(f)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("read succeeded")
	}
}

// dialForward connects to f the way the app does: with the token preamble.
func dialForward(f *Forward) (net.Conn, error) {
	c, err := net.Dial("tcp", f.Addr())
	if err != nil {
		return nil, err
	}
	if _, err := io.WriteString(c, "TP-FWD "+f.Token()+"\n"); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// F1: only what presents the forward's token reaches the host. HTTP and WebSocket requests carry it
// in the path under BasePath or in a header, which the host never sees; anything else is refused
// before the host is dialed.
func TestForwardCarriesOnlyRequestsWithTheToken(t *testing.T) {
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "echo" {
			w.Header().Set("Connection", "Upgrade")
			w.Header().Set("Upgrade", "echo")
			w.WriteHeader(http.StatusSwitchingProtocols)
			c, rw, _ := http.NewResponseController(w).Hijack()
			defer c.Close()
			_ = rw.Flush()
			_, _ = io.Copy(c, rw)
			return
		}
		_, _ = io.WriteString(w, r.RequestURI+" token="+r.Header.Get(ForwardTokenHeader))
	}))
	defer host.Close()
	var dials atomic.Int32
	f, err := startForward(func(ctx context.Context) (net.Conn, error) {
		dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, "tcp", host.Listener.Addr().String())
	})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	other, _ := startForward(func(context.Context) (net.Conn, error) { return nil, errors.New("unused") })
	other.Close()
	if f.Token() == other.Token() || len(f.Token()) < 40 || f.BasePath() != "/_tailpocket/"+f.Token() {
		t.Fatalf("tokens %q %q base %q", f.Token(), other.Token(), f.BasePath())
	}
	base := "http://" + f.Addr()
	get := func(path string, header ...string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest("GET", base+path, nil)
		for i := 0; i+1 < len(header); i += 2 {
			req.Header.Add(header[i], header[i+1])
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	for name, c := range map[string][]string{
		"no token":          {"/api/info"},
		"other token":       {"/_tailpocket/" + other.Token() + "/api/info"},
		"token prefix":      {"/_tailpocket/" + f.Token()[:20] + "/api/info"},
		"wrong header":      {"/api/info", ForwardTokenHeader, other.Token()},
		"two headers":       {"/api/info", ForwardTokenHeader, f.Token(), ForwardTokenHeader, f.Token()},
		"header beats path": {f.BasePath() + "/api/info", ForwardTokenHeader, other.Token()},
	} {
		if code, _ := get(c[0], c[1:]...); code != http.StatusForbidden {
			t.Errorf("%s: %d", name, code)
		}
	}
	if dials.Load() != 0 {
		t.Fatalf("the host was dialed %d times for refused requests", dials.Load())
	}
	if code, body := get(f.BasePath() + "/api/info?x=1"); code != 200 || body != "/api/info?x=1 token=" {
		t.Fatalf("path token: %d %q", code, body)
	}
	if code, body := get(f.BasePath()); code != 200 || body != "/ token=" {
		t.Fatalf("bare base: %d %q", code, body)
	}
	if code, body := get("/api/info", ForwardTokenHeader, f.Token()); code != 200 || body != "/api/info token=" {
		t.Fatalf("header token: %d %q", code, body)
	}

	// A raw first line with a wrong token, and bytes that are not HTTP, are closed undialed.
	before := dials.Load()
	for _, send := range []string{"TP-FWD " + other.Token() + "\n", "\x16\x03\x01\x00\x05hello\r\n\r\n"} {
		c, err := net.Dial("tcp", f.Addr())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(c, send)
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		b, _ := io.ReadAll(c)
		c.Close()
		if strings.Contains(string(b), " 200 ") || strings.Contains(string(b), "token=") {
			t.Fatalf("%q answered %q", send, b)
		}
	}
	if dials.Load() != before {
		t.Fatal("the host was dialed for a refused connection")
	}

	// A WebSocket-style upgrade under BasePath is carried both ways.
	c, err := net.Dial("tcp", f.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "GET "+f.BasePath()+"/hc HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
	br := bufio.NewReader(c)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	res, err := http.ReadResponse(br, nil)
	if err != nil || res.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade %v %v", res, err)
	}
	_, _ = io.WriteString(c, "ping")
	buf := make([]byte, 4)
	if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("after upgrade %q %v", buf, err)
	}
}

func timedOut(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// Push over an encrypted route is bounded by perRoute while the route is set up, even when the caller
// gives no deadline: a relay that takes the connection and never answers the WebSocket upgrade ends in
// ErrUnreachable, not in a call that runs until the app gives up.
func TestPushOverASilentRelayIsBounded(t *testing.T) {
	testhook.LoopbackRoutes = true
	silent := auditSilent(t)
	s, err := Connect(Link{Name: "Mac", Key: NewKey(), HostKey: auditSomeHostKey(t),
		Via: []connectinvite.Route{{T: connectinvite.RouteRelay, U: "ws://" + silent, R: "AAAAAAAAAAAAAAAAAAAAAA"}}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	done := make(chan error, 1)
	go func() { done <- s.ClearPush(context.Background()) }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrUnreachable) {
			t.Fatalf("ClearPush over a relay that never answers: %v, want ErrUnreachable", err)
		}
	case <-time.After(perRoute + 5*time.Second):
		t.Fatalf("ClearPush still running after %s", perRoute+5*time.Second)
	}
}
