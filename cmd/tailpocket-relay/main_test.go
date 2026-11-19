package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/jt-wang/tailpocket/connectrelay"
)

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

func noEnv(string) string { return "" }

func envWith(k, v string) func(string) string {
	return func(name string) string {
		if name == k {
			return v
		}
		return ""
	}
}

func runQuick(t *testing.T, args []string, getenv func(string) string) (int, string, string) {
	t.Helper()
	var out, errb syncBuf
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	code := run(ctx, args, getenv, &out, &errb)
	return code, out.String(), errb.String()
}

func TestNoTokenRefusesToStart(t *testing.T) {
	code, _, stderr := runQuick(t, []string{"--listen", "127.0.0.1:0"}, noEnv)
	if code != 2 {
		t.Fatalf("exit %d, want 2; stderr:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "openssl rand -base64 32") {
		t.Fatalf("stderr does not say how to make a token:\n%s", stderr)
	}
}

func TestBadArgs(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	os.WriteFile(empty, []byte("\n"), 0o600)
	for name, args := range map[string][]string{
		"missing token file":   {"--token-file", filepath.Join(dir, "nope")},
		"empty token file":     {"--token-file", empty},
		"cert without key":     {"--open", "--tls-cert", filepath.Join(dir, "c.pem")},
		"key without cert":     {"--open", "--tls-key", filepath.Join(dir, "k.pem")},
		"bad trust-proxy":      {"--open", "--trust-proxy", "not-a-cidr"},
		"unknown flag":         {"--open", "--no-such-flag"},
		"stray argument":       {"--open", "extra"},
		"negative max-rooms":   {"--open", "--max-rooms", "-1"},
		"zero phones per room": {"--open", "--max-phones-per-room", "0"},
		"zero phone rate":      {"--open", "--phone-rate", "0"},
		"zero max-conns":       {"--open", "--max-conns", "0"},
		"public-host no name":  {"--open", "--public-host", ":443"},
	} {
		if code, _, stderr := runQuick(t, args, noEnv); code != 2 {
			t.Errorf("%s: exit %d, want 2; stderr:\n%s", name, code, stderr)
		}
	}
}

func TestVersion(t *testing.T) {
	code, stdout, _ := runQuick(t, []string{"--version"}, noEnv)
	if code != 0 || !strings.Contains(stdout, "tailpocket-relay ") {
		t.Fatalf("--version: exit %d, stdout %q", code, stdout)
	}
}

var listenRe = regexp.MustCompile(`listening on (\S+)`)

// testPublicHost is the made-up name start gives a relay when the test
// does not pass --public-host itself.
const testPublicHost = "relay.example.com"

// start runs the relay until the test ends and returns its address.
func start(t *testing.T, args []string, getenv func(string) string) (addr string, stderr *syncBuf, stop func() int) {
	t.Helper()
	if !hasFlag(args, "--public-host") {
		args = append(args, "--public-host", testPublicHost)
	}
	stderr = &syncBuf{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- run(ctx, args, getenv, io.Discard, stderr) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if m := listenRe.FindStringSubmatch(stderr.String()); m != nil {
			addr = m[1]
			break
		}
		select {
		case code := <-done:
			cancel()
			t.Fatalf("relay exited %d before listening:\n%s", code, stderr.String())
		default:
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("relay never said where it listens:\n%s", stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	var once sync.Once
	code := -1
	stop = func() int {
		once.Do(func() {
			cancel()
			select {
			case code = <-done:
			case <-time.After(10 * time.Second):
				t.Error("relay did not stop")
			}
		})
		return code
	}
	t.Cleanup(func() { stop() })
	return addr, stderr, stop
}

func TestStartsWithEnvToken(t *testing.T) {
	addr, stderr, stop := start(t, []string{"--listen", "127.0.0.1:0"}, envWith("TAILPOCKET_RELAY_TOKEN", "made-up-token-for-test"))
	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || strings.TrimSpace(string(b)) != "ok" {
		t.Fatalf("healthz %d %q", resp.StatusCode, b)
	}
	if !strings.Contains(stderr.String(), "TLS reverse proxy") {
		t.Fatalf("plain ws:// start does not point to a TLS reverse proxy:\n%s", stderr)
	}
	if strings.Contains(stderr.String(), "made-up-token-for-test") {
		t.Fatalf("token on stderr:\n%s", stderr)
	}
	if code := stop(); code != 0 {
		t.Fatalf("exit %d after stop, want 0", code)
	}
}

func TestStartsWithTokenFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "token")
	os.WriteFile(p, []byte("made-up-file-token\n"), 0o600)
	addr, _, _ := start(t, []string{"--listen", "127.0.0.1:0", "--token-file", p}, noEnv)
	// The file's token (without its newline) is the one checked.
	req, _ := http.NewRequest("GET", "http://"+addr+"/v1/host?room=AAAAAAAAAAAAAAAAAAAAAA", nil)
	req.Header.Set("Authorization", "Bearer made-up-file-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// Past the token check; a plain GET is not a WebSocket upgrade.
	if resp.StatusCode == http.StatusUnauthorized {
		t.Fatal("token from the file was refused")
	}
}

func TestOpenWarns(t *testing.T) {
	_, stderr, _ := start(t, []string{"--listen", "127.0.0.1:0", "--open"}, noEnv)
	if !strings.Contains(strings.ToLower(stderr.String()), "warning") {
		t.Fatalf("--open start has no warning:\n%s", stderr)
	}
}

func writeCert(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "relay.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return
}

func TestTLS(t *testing.T) {
	c, k := writeCert(t, t.TempDir())
	addr, stderr, _ := start(t, []string{"--listen", "127.0.0.1:0", "--open", "--tls-cert", c, "--tls-key", k}, noEnv)
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := cl.Get("https://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("https healthz: %v\n%s", err, stderr)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("https healthz %d", resp.StatusCode)
	}
	if strings.Contains(stderr.String(), "TLS reverse proxy") {
		t.Fatalf("TLS start still asks for a reverse proxy:\n%s", stderr)
	}
}

// A keep-alive connection that goes quiet after a request is closed, so
// idle sockets cannot pile up.
func TestIdleConnectionClosed(t *testing.T) {
	old := idleTimeout
	idleTimeout = 300 * time.Millisecond
	defer func() { idleTimeout = old }()
	addr, _, _ := start(t, []string{"--listen", "127.0.0.1:0", "--open"}, noEnv)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "GET /healthz HTTP/1.1\r\nHost: relay.example.com\r\n\r\n")
	buf := make([]byte, 4096)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := c.Read(buf); err != nil || !strings.Contains(string(buf[:n]), "200 OK") {
		t.Fatalf("first request: %q %v", buf[:n], err)
	}
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = c.Read(buf)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("idle keep-alive connection still open after 3 s")
	}
	if err != io.EOF {
		t.Fatalf("idle connection: %v, want EOF", err)
	}
}

func TestShortTokenRefused(t *testing.T) {
	code, _, stderr := runQuick(t, []string{"--listen", "127.0.0.1:0"}, envWith("TAILPOCKET_RELAY_TOKEN", "short-tok"))
	if code != 2 || !strings.Contains(stderr, "16") {
		t.Fatalf("9-byte token: exit %d, stderr:\n%s", code, stderr)
	}
	p := filepath.Join(t.TempDir(), "token")
	os.WriteFile(p, []byte("abc\n"), 0o600)
	if code, _, stderr := runQuick(t, []string{"--token-file", p}, noEnv); code != 2 {
		t.Fatalf("3-byte token file: exit %d, stderr:\n%s", code, stderr)
	}
}

func TestTokenFileReadableByOthersWarns(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes do not say who can read on Windows")
	}
	p := filepath.Join(t.TempDir(), "token")
	os.WriteFile(p, []byte("made-up-file-token-xyz\n"), 0o600)
	_, stderr, _ := start(t, []string{"--listen", "127.0.0.1:0", "--token-file", p}, noEnv)
	if strings.Contains(stderr.String(), "readable by other users") {
		t.Fatalf("0600 token file warned:\n%s", stderr)
	}
	q := filepath.Join(t.TempDir(), "token")
	os.WriteFile(q, []byte("made-up-file-token-xyz\n"), 0o600)
	os.Chmod(q, 0o644)
	_, stderr2, _ := start(t, []string{"--listen", "127.0.0.1:0", "--token-file", q}, noEnv)
	if !strings.Contains(stderr2.String(), "readable by other users") {
		t.Fatalf("0644 token file did not warn:\n%s", stderr2)
	}
}

func TestTokenFileWrongTokenRefused(t *testing.T) {
	p := filepath.Join(t.TempDir(), "token")
	os.WriteFile(p, []byte("made-up-file-token\n"), 0o600)
	addr, _, _ := start(t, []string{"--listen", "127.0.0.1:0", "--token-file", p}, noEnv)
	req, _ := http.NewRequest("GET", "http://"+addr+"/v1/host?room=AAAAAAAAAAAAAAAAAAAAAA", nil)
	req.Header.Set("Authorization", "Bearer made-up-file-token-x")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong token: %d, want 401", resp.StatusCode)
	}
}

// writeCertSerial writes a self-signed certificate with this serial number.
func writeCertSerial(t *testing.T, certFile, keyFile string, serial int64) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "relay.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
}

// A renewed certificate (new files at the same paths) is served without a
// restart.
func TestTLSReloadsRenewedCertificate(t *testing.T) {
	dir := t.TempDir()
	c, k := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writeCertSerial(t, c, k, 1)
	addr, _, _ := start(t, []string{"--listen", "127.0.0.1:0", "--open", "--tls-cert", c, "--tls-key", k}, noEnv)
	serial := func() int64 {
		conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64()
	}
	if got := serial(); got != 1 {
		t.Fatalf("serial %d, want 1", got)
	}
	writeCertSerial(t, c, k, 2)
	later := time.Now().Add(2 * time.Second)
	os.Chtimes(c, later, later)
	os.Chtimes(k, later, later)
	if got := serial(); got != 2 {
		t.Fatalf("after renewal: serial %d, want 2", got)
	}
}

// Over wss://, a the computer registers, a phone joins, and bytes go both ways.
func TestWSSRoundTrip(t *testing.T) {
	c, k := writeCert(t, t.TempDir())
	addr, stderr, _ := start(t, []string{"--listen", "127.0.0.1:0", "--tls-cert", c, "--tls-key", k},
		envWith("TAILPOCKET_RELAY_TOKEN", "made-up-token-for-test"))
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	base := "wss://" + addr
	auth := http.Header{"Authorization": {"Bearer made-up-token-for-test"}}
	wsDial := func(u string, h http.Header) *websocket.Conn {
		conn, _, err := websocket.Dial(ctx, u, &websocket.DialOptions{HTTPClient: hc, HTTPHeader: h})
		if err != nil {
			t.Fatalf("dial %s: %v\n%s", u[:strings.Index(u, "?")], err, stderr)
		}
		conn.SetReadLimit(connectrelay.MaxMessage)
		return conn
	}
	readMsg := func(conn *websocket.Conn, v any) {
		_, b, err := conn.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, v); err != nil {
			t.Fatal(err)
		}
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	room := connectrelay.RoomFor(pub)
	host := wsDial(base+connectrelay.PathHost+"?room="+room, auth)
	defer host.CloseNow()
	var ch connectrelay.Challenge
	readMsg(host, &ch)
	reg, _ := json.Marshal(connectrelay.Register{Type: connectrelay.TypeRegister,
		Pub:  base64.RawURLEncoding.EncodeToString(pub),
		Host: testPublicHost,
		Sig:  base64.RawURLEncoding.EncodeToString(connectrelay.SignChallenge(priv, testPublicHost, room, ch.Nonce))})
	host.Write(ctx, websocket.MessageText, reg)
	var ready connectrelay.Ready
	readMsg(host, &ready)
	if ready.Type != connectrelay.TypeReady {
		t.Fatalf("got %q, want ready", ready.Type)
	}
	phone := wsDial(base+connectrelay.PathPhone+"?room="+room, nil)
	defer phone.CloseNow()
	var in connectrelay.Incoming
	readMsg(host, &in)
	acc := wsDial(base+connectrelay.PathAccept+"?room="+room+"&id="+in.ID, auth)
	defer acc.CloseNow()
	for _, d := range []struct{ from, to *websocket.Conn }{{phone, acc}, {acc, phone}} {
		msg := make([]byte, 50000)
		rand.Read(msg)
		if err := d.from.Write(ctx, websocket.MessageBinary, msg); err != nil {
			t.Fatal(err)
		}
		_, got, err := d.to.Read(ctx)
		if err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("over wss: got %d bytes, %v", len(got), err)
		}
	}
}

// register dials /v1/host on a plain ws:// relay with the made-up token,
// sends host in register and signs over it, and returns the close code (0
// when the relay answered ready).
func register(t *testing.T, addr, host string) websocket.StatusCode {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	room := connectrelay.RoomFor(pub)
	c, _, err := websocket.Dial(ctx, "ws://"+addr+connectrelay.PathHost+"?room="+room,
		&websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer made-up-token-for-test"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	_, b, err := c.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var ch connectrelay.Challenge
	json.Unmarshal(b, &ch)
	reg, _ := json.Marshal(connectrelay.Register{Type: connectrelay.TypeRegister,
		Pub:  base64.RawURLEncoding.EncodeToString(pub),
		Host: host,
		Sig:  base64.RawURLEncoding.EncodeToString(connectrelay.SignChallenge(priv, host, room, ch.Nonce))})
	c.Write(ctx, websocket.MessageText, reg)
	_, b, err = c.Read(ctx)
	if err != nil {
		return websocket.CloseStatus(err)
	}
	var ready connectrelay.Ready
	json.Unmarshal(b, &ready)
	if ready.Type != connectrelay.TypeReady {
		t.Fatalf("after register: %s", b)
	}
	return 0
}

func TestPublicHostFlag(t *testing.T) {
	tok := envWith("TAILPOCKET_RELAY_TOKEN", "made-up-token-for-test")
	addr, _, _ := start(t, []string{"--listen", "127.0.0.1:0", "--public-host", "Relay.Example.com:8443"}, tok)
	if code := register(t, addr, "relay.example.com"); code != 0 {
		t.Fatalf("--public-host Relay.Example.com:8443, register for relay.example.com: close %d, want ready", code)
	}
	// The dialled address (the Host header) does not count.
	if code := register(t, addr, "127.0.0.1"); code != connectrelay.CloseBadRegister {
		t.Fatalf("register for the dialled address 127.0.0.1: close %d, want 4403", code)
	}
}

func TestPublicHostRequired(t *testing.T) {
	code, _, stderr := runQuick(t, []string{"--listen", "127.0.0.1:0"}, envWith("TAILPOCKET_RELAY_TOKEN", "made-up-token-for-test"))
	if code != 2 {
		t.Fatalf("no --public-host: exit %d, want 2; stderr:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "--public-host") || !strings.Contains(stderr, "relay.example.com") {
		t.Fatalf("no --public-host: stderr does not say what to pass:\n%s", stderr)
	}
	code, _, stderr = runQuick(t, []string{"--listen", "127.0.0.1:0", "--open"}, noEnv)
	if code != 2 {
		t.Fatalf("--open, no --public-host: exit %d, want 2; stderr:\n%s", code, stderr)
	}
}

func TestHelpSaysPublicHostRequired(t *testing.T) {
	code, _, stderr := runQuick(t, []string{"--help"}, noEnv)
	if code != 0 {
		t.Fatalf("--help: exit %d", code)
	}
	i := strings.Index(stderr, "-public-host")
	if i < 0 || !strings.Contains(stderr[i:min(len(stderr), i+300)], "required") {
		t.Fatalf("--help does not say --public-host is required:\n%s", stderr)
	}
}

func TestMaxConnsFlag(t *testing.T) {
	addr, _, _ := start(t, []string{"--listen", "127.0.0.1:0", "--open", "--max-conns", "2"}, noEnv)
	for i := 0; i < 2; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
	}
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("3rd connection with --max-conns 2: %v, want closed (EOF)", err)
	}
}

const roomsWarning = "connections; raise --max-conns"
const filesWarning = "open files"

func TestWarnsWhenRoomsDoNotFit(t *testing.T) {
	_, stderr, _ := start(t, []string{"--listen", "127.0.0.1:0", "--open", "--max-rooms", "200"}, noEnv)
	if !strings.Contains(stderr.String(), roomsWarning) {
		t.Fatalf("--max-rooms 200 with --max-conns 4096: no warning:\n%s", stderr)
	}
	_, stderr, _ = start(t, []string{"--listen", "127.0.0.1:0", "--open"}, noEnv)
	if strings.Contains(stderr.String(), roomsWarning) {
		t.Fatalf("defaults warn that rooms do not fit:\n%s", stderr)
	}
}

func TestWarnsWhenFileLimitLow(t *testing.T) {
	old := fileLimit
	defer func() { fileLimit = old }()
	fileLimit = func() (uint64, bool) { return 256, true }
	_, stderr, _ := start(t, []string{"--listen", "127.0.0.1:0", "--open"}, noEnv)
	if !strings.Contains(stderr.String(), filesWarning) {
		t.Fatalf("open-file limit 256 under --max-conns 4096: no warning:\n%s", stderr)
	}
	fileLimit = func() (uint64, bool) { return 1 << 20, true }
	_, stderr, _ = start(t, []string{"--listen", "127.0.0.1:0", "--open"}, noEnv)
	if strings.Contains(stderr.String(), filesWarning) {
		t.Fatalf("a high open-file limit warns:\n%s", stderr)
	}
}

func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == name || strings.HasPrefix(a, name+"=") {
			return true
		}
	}
	return false
}
