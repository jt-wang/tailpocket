package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jt-wang/tailpocket/connectpush"
)

const (
	appA = "io.example.alpha"
	appB = "io.example.bravo" // same length as appA on purpose

	ipX = "198.51.100.7:1111"
	ipY = "203.0.113.9:2222"
	ipZ = "192.0.2.55:3333"
)

var (
	keysOnce sync.Once
	ecKey    *ecdsa.PrivateKey
	rsaKey   *rsa.PrivateKey
	pushKey  = [32]byte{7, 7, 7}
)

func testKeys(t *testing.T) {
	keysOnce.Do(func() {
		var err error
		if ecKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			panic(err)
		}
		if rsaKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
	})
}

const baseConfig = `{
  "handle_key_file": "handle.key",
  "state_file": "state.json",
  "apps": [
    {"id": "io.example.alpha", "placeholder": {"title": "Alpha", "body": "New activity"},
     "apns": {"team_id": "TEAM123456", "key_id": "KEY1234567", "key_file": "apns.p8", "topic": "io.example.alpha", "env": "sandbox"},
     "fcm": {"project_id": "alpha-proj", "credentials_file": "fcm.json"}},
    {"id": "io.example.bravo", "placeholder": {"title": "Bravo", "body": "Something happened"},
     "apns": {"team_id": "TEAM123456", "key_id": "KEY1234567", "key_file": "apns.p8", "topic": "io.example.bravo.app"}}
  ]
}`

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

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type upReq struct {
	proto  int
	method string
	path   string
	host   string
	header http.Header
	body   []byte
}

// fakeUp stands for APNs, FCM and Google OAuth at once, over TLS and
// HTTP/2 like the real ones.
type fakeUp struct {
	mu    sync.Mutex
	reqs  []upReq
	reply func(path string) (int, string) // nil: 200 and no body
	ts    *httptest.Server
}

func (f *fakeUp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.reqs = append(f.reqs, upReq{r.ProtoMajor, r.Method, r.URL.Path, r.Host, r.Header.Clone(), b})
	reply := f.reply
	f.mu.Unlock()
	if r.URL.Path == "/token" {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token":"ya29.test-access","expires_in":3600,"token_type":"Bearer"}`)
		return
	}
	code, body := http.StatusOK, ""
	if reply != nil {
		code, body = reply(r.URL.Path)
	}
	w.WriteHeader(code)
	io.WriteString(w, body)
}

func (f *fakeUp) setReply(fn func(path string) (int, string)) {
	f.mu.Lock()
	f.reply = fn
	f.mu.Unlock()
}

// pushes are the requests to APNs and FCM (not OAuth).
func (f *fakeUp) pushes() []upReq {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []upReq
	for _, r := range f.reqs {
		if r.path != "/token" {
			out = append(out, r)
		}
	}
	return out
}

func (f *fakeUp) find(path string) []upReq {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []upReq
	for _, r := range f.reqs {
		if r.path == path {
			out = append(out, r)
		}
	}
	return out
}

func (f *fakeUp) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.reqs {
		if r.path == path {
			n++
		}
	}
	return n
}

func (f *fakeUp) total() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reqs)
}

// counter is a server that must never be reached.
type counter struct {
	n  atomic.Int32
	ts *httptest.Server
}

func newCounter(t *testing.T) *counter {
	c := &counter{}
	c.ts = httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { c.n.Add(1) }))
	t.Cleanup(c.ts.Close)
	return c
}

type gw struct {
	t     *testing.T
	dir   string
	srv   *server
	up    *fakeUp
	logs  *syncBuf
	clock *clock

	mu      sync.Mutex
	secrets []string // must never be in the log
}

func writeFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func newGateway(t *testing.T) *gw { return newGatewayWith(t, baseConfig) }

func newGatewayWith(t *testing.T, cfgJSON string) *gw {
	t.Helper()
	testKeys(t)
	dir := t.TempDir()
	p8, _ := x509.MarshalPKCS8PrivateKey(ecKey)
	writeFile(t, filepath.Join(dir, "apns.p8"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p8}))
	rk, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	sa, _ := json.Marshal(map[string]string{
		"type":           "service_account",
		"project_id":     "alpha-proj",
		"private_key_id": "abc123",
		"private_key":    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rk})),
		"client_email":   "push@alpha-proj.iam.gserviceaccount.com",
		// Ignored: the gateway always uses Google's fixed token URL.
		"token_uri": "http://attacker.invalid/token",
	})
	writeFile(t, filepath.Join(dir, "fcm.json"), sa)

	g := &gw{t: t, dir: dir, logs: &syncBuf{}, clock: &clock{t: time.Unix(1_790_000_000, 0)}}
	g.up = &fakeUp{}
	g.up.ts = httptest.NewUnstartedServer(g.up)
	g.up.ts.EnableHTTP2 = true
	g.up.ts.StartTLS()
	t.Cleanup(g.up.ts.Close)
	g.srv = g.build(cfgJSON)
	t.Cleanup(func() {
		logs := g.logs.String()
		g.mu.Lock()
		defer g.mu.Unlock()
		for _, s := range g.secrets {
			if strings.Contains(logs, s) {
				t.Errorf("log holds a token, handle or ct (%.12s…):\n%s", s, logs)
			}
		}
	})
	return g
}

func (g *gw) upstream() upstream {
	c := *g.up.ts.Client()
	c.Timeout = 5 * time.Second
	return upstream{
		client:         &c,
		apnsProduction: g.up.ts.URL + "/prod",
		apnsSandbox:    g.up.ts.URL + "/sandbox",
		fcm:            g.up.ts.URL,
		oauth:          g.up.ts.URL + "/token",
	}
}

// build makes a gateway from cfgJSON over the files in g.dir, as a start
// of the binary would.
func (g *gw) build(cfgJSON string) *server {
	g.t.Helper()
	cfg, err := parseConfig([]byte(cfgJSON), g.dir)
	if err != nil {
		g.t.Fatal(err)
	}
	warn := func(string, ...any) {}
	keys, err := loadHandleKeys(cfg, warn)
	if err != nil {
		g.t.Fatal(err)
	}
	gens, err := loadGenStore(cfg.StateFile)
	if err != nil {
		g.t.Fatal(err)
	}
	up := g.upstream()
	apps, err := loadApps(cfg, up, warn)
	if err != nil {
		g.t.Fatal(err)
	}
	s := newServer(cfg, keys, gens, apps, up, log.New(g.logs, "", 0))
	s.now = g.clock.now
	return s
}

func (g *gw) secret(s ...string) {
	g.mu.Lock()
	g.secrets = append(g.secrets, s...)
	g.mu.Unlock()
}

func (g *gw) req(method, target, remote string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, bytes.NewReader(body))
	r.RemoteAddr = remote
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	g.srv.ServeHTTP(w, r)
	return w
}

func (g *gw) post(path, remote string, body any) *httptest.ResponseRecorder {
	var b []byte
	switch v := body.(type) {
	case string:
		b = []byte(v)
	case []byte:
		b = v
	default:
		b, _ = json.Marshal(v)
	}
	return g.req(http.MethodPost, path, remote, b)
}

func apnsToken(i int) string { return fmt.Sprintf("%064x", 0xa0000+i) }
func fcmToken(i int) string {
	return "fcm:APA91b" + strings.Repeat("x", 40) + "-" + strconv.Itoa(i)
}

// register returns the handle, failing the test unless the gateway gives one.
func (g *gw) register(app, platform, token string, gen uint64, remote string) string {
	g.t.Helper()
	g.secret(token)
	w := g.post("/v1/register", remote, map[string]any{"app": app, "platform": platform, "token": token, "generation": gen})
	if w.Code != http.StatusOK {
		g.t.Fatalf("register %s %s: %d %s", app, platform, w.Code, w.Body)
	}
	var out struct {
		Handle  string `json:"handle"`
		Expires int64  `json:"expires"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || out.Handle == "" {
		g.t.Fatalf("register answer %s", w.Body)
	}
	g.secret(out.Handle)
	return out.Handle
}

func (g *gw) ct(app string, seq uint64) string {
	g.t.Helper()
	ct, err := connectpush.Seal(pushKey, "k1", app, connectpush.Note{
		Title: "SECRET-TITLE", Body: "SECRET-BODY", URL: "https://evil.example/x", Sent: g.clock.now().Unix(), Seq: seq,
	})
	if err != nil {
		g.t.Fatal(err)
	}
	g.secret(ct)
	return ct
}

func (g *gw) send(handle, ct, remote string, extra map[string]any) *httptest.ResponseRecorder {
	m := map[string]any{"handle": handle, "ct": ct}
	for k, v := range extra {
		m[k] = v
	}
	return g.post("/v1/send", remote, m)
}

func wantCode(t *testing.T, w *httptest.ResponseRecorder, code int, errCode string) {
	t.Helper()
	if w.Code != code {
		t.Fatalf("status %d, want %d; body %s", w.Code, code, w.Body)
	}
	if errCode != "" {
		var e struct {
			Error string `json:"error"`
		}
		json.Unmarshal(w.Body.Bytes(), &e)
		if e.Error != errCode {
			t.Fatalf("error %q, want %q; body %s", e.Error, errCode, w.Body)
		}
	}
}
