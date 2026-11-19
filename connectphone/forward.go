package connectphone

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"
)

// Forward is a loopback listener whose connections continue to the host, as this phone. Any program
// on the phone can connect to a loopback port (another app, a web page through ws://127.0.0.1), so
// nothing reaches the host unless it presents Token:
//
//   - HTTP and WebSocket: every request names the token, either in its path, under BasePath (which
//     the SDKs put in baseUrl), or in the header "Tailpocket-Token". The forward removes it and
//     sends the request on; a request without it gets 403 and the host is never dialed.
//   - Any other protocol (an app's own TLS): the connection starts with the line
//     "TP-FWD <token>\n", which the forward removes; then bytes are carried as they are.
//
// A wrong token, a malformed request, or nothing within 10 s closes the connection.
type Forward struct {
	token  string
	ln     net.Listener
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	closed bool
	live   map[net.Conn]struct{}
	wg     sync.WaitGroup
	once   sync.Once
	queue  *connQueue
	server *http.Server
	tr     *http.Transport
}

// ForwardTokenHeader is the HTTP header that may carry Forward.Token instead of the path.
const ForwardTokenHeader = "Tailpocket-Token"

// forwardPathRoot is where BasePath starts: "/_tailpocket/<token>".
const forwardPathRoot = "/_tailpocket/"

// rawPreamble starts a connection that is carried as raw bytes.
const rawPreamble = "TP-FWD "

func startForward(dial func(context.Context) (net.Conn, error)) (*Forward, error) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		_ = ln.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	f := &Forward{token: base64.RawURLEncoding.EncodeToString(b[:]), ln: ln, ctx: ctx, cancel: cancel,
		live: map[net.Conn]struct{}{}, queue: &connQueue{ch: make(chan net.Conn), done: make(chan struct{}), addr: ln.Addr()}}
	f.tr = &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			c, err := dial(ctx)
			if err != nil {
				return nil, err // c may be a nil pointer inside a non-nil net.Conn; never touch it
			}
			if !f.track(c) {
				return nil, net.ErrClosed
			}
			return &trackedConn{Conn: c, f: f}, nil
		},
		DisableCompression:  true,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			host := pr.In.Host
			if host == "" {
				host = f.Addr()
			}
			pr.Out.URL.Scheme, pr.Out.URL.Host, pr.Out.Host = "http", host, host
		},
		Transport:     f.tr,
		FlushInterval: -1,
		ErrorLog:      log.New(io.Discard, "", 0),
		// The host is unreachable: close the app's connection without an answer, as v0.2 did.
		ErrorHandler: func(http.ResponseWriter, *http.Request, error) { panic(http.ErrAbortHandler) },
	}
	f.server = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !f.admitRequest(r) {
				w.Header().Set("Connection", "close")
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			proxy.ServeHTTP(w, r)
		}),
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	f.wg.Add(2)
	go func() {
		defer f.wg.Done()
		_ = f.server.Serve(f.queue)
	}()
	go func() {
		defer f.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if !f.track(c) {
				return
			}
			f.wg.Add(1)
			go f.bridge(c, dial)
		}
	}()
	return f, nil
}

// Addr is "127.0.0.1:<port>".
func (f *Forward) Addr() string { return f.ln.Addr().String() }

// Port is the loopback port.
func (f *Forward) Port() int { return f.ln.Addr().(*net.TCPAddr).Port }

// Token is the secret every connection presents (see Forward). Keep it in the app's memory only.
func (f *Forward) Token() string { return f.token }

// BasePath is "/_tailpocket/<token>": prefix every HTTP and WebSocket path with it, as in
// "http://127.0.0.1:<port>" + BasePath + "/api/info". The host sees "/api/info".
func (f *Forward) BasePath() string { return forwardPathRoot + f.token }

func (f *Forward) match(t string) bool {
	return subtle.ConstantTimeCompare([]byte(t), []byte(f.token)) == 1
}

// admitRequest checks the token of one HTTP request and removes it.
func (f *Forward) admitRequest(r *http.Request) bool {
	if r.Method == http.MethodConnect || r.URL.Host != "" || !strings.HasPrefix(r.URL.Path, "/") {
		return false // authority or absolute form: the forward goes only to the host
	}
	if v := r.Header.Values(ForwardTokenHeader); len(v) > 0 {
		r.Header.Del(ForwardTokenHeader)
		if len(v) != 1 || !f.match(strings.TrimSpace(v[0])) {
			return false
		}
		return true
	}
	rest, ok := strings.CutPrefix(r.URL.Path, forwardPathRoot)
	if !ok {
		return false
	}
	tok, _, _ := strings.Cut(rest, "/")
	if !f.match(tok) {
		return false
	}
	// The token is base64url, the same escaped as decoded, so both forms lose the same prefix.
	r.URL.Path = stripBase(r.URL.Path, len(forwardPathRoot)+len(tok))
	if r.URL.RawPath != "" {
		r.URL.RawPath = stripBase(r.URL.RawPath, len(forwardPathRoot)+len(tok))
	}
	return true
}

func stripBase(p string, n int) string {
	if p = p[n:]; p == "" {
		return "/"
	}
	return p
}

func (f *Forward) track(c net.Conn) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		_ = c.Close()
		return false
	}
	f.live[c] = struct{}{}
	return true
}

func (f *Forward) untrack(c net.Conn) {
	_ = c.Close()
	f.mu.Lock()
	delete(f.live, c)
	f.mu.Unlock()
}

// bridge sends a connection that starts with the raw preamble straight to the host, and any other
// to the HTTP server.
func (f *Forward) bridge(local net.Conn, dial func(context.Context) (net.Conn, error)) {
	defer f.wg.Done()
	_ = local.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReaderSize(local, 4096)
	peek, err := br.Peek(len(rawPreamble))
	if err != nil {
		f.untrack(local)
		return
	}
	if string(peek) != rawPreamble {
		_ = local.SetReadDeadline(time.Time{})
		f.queue.give(&trackedConn{Conn: local, r: br, f: f})
		return
	}
	defer f.untrack(local)
	line, err := br.ReadSlice('\n')
	_ = local.SetReadDeadline(time.Time{})
	if err != nil || !f.match(strings.TrimRight(string(line[len(rawPreamble):]), "\r\n")) {
		return // the host is never dialed
	}
	remote, err := dial(f.ctx)
	if err != nil {
		return // remote may be a nil pointer inside a non-nil net.Conn; never touch it
	}
	if !f.track(remote) {
		return
	}
	defer f.untrack(remote)
	var copying sync.WaitGroup
	copying.Add(2)
	pipe := func(dst net.Conn, src io.Reader) {
		defer copying.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	go pipe(remote, br)
	go pipe(local, remote)
	copying.Wait()
}

// Close stops listening and cuts every open connection.
func (f *Forward) Close() {
	f.once.Do(func() {
		f.cancel()
		_ = f.ln.Close()
		_ = f.server.Close()
		f.mu.Lock()
		f.closed = true
		for c := range f.live {
			_ = c.Close()
		}
		f.mu.Unlock()
		f.tr.CloseIdleConnections()
		f.wg.Wait()
	})
}

// trackedConn leaves f's live set when closed; r, when set, holds bytes already read from Conn.
type trackedConn struct {
	net.Conn
	r    *bufio.Reader
	f    *Forward
	once sync.Once
}

func (c *trackedConn) Read(b []byte) (int, error) {
	if c.r != nil {
		return c.r.Read(b)
	}
	return c.Conn.Read(b)
}

func (c *trackedConn) Close() error {
	c.once.Do(func() { c.f.untrack(c.Conn) })
	return nil
}

// connQueue is the listener the HTTP server accepts from.
type connQueue struct {
	ch   chan net.Conn
	done chan struct{}
	addr net.Addr
	once sync.Once
}

func (q *connQueue) give(c net.Conn) {
	select {
	case q.ch <- c:
	case <-q.done:
		_ = c.Close()
	}
}

func (q *connQueue) Accept() (net.Conn, error) {
	select {
	case c := <-q.ch:
		return c, nil
	case <-q.done:
		return nil, net.ErrClosed
	}
}

func (q *connQueue) Close() error {
	q.once.Do(func() { close(q.done) })
	return nil
}

func (q *connQueue) Addr() net.Addr { return q.addr }
