package main

// The relay never dials out: it is not a proxy and not an SSRF hop. Checked twice: by reading the
// relay's server source for anything that opens or resolves an outbound connection, and by sending
// a running relay proxy-style requests that name a listener, which must see no connection.

import (
	"crypto/ed25519"
	"crypto/rand"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jt-wang/tailpocket/connectrelay"
)

// relaySources are the files the relay server is built from: this command's non-test files and
// the server half of connectrelay (client.go and dialopts.go are the host's and phone's side).
func relaySources(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, f := range files {
		if !strings.HasSuffix(f, "_test.go") {
			out = append(out, f)
		}
	}
	for _, f := range []string{"server.go", "proto.go", "ratelimit.go", "listener.go"} {
		out = append(out, filepath.Join("..", "..", "connectrelay", f))
	}
	return out
}

// outbound lists what opens, resolves or hands off an outbound connection, by import path.
var outbound = map[string][]string{
	"net": {"Dial", "DialTimeout", "DialTCP", "DialUDP", "DialIP", "DialUnix", "Dialer",
		"Resolver", "DefaultResolver", "LookupHost", "LookupIP", "LookupAddr", "LookupCNAME", "LookupMX",
		"LookupNS", "LookupPort", "LookupSRV", "LookupTXT", "ResolveTCPAddr", "ResolveUDPAddr", "ResolveIPAddr", "ResolveUnixAddr"},
	"net/http": {"Get", "Head", "Post", "PostForm", "Client", "DefaultClient", "Transport", "DefaultTransport",
		"NewRequest", "NewRequestWithContext", "ProxyFromEnvironment", "ProxyURL"},
	"crypto/tls":                 {"Dial", "DialWithDialer", "Dialer"},
	"github.com/coder/websocket": {"Dial"},
	"syscall":                    {"Connect", "Exec", "ForkExec", "StartProcess"},
	"os":                         {"StartProcess"},
}

// outboundImports may not be imported at all.
var outboundImports = []string{"os/exec", "plugin", "net/http/httputil", "net/rpc", "net/smtp", "golang.org/x/net/proxy"}

// outboundMethods are method names that dial whatever their receiver is.
var outboundMethods = []string{"Dial", "DialContext", "DialTCP", "DialUDP", "DialTLS", "DialTLSContext", "RoundTrip"}

// scanOutbound reports every use of outbound, outboundImports and outboundMethods in src.
func scanOutbound(fset *token.FileSet, f *ast.File) []string {
	var found []string
	at := func(n ast.Node, what string) { found = append(found, fset.Position(n.Pos()).String()+": "+what) }
	names := map[string]string{} // local name → import path
	for _, imp := range f.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		for _, bad := range outboundImports {
			if path == bad {
				at(imp, "imports "+path)
			}
		}
		name := path[strings.LastIndex(path, "/")+1:]
		if imp.Name != nil {
			name = imp.Name.Name
		}
		names[name] = path
	}
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		for _, m := range outboundMethods {
			if sel.Sel.Name == m {
				at(sel, "calls ."+m)
			}
		}
		if id, ok := sel.X.(*ast.Ident); ok && id.Obj == nil { // a package, not a local variable
			for _, bad := range outbound[names[id.Name]] {
				if sel.Sel.Name == bad {
					at(sel, "uses "+names[id.Name]+"."+bad)
				}
			}
		}
		return true
	})
	return found
}

func TestFailClosedRelaySourceNeverDialsOut(t *testing.T) {
	files := relaySources(t)
	seen := map[string]bool{}
	fset := token.NewFileSet()
	for _, path := range files {
		f, err := parser.ParseFile(fset, path, nil, 0) // with object resolution: id.Obj tells a variable from a package
		if err != nil {
			t.Fatal(err)
		}
		seen[filepath.Base(path)] = true
		for _, hit := range scanOutbound(fset, f) {
			t.Errorf("relay server source dials out: %s", hit)
		}
	}
	for _, must := range []string{"main.go", "server.go", "proto.go", "ratelimit.go", "listener.go"} {
		if !seen[must] {
			t.Fatalf("did not scan %s (scanned %v)", must, files)
		}
	}
}

// The scan is not vacuous: it finds each way of dialling, also under an import alias.
func TestFailClosedOutboundScanFindsDials(t *testing.T) {
	const src = `package p
import (
	n "net"
	"net/http"
	"crypto/tls"
	"os/exec"
	ws "github.com/coder/websocket"
)
func f() {
	n.Dial("tcp", "x")
	_ = (&n.Dialer{}).DialContext
	var c http.Client
	_ = c
	http.Get("http://x")
	tls.Dial("tcp", "x", nil)
	ws.Dial(nil, "ws://x", nil)
	n.LookupHost("x")
	_ = http.DefaultTransport.RoundTrip
	exec.Command("sh")
}
func g(net int) { _ = net } // a variable named like a package is not one
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "planted.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(scanOutbound(fset, f), "\n")
	for _, want := range []string{"imports os/exec", "uses net.Dial", "uses net.Dialer", "calls .DialContext", "uses net/http.Client",
		"uses net/http.Get", "uses crypto/tls.Dial", "uses github.com/coder/websocket.Dial", "uses net.LookupHost",
		"calls .RoundTrip", "uses net/http.DefaultTransport"} {
		if !strings.Contains(got, want) {
			t.Errorf("scan missed %q; found:\n%s", want, got)
		}
	}
}

// A running relay (run, as main starts it) sends none of these anywhere: the listener they name
// sees no connection.
func TestFailClosedRunningRelayIsNotAProxy(t *testing.T) {
	victim, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer victim.Close()
	var hits atomic.Int64
	go func() {
		for {
			c, err := victim.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			c.Close()
		}
	}()
	addr, _, _ := start(t, []string{"--listen", "127.0.0.1:0", "--trust-proxy", "127.0.0.1/32"}, envWith("TAILPOCKET_RELAY_TOKEN", "made-up-token-for-test"))
	va := victim.Addr().String()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	room := connectrelay.RoomFor(pub)
	ws := "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
	reqs := []struct{ req, status string }{
		{"CONNECT " + va + " HTTP/1.1\r\nHost: " + va + "\r\n\r\n", "400"},
		{"GET http://" + va + "/ HTTP/1.1\r\nHost: " + va + "\r\nConnection: close\r\n\r\n", "400"},
		{"POST http://" + va + "/ HTTP/1.1\r\nHost: " + va + "\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx", "400"},
		{"GET http://" + va + connectrelay.PathPhone + "?room=" + room + " HTTP/1.1\r\nHost: " + va + "\r\n" + ws + "\r\n", "400"},
		{"GET http://" + va + connectrelay.PathHost + "?room=" + room + " HTTP/1.1\r\nHost: " + va + "\r\nAuthorization: Bearer made-up-token-for-test\r\n" + ws + "\r\n", "400"},
		{"OPTIONS * HTTP/1.1\r\nHost: " + va + "\r\nConnection: close\r\n\r\n", "400"},
		{"GET / HTTP/1.1\r\nHost: " + va + "\r\nX-Forwarded-Host: " + va + "\r\nX-Forwarded-For: " + strings.Split(va, ":")[0] + "\r\nConnection: close\r\n\r\n", "404"},
		{"GET " + connectrelay.PathPhone + "?room=" + room + " HTTP/1.1\r\nHost: " + va + "\r\nX-Forwarded-For: " + va + "\r\n" + ws + "\r\n", "101"}, // then 4404
		{"GET " + connectrelay.PathPhone + "?room=" + strings.NewReplacer(":", "%3A").Replace(va) + " HTTP/1.1\r\nHost: x\r\n" + ws + "\r\n", "400"},
		{"GET " + connectrelay.PathHost + "?room=" + room + " HTTP/1.1\r\nHost: " + va + "\r\nAuthorization: Bearer made-up-token-for-test\r\n" + ws + "\r\n", "101"}, // the relay's own challenge
	}
	for _, tc := range reqs {
		if line := exchange(t, addr, tc.req); !strings.Contains(line, " "+tc.status+" ") {
			first, _, _ := strings.Cut(tc.req, "\r\n")
			t.Errorf("%s: %q, want %s", first, line, tc.status)
		}
	}
	time.Sleep(200 * time.Millisecond)
	if n := hits.Load(); n != 0 {
		t.Fatalf("the listener the requests named got %d connection(s), want 0", n)
	}
}

// exchange sends req on a new connection to addr and returns the status line of the answer.
func exchange(t *testing.T, addr, req string) string {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, req)
	c.SetReadDeadline(time.Now().Add(time.Second))
	b, _ := io.ReadAll(c)
	line, _, _ := strings.Cut(string(b), "\r\n")
	return line
}

// Request headers are capped at 8 KiB (net/http lets a request read 4 KiB past MaxHeaderBytes):
// a bigger header gets 431.
func TestFailClosedRunningRelayHeaderLimits(t *testing.T) {
	addr, _, _ := start(t, []string{"--listen", "127.0.0.1:0"}, envWith("TAILPOCKET_RELAY_TOKEN", "made-up-token-for-test"))
	req := func(pad int) string {
		return "GET /healthz HTTP/1.1\r\nHost: x\r\nX-Pad: " + strings.Repeat("a", pad) + "\r\nConnection: close\r\n\r\n"
	}
	if line := exchange(t, addr, req(6<<10)); !strings.Contains(line, " 200 ") {
		t.Fatalf("6 KiB header: %q, want 200", line)
	}
	if line := exchange(t, addr, req(16<<10)); !strings.Contains(line, " 431 ") {
		t.Fatalf("16 KiB header: %q, want 431", line)
	}
}
