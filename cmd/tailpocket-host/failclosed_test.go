package main

// Fail-closed checks for the helper's IPC: it talks only over stdin and stdout, runs no program,
// opens no listener and touches no file itself, and anything it cannot parse gets an error event
// or ends the helper without doing anything else.

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func helperSources(t *testing.T) []*ast.File {
	t.Helper()
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var out []*ast.File
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, f)
	}
	if len(out) < 2 {
		t.Fatalf("scanned %v, want ipc.go and main.go", paths)
	}
	return out
}

// forbidden is, by import path, what runs a program, opens a listener or touches a file.
var forbidden = map[string][]string{
	"os": {"StartProcess", "Executable", "Open", "OpenFile", "Create", "CreateTemp", "ReadFile", "WriteFile", "ReadDir",
		"Remove", "RemoveAll", "Rename", "Mkdir", "MkdirAll", "MkdirTemp", "Chmod", "Chown", "Symlink", "Link", "Truncate", "DirFS", "OpenRoot"},
	"syscall":               {"Exec", "ForkExec", "StartProcess", "Open", "Creat", "Socket", "Bind", "Listen"},
	"golang.org/x/sys/unix": {"Exec", "ForkExec", "Open", "Openat", "Socket", "Bind", "Listen"},
	"net":                   {"Listen", "ListenTCP", "ListenUDP", "ListenIP", "ListenUnix", "ListenUnixgram", "ListenPacket", "ListenMulticastUDP", "ListenConfig", "FileListener"},
	"net/http":              {"ListenAndServe", "ListenAndServeTLS", "Serve", "ServeTLS", "Server", "FileServer", "ServeFile"},
}

var forbiddenImports = []string{"os/exec", "plugin", "net/rpc", "net/http/httputil", "net/http/cgi", "net/http/fcgi", "io/ioutil"}

var forbiddenMethods = []string{"Listen", "ListenPacket", "ListenAndServe", "ListenAndServeTLS"}

func scanForbidden(f *ast.File) []string {
	var found []string
	names := map[string]string{}
	for _, imp := range f.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		if slices.Contains(forbiddenImports, path) {
			found = append(found, "imports "+path)
		}
		name := path[strings.LastIndex(path, "/")+1:]
		if imp.Name != nil {
			name = imp.Name.Name
		}
		names[name] = path
	}
	ast.Inspect(f, func(n ast.Node) bool {
		// A method only when called: cfg.Listen is the config's list of addresses, a field.
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && slices.Contains(forbiddenMethods, sel.Sel.Name) {
				found = append(found, "calls ."+sel.Sel.Name)
			}
		}
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && id.Obj == nil && slices.Contains(forbidden[names[id.Name]], sel.Sel.Name) {
			found = append(found, "uses "+names[id.Name]+"."+sel.Sel.Name)
		}
		return true
	})
	return found
}

// The helper's own code runs no program, opens no listener and reads or writes no file. (It does
// dial one thing: the app's own forward address from the config line, for each phone connection.)
func TestFailClosedHelperSourceRunsNothingListensNowhere(t *testing.T) {
	for _, f := range helperSources(t) {
		for _, hit := range scanForbidden(f) {
			t.Errorf("helper source: %s", hit)
		}
	}
	// The scan is not vacuous.
	planted, err := parser.ParseFile(token.NewFileSet(), "planted.go", `package p
import (x "os/exec"; n "net"; "os"; "net/http"; "syscall")
func f() { x.Command("sh"); n.Listen("tcp", ":0"); os.WriteFile("f", nil, 0); http.ListenAndServe(":1", nil); syscall.Exec("", nil, nil); (&n.ListenConfig{}).Listen(nil, "", "") }
`, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(scanForbidden(planted), "\n")
	for _, want := range []string{"imports os/exec", "uses net.Listen", "uses os.WriteFile", "uses net/http.ListenAndServe", "uses syscall.Exec", "uses net.ListenConfig", "calls .Listen"} {
		if !strings.Contains(got, want) {
			t.Errorf("scan missed %q; found:\n%s", want, got)
		}
	}
}

// ipcCommands reads, from ipc.go, the commands the helper acts on: the cases of handle's switch,
// and the answers Run takes at once.
func ipcCommands(t *testing.T) (handled, answers []string) {
	t.Helper()
	for _, f := range helperSources(t) {
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncDecl:
				if n.Name.Name == "handle" {
					ast.Inspect(n.Body, func(m ast.Node) bool {
						if sw, ok := m.(*ast.SwitchStmt); ok {
							for _, st := range sw.Body.List {
								for _, e := range st.(*ast.CaseClause).List {
									if lit, ok := e.(*ast.BasicLit); ok {
										s, _ := strconv.Unquote(lit.Value)
										handled = append(handled, s)
									}
								}
							}
							return false
						}
						return true
					})
					return false
				}
			case *ast.BinaryExpr: // c.Cmd == "saved"
				if sel, ok := n.X.(*ast.SelectorExpr); ok && sel.Sel.Name == "Cmd" && n.Op == token.EQL {
					if lit, ok := n.Y.(*ast.BasicLit); ok {
						s, _ := strconv.Unquote(lit.Value)
						answers = append(answers, s)
					}
				}
			}
			return true
		})
	}
	return handled, answers
}

// Every command the helper acts on is one docs/HOST-IPC.md lists, and none of them runs a program
// or names a file. A new command fails this test until it is reviewed and added to both lists.
func TestFailClosedIPCCommandsAreTheReviewedOnes(t *testing.T) {
	handled, answers := ipcCommands(t)
	slices.Sort(handled)
	slices.Sort(answers)
	// push: sends only to the target a phone gave over its session, for a gateway in the config's
	// pushGateways (no command can add one); it runs nothing and names no file.
	reviewed := []string{"cancel", "confirm", "disconnect", "local", "pair", "push", "revoke", "setAllowed", "status"}
	if !slices.Equal(handled, reviewed) {
		t.Errorf("handle acts on %v, reviewed %v", handled, reviewed)
	}
	if !slices.Equal(answers, []string{"authorized", "saved"}) {
		t.Errorf("answers taken at once: %v", answers)
	}
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "HOST-IPC.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, table, _ := strings.Cut(string(doc), "## Commands")
	table, _, _ = strings.Cut(table, "## Events")
	var documented []string
	for _, m := range regexp.MustCompile("(?m)^\\| `([A-Za-z]+)` \\|").FindAllStringSubmatch(table, -1) {
		documented = append(documented, m[1])
	}
	slices.Sort(documented)
	if all := slices.Sorted(slices.Values(append(slices.Clone(handled), answers...))); !slices.Equal(all, documented) {
		t.Errorf("ipc.go has %v, HOST-IPC.md lists %v", all, documented)
	}
}

// helper runs Run on pipes and returns a writer for its stdin, its events and its result.
func helper(t *testing.T, config string) (send func(string), ev *eventStream, done chan error, stdin *io.PipeReader) {
	t.Helper()
	in, w := io.Pipe()
	r, out := io.Pipe()
	done = make(chan error, 1)
	go func() { done <- Run(context.Background(), in, out); out.Close() }()
	t.Cleanup(func() { w.Close(); in.Close() })
	ev = events(r)
	send = func(s string) {
		go io.WriteString(w, s) // the helper may stop reading (a line over the limit)
	}
	send(config + "\n")
	ev.next(t, "ready")
	return send, ev, done, in
}

// Malformed and unknown commands get one error event each and change nothing: no save, no
// pairing, no connection to the app's forward address. The helper keeps answering afterwards.
func TestFailClosedMalformedIPC(t *testing.T) {
	app, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	var dialled atomic.Int64
	go func() {
		for {
			c, err := app.Accept()
			if err != nil {
				return
			}
			dialled.Add(1)
			c.Close()
		}
	}()
	send, ev, done, _ := helper(t, `{"v":1,"forward":"`+app.Addr().String()+`"}`)
	lines := []string{
		"garbage", "{", "[]", `"pair"`, "null", `{"cmd":1}`, `{"cmd":["pair"]}`, `{"cmd":"pair","ttl":"x"}`,
		`{"cmd":"exec","id":"e","args":["sh","-c","id"]}`, `{"cmd":"shell","id":"s"}`, `{"cmd":"run","id":"r","path":"/bin/sh"}`,
		`{"cmd":"PAIR","id":"p"}`, `{"cmd":"pair ","id":"p"}`, `{"cmd":"pair"}`,
		`{"cmd":"confirm","id":"nope","approve":true}`, `{"cmd":"cancel","id":"nope"}`,
		`{"cmd":"local","id":"nope","service":"_x._tcp","instance":"--help"}`,
		`{"cmd":"setAllowed","id":"a","allowed":["nodekey:zz"]}`, `{"cmd":"revoke","id":"v","phone":"../../etc/passwd"}`,
		`{"cmd":"saved","id":"s1","ok":true}`, `{"cmd":"authorized","id":"a1","ok":true}`,
		`{"cmd":"disconnect","id":"d","phone":"nobody"}`,
		strings.Repeat("{", 100000), `{"cmd":"status","id":"` + strings.Repeat("x", 500000) + `"}`,
	}
	for _, l := range lines {
		send(l + "\n")
		time.Sleep(5 * time.Millisecond) // one at a time, in order
	}
	send(`{"cmd":"status","id":"last"}` + "\n")
	errs := 0
	for {
		var e map[string]any
		select {
		case e = <-ev.ch:
		case <-time.After(20 * time.Second):
			t.Fatal("no status answer")
		}
		kind := e["event"]
		if kind == "status" && e["id"] == "last" {
			break
		}
		switch kind {
		case "error":
			errs++
			if c := e["code"]; !slices.Contains([]any{"invalid-command", "unknown-command", "unknown-pairing", "invalid-allowed", "operation-failed"}, c) {
				t.Errorf("error code %v", c)
			}
		case "disconnected", "status": // disconnect of a phone it does not know; the long-id status
		default:
			t.Errorf("malformed input caused %v", e)
		}
	}
	if errs < 18 {
		t.Errorf("%d error events for %d malformed lines", errs, len(lines))
	}
	if n := dialled.Load(); n != 0 {
		t.Errorf("the app's forward address was dialled %d time(s)", n)
	}
	select {
	case err := <-done:
		t.Fatalf("helper exited: %v", err)
	default:
	}
}

// A line over the 1 MiB limit ends the helper: it stops reading and returns, having done nothing.
func TestFailClosedOverlongIPCLineEndsTheHelper(t *testing.T) {
	send, ev, done, stdin := helper(t, `{"v":1,"forward":"127.0.0.1:9"}`)
	send(`{"cmd":"pair","id":"p","payload":"` + strings.Repeat("x", lineLimit+10) + `"}` + "\n")
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("helper still running after a line over the limit")
	}
	stdin.Close() // unblock the writer
	for e := range ev.ch {
		if e["event"] != "error" {
			t.Errorf("after an over-long line: %v", e)
		}
	}
	// The config line has the same limit.
	out, err := runWith(t, `{"v":1,"forward":"127.0.0.1:9","name":"`+strings.Repeat("x", lineLimit)+`"}`+"\n")
	if err == nil || !strings.Contains(out, `"code":"invalid-config"`) {
		t.Fatalf("over-long config: %q %v", out, err)
	}
}

// Finding for the IPC owner (ipc.go): after a line over the limit the helper returns nil (exit 0)
// with no error event, so the app cannot tell it from a normal stop on stdin closing.
func TestFailClosedOverlongIPCLineIsReported(t *testing.T) {
	send, ev, done, stdin := helper(t, `{"v":1,"forward":"127.0.0.1:9"}`)
	send(strings.Repeat("x", lineLimit+10) + "\n")
	err := <-done
	stdin.Close()
	got := false
	for e := range ev.ch {
		got = got || e["event"] == "error"
	}
	if err == nil || !got {
		t.Fatalf("over-long line: Run returned %v, error event %v; want both", err, got)
	}
}
