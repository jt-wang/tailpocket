package e2e

// Released binaries against this tree: scripts/e2e-compat.sh downloads the last release's
// tailpocket-host and tailpocket-phone (checked against its SHA256SUMS), builds this tree's, and runs
// TestCompatReleasedBinaries for each pair: this host with the released phone, the released host with
// this phone, and this tree with itself. Each pairs with the emoji over a v2 invite, reaches the app
// over lan and over a local tailpocket-relay, and is revoked: sessions it holds open end within
// revokeDeadline and carry nothing more, a second phone's session is untouched, and new connections are
// refused on both routes. Revoking that second phone too (the last one, which restarts the host's
// node) ends its open session the same way. No Tailcat. Without TAILPOCKET_COMPAT_HOST and
// TAILPOCKET_COMPAT_PHONE it is skipped.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCompatReleasedBinaries(t *testing.T) {
	hostBin, phoneBin := os.Getenv("TAILPOCKET_COMPAT_HOST"), os.Getenv("TAILPOCKET_COMPAT_PHONE")
	if hostBin == "" || phoneBin == "" {
		t.Skip("set TAILPOCKET_COMPAT_HOST and TAILPOCKET_COMPAT_PHONE (scripts/e2e-compat.sh)")
	}
	checkHome := noTailcatHome(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	// The app: the host writes the phone's key on the first line, then the phone's bytes. A held session
	// names itself first ("id <tag>"); the app records every line each one sends and when its read ends.
	sessions := newAppSessions()
	app, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	go func() {
		for {
			c, err := app.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				key, _ := r.ReadString('\n')
				var rec *appSession
				defer func() {
					if rec != nil {
						close(rec.ended)
					}
				}()
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if tag, ok := strings.CutPrefix(strings.TrimSpace(line), "id "); ok && rec == nil {
						rec = sessions.open(tag)
					} else if rec != nil {
						rec.got(strings.TrimSpace(line))
					}
					io.WriteString(c, "echo "+strings.TrimSpace(key)+" "+line)
				}
			}()
		}
	}()
	relay := localRelay(t)

	host := exec.CommandContext(ctx, hostBin)
	stdin, _ := host.StdinPipe()
	stdout, _ := host.StdoutPipe()
	host.Stderr = os.Stderr
	if err := host.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { stdin.Close(); _ = host.Wait() }()
	send := func(v any) { b, _ := json.Marshal(v); _, _ = stdin.Write(append(b, '\n')) }
	ev := hostEvents(t, stdout, send)

	send(map[string]any{"v": 1, "forward": app.Addr().String(), "identifyPhone": true, "audit": true, "routes": []string{"lan", "relay"},
		"relays": []any{map[string]any{"url": relay, "token": "e2e-relay-token"}}})
	ev.next(t, "ready")
	// Both routes up before the window opens, so the invite names both.
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		send(map[string]any{"cmd": "status", "id": "st"})
		st := ev.next(t, "status")
		types := map[string]bool{}
		for _, r := range st["routes"].([]any) {
			types[r.(map[string]any)["t"].(string)] = true
		}
		if st["relays"].(map[string]any)[relay] == "up" && types["lan"] && types["relay"] {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("routes not up (lan needs a private address on this machine): %v", st)
		}
	}
	dir := t.TempDir()
	phone := func(stdin string, args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, phoneBin, args...)
		cmd.Stdin = strings.NewReader(stdin)
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		return out.String(), err
	}
	pair := func(name string) (link, key string) {
		send(map[string]any{"cmd": "pair", "id": name, "emoji": true})
		qr2 := ev.next(t, "pairing")["qr2"].(string)
		link = filepath.Join(dir, name+".json")
		if out, err := phone("", "pair", "-routes", "lan,relay", "-device", name, "-key", filepath.Join(dir, name+".key"), "-out", link, qr2); err != nil {
			t.Fatalf("pair %s: %v\n%s", name, err, out)
		}
		paired := ev.next(t, "paired")
		key, _ = paired["phone"].(string)
		if key == "" || paired["device"] != name {
			t.Fatalf("paired %v", paired)
		}
		return link, key
	}
	linkA, keyA := pair("Phone A")
	linkB, keyB := pair("Phone B")
	ev.quiet() // pairing's own audits (it runs over the relay); every check below reads only its dial's

	for _, route := range []string{"lan", "relay"} {
		out, err := phone("ping\n", "dial", "-routes", route, "-link", linkA)
		if want := "echo " + keyA + " ping\n"; err != nil || out != want {
			t.Fatalf("dial over %s: %v, got %q, want %q", route, err, out, want)
		}
		ev.audit(t, "conn-open", keyA, route)
	}

	// Sessions open across the revoke: A's on both routes, and B's.
	aLAN := hold(t, ctx, phoneBin, linkA, "lan", keyA, "a-lan", sessions)
	ev.audit(t, "conn-open", keyA, "lan")
	aRelay := hold(t, ctx, phoneBin, linkA, "relay", keyA, "a-relay", sessions)
	ev.audit(t, "conn-open", keyA, "relay")
	bLAN := hold(t, ctx, phoneBin, linkB, "lan", keyB, "b-lan", sessions)
	ev.audit(t, "conn-open", keyB, "lan")
	revoke := func(key string, left int) {
		send(map[string]any{"cmd": "revoke", "id": "rv-" + key, "phone": key})
		if a := ev.next(t, "allowed"); len(a["allowed"].([]any)) != left {
			t.Fatalf("after revoke: %v", a)
		}
	}
	revoke(keyA, 1)
	endedBy(t, time.Now().Add(revokeDeadline), aLAN, aRelay)
	bLAN.stillUp(t)
	for _, route := range []string{"lan", "relay"} {
		out, err := phone("ping\n", "dial", "-routes", route, "-link", linkA)
		if err == nil || !strings.Contains(out, "no longer has this phone paired") || strings.Contains(out, "echo ") {
			t.Fatalf("dial over %s after revoke: %v\n%s", route, err, out)
		}
		ev.audit(t, "denied", "", route)
	}
	// The last phone: the host restarts its node without it.
	revoke(keyB, 0)
	endedBy(t, time.Now().Add(revokeDeadline), bLAN)
	if out, err := phone("ping\n", "dial", "-routes", "lan", "-link", linkB); err == nil || strings.Contains(out, "echo ") {
		t.Fatalf("B dial after revoke: %v\n%s", err, out)
	}
	checkHome()
}

// revokeDeadline: how long a revoked phone's open session may last.
const revokeDeadline = 10 * time.Second

// heldDial is a tailpocket-phone dial kept open: lines it received, and done when it exits; app is
// the app's record of the same session.
type heldDial struct {
	in    io.WriteCloser
	lines chan string
	done  chan struct{}
	key   string
	tag   string
	app   *appSession
}

// appSession is what the app received on one held session, and ended when its read loop returned.
type appSession struct {
	mu    sync.Mutex
	lines []string
	ended chan struct{}
}

func (a *appSession) got(l string) { a.mu.Lock(); a.lines = append(a.lines, l); a.mu.Unlock() }
func (a *appSession) received() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.lines)
}

type appSessions struct {
	mu     sync.Mutex
	byTag  map[string]*appSession
	opened chan string
}

func newAppSessions() *appSessions {
	return &appSessions{byTag: map[string]*appSession{}, opened: make(chan string, 16)}
}

func (s *appSessions) open(tag string) *appSession {
	rec := &appSession{ended: make(chan struct{})}
	s.mu.Lock()
	s.byTag[tag] = rec
	s.mu.Unlock()
	return rec
}

func (s *appSessions) get(tag string) *appSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.byTag[tag]
}

// hold opens a session over route and checks it reaches the app.
func hold(t *testing.T, ctx context.Context, phoneBin, link, route, key, tag string, sessions *appSessions) *heldDial {
	t.Helper()
	cmd := exec.CommandContext(ctx, phoneBin, "dial", "-routes", route, "-link", link)
	in, _ := cmd.StdinPipe()
	out, _ := cmd.StdoutPipe()
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	h := &heldDial{in: in, lines: make(chan string, 16), done: make(chan struct{}), key: key, tag: tag}
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			h.lines <- sc.Text()
		}
		_ = cmd.Wait()
		close(h.done)
	}()
	t.Cleanup(func() { in.Close(); _ = cmd.Process.Kill() })
	io.WriteString(in, "id "+tag+"\n")
	select {
	case l := <-h.lines:
		if l != "echo "+key+" id "+tag {
			t.Fatalf("session %s got %q", tag, l)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("session %s: no echo", tag)
	}
	if h.app = sessions.get(tag); h.app == nil {
		t.Fatalf("session %s: the app has no record of it", tag)
	}
	h.stillUp(t)
	return h
}

// stillUp sends a line and waits for its echo.
func (h *heldDial) stillUp(t *testing.T) {
	t.Helper()
	io.WriteString(h.in, "alive\n")
	select {
	case l := <-h.lines:
		if l != "echo "+h.key+" alive" {
			t.Fatalf("session got %q", l)
		}
	case <-h.done:
		t.Fatal("session ended")
	case <-time.After(30 * time.Second):
		t.Fatal("no echo on the session")
	}
}

// endedBy sends a probe on each session at once, then checks that by deadline (one for all of them)
// the phone's dial exited and the app's read of that session ended, and that the app never received
// the probe and the phone got nothing back.
func endedBy(t *testing.T, deadline time.Time, hs ...*heldDial) {
	t.Helper()
	for _, h := range hs {
		io.WriteString(h.in, "after "+h.tag+"\n")
	}
	for _, h := range hs {
		for _, ch := range []chan struct{}{h.done, h.app.ended} {
			select {
			case <-ch:
			case <-time.After(time.Until(deadline)):
				t.Fatalf("%s: session still open %v after revoke", h.tag, revokeDeadline)
			}
		}
		if got := h.app.received(); slices.Contains(got, "after "+h.tag) {
			t.Fatalf("%s: the app received %q after revoke", h.tag, "after "+h.tag)
		}
		select {
		case l := <-h.lines:
			t.Fatalf("%s: the phone received %q after revoke", h.tag, l)
		default:
		}
	}
}

// hostEvents reads the helper's events, answers save with ok and the pairRequest's four emoji with
// approve (the user compares them), and hands every event to next.
type hostEventStream struct {
	t      *testing.T
	ch     chan map[string]any
	audits chan map[string]any
}

func hostEvents(t *testing.T, r io.Reader, send func(any)) *hostEventStream {
	s := &hostEventStream{t: t, ch: make(chan map[string]any, 64), audits: make(chan map[string]any, 256)}
	go func() {
		defer close(s.ch)
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			var e map[string]any
			if json.Unmarshal(sc.Bytes(), &e) != nil {
				continue
			}
			switch e["event"] {
			case "audit":
				s.audits <- e
				continue
			case "save":
				send(map[string]any{"cmd": "saved", "id": e["id"], "ok": true})
			case "pairRequest":
				if em, _ := e["emoji"].([]any); len(em) == 4 {
					send(map[string]any{"cmd": "confirm", "id": e["id"], "approve": true})
				}
			}
			s.ch <- e
		}
	}()
	return s
}

// audit waits for the next audit event of kind and checks the route it was on (and the phone, if
// given): the route the host saw, not the one the phone was asked for.
func (s *hostEventStream) audit(t *testing.T, kind, phone, route string) {
	t.Helper()
	timeout := time.After(10 * time.Second)
	for {
		select {
		case e := <-s.audits:
			if e["kind"] != kind {
				continue
			}
			if e["route"] != route || (phone != "" && e["phone"] != phone) {
				t.Fatalf("audit %s: route %v phone %v, want route %s", kind, e["route"], e["phone"], route)
			}
			return
		case <-timeout:
			t.Fatalf("no %s audit on %s", kind, route)
		}
	}
}

// quiet drops audit events until none has come for a second.
func (s *hostEventStream) quiet() {
	for {
		select {
		case <-s.audits:
		case <-time.After(time.Second):
			return
		}
	}
}

func (s *hostEventStream) next(t *testing.T, kind string) map[string]any {
	t.Helper()
	timeout := time.After(90 * time.Second)
	for {
		select {
		case e, ok := <-s.ch:
			if !ok {
				t.Fatalf("helper exited waiting for %s", kind)
			}
			if e["event"] == kind {
				return e
			}
			if e["event"] == "error" {
				t.Fatalf("error waiting for %s: %v", kind, e)
			}
		case <-timeout:
			t.Fatalf("timed out waiting for %s", kind)
		}
	}
}
