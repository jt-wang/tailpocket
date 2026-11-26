package connectmdns

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func testService() Service {
	return Service{Instance: "Studio Mac", Type: "_tailpocket-demo._tcp", Port: 40123, TXT: []string{"v=1"}}
}

func question(t *testing.T, name string, typ dnsmessage.Type) dnsmessage.Question {
	t.Helper()
	return dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET}
}

func TestServiceValidation(t *testing.T) {
	good := testService()
	if err := good.validate(); err != nil {
		t.Fatal(err)
	}
	for _, typ := range []string{"", "tailpocket-demo._tcp", "_tailpocket-demo", "_tailpocket-demo._udp", "_has space._tcp", "_waytoolongservicename._tcp"} {
		s := good
		s.Type = typ
		if s.validate() == nil {
			t.Errorf("type %q accepted", typ)
		}
	}
	for _, inst := range []string{"", "a.b", "line\nbreak", strings.Repeat("x", 64)} {
		s := good
		s.Instance = inst
		if s.validate() == nil {
			t.Errorf("instance %q accepted", inst)
		}
	}
	s := good
	s.Port = 0
	if s.validate() == nil {
		t.Error("port 0 accepted")
	}
}

func TestAnswersForBrowseQuery(t *testing.T) {
	r := newRecords(testService(), "studio-mac-1a2b.local.")
	ips := []net.IP{net.IPv4(192, 168, 1, 20)}
	answers, extra := r.answer(question(t, "_tailpocket-demo._tcp.local.", dnsmessage.TypePTR), ips)
	if len(answers) != 1 {
		t.Fatalf("answers %v", answers)
	}
	ptr, ok := answers[0].Body.(*dnsmessage.PTRResource)
	if !ok || ptr.PTR.String() != "Studio Mac._tailpocket-demo._tcp.local." {
		t.Fatalf("ptr %+v", answers[0].Body)
	}
	var srv, txt, a bool
	for _, rr := range extra {
		switch b := rr.Body.(type) {
		case *dnsmessage.SRVResource:
			srv = b.Port == 40123 && b.Target.String() == "studio-mac-1a2b.local."
		case *dnsmessage.TXTResource:
			txt = len(b.TXT) == 1 && b.TXT[0] == "v=1"
		case *dnsmessage.AResource:
			a = net.IP(b.A[:]).Equal(ips[0])
		}
	}
	if !srv || !txt || !a {
		t.Fatalf("additional srv=%v txt=%v a=%v", srv, txt, a)
	}
}

func TestAnswersForOtherQuestions(t *testing.T) {
	r := newRecords(testService(), "studio-mac-1a2b.local.")
	ips := []net.IP{net.IPv4(10, 0, 0, 2)}
	if a, _ := r.answer(question(t, "_services._dns-sd._udp.local.", dnsmessage.TypePTR), ips); len(a) != 1 {
		t.Fatalf("service enumeration: %v", a)
	}
	if a, _ := r.answer(question(t, "Studio Mac._tailpocket-demo._tcp.local.", dnsmessage.TypeSRV), ips); len(a) != 1 {
		t.Fatalf("srv: %v", a)
	}
	if a, _ := r.answer(question(t, "studio-mac-1a2b.local.", dnsmessage.TypeA), ips); len(a) != 1 {
		t.Fatalf("a: %v", a)
	}
	if a, _ := r.answer(question(t, "STUDIO MAC._TAILPOCKET-DEMO._TCP.LOCAL.", dnsmessage.TypeTXT), ips); len(a) != 1 {
		t.Fatalf("names compare case-insensitively: %v", a)
	}
	if a, _ := r.answer(question(t, "_other._tcp.local.", dnsmessage.TypePTR), ips); len(a) != 0 {
		t.Fatalf("answered a foreign type: %v", a)
	}
}

func TestLegacyUnicastReplyEchoesIDAndQuestion(t *testing.T) {
	r := newRecords(testService(), "studio-mac-1a2b.local.")
	q := question(t, "_tailpocket-demo._tcp.local.", dnsmessage.TypePTR)
	query := buildQuery(t, 0x4242, q)
	reply, unicast, ok := r.respond(query, 49152, []net.IP{net.IPv4(192, 168, 1, 20)})
	if !ok || !unicast {
		t.Fatalf("ok=%v unicast=%v", ok, unicast)
	}
	var p dnsmessage.Parser
	h, err := p.Start(reply)
	if err != nil {
		t.Fatal(err)
	}
	if h.ID != 0x4242 || !h.Response {
		t.Fatalf("header %+v", h)
	}
	qs, err := p.AllQuestions()
	if err != nil || len(qs) != 1 || qs[0].Name.String() != q.Name.String() {
		t.Fatalf("questions %v %v", qs, err)
	}
	// From port 5353 it is a normal multicast query: no ID echo, multicast reply.
	if _, unicast, ok := r.respond(query, 5353, nil); !ok || unicast {
		t.Fatalf("mdns query: ok=%v unicast=%v", ok, unicast)
	}
}

func buildQuery(t *testing.T, id uint16, q dnsmessage.Question) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(q); err != nil {
		t.Fatal(err)
	}
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func needLAN(t *testing.T) {
	t.Helper()
	if os.Getenv("TAILPOCKET_NO_LAN") == "1" || len(lanInterfaces()) == 0 {
		t.Skip("no Wi-Fi/LAN interface")
	}
}

func uniqueService(t *testing.T) Service {
	s := testService()
	s.Instance = "tailpocket test " + strings.ReplaceAll(t.Name(), "/", "-")[4:] + " " + time.Now().Format("150405.000")
	s.Instance = strings.ReplaceAll(s.Instance, ".", "")
	if len(s.Instance) > 63 {
		s.Instance = s.Instance[:63]
	}
	return s
}

func findIn(t *testing.T, ctx context.Context, s Service) Entry {
	t.Helper()
	// On a failure, say which step of the system browse got no answer (a CI runner nobody can log in
	// to), from what this Browse saw, with no names or addresses (CI logs are public).
	var mu sync.Mutex
	var seen []resolveSummary
	hooks := hooksOf(ctx) // a fixture's tool, if a test set one
	hooks.trace = func(instance string, r resolveSummary) {
		if instance == s.Instance {
			mu.Lock()
			seen = append(seen, r)
			mu.Unlock()
		}
	}
	ctx = context.WithValue(ctx, dnssdHooksKey{}, hooks)
	defer func() {
		if t.Failed() && SystemBrowseAvailable() && runtime.GOOS == "darwin" {
			mu.Lock()
			defer mu.Unlock()
			t.Log(describeResolve(seen))
		}
	}()
	entries, err := Browse(ctx, s.Type)
	if err != nil {
		t.Fatal(err)
	}
	for e := range entries {
		if e.Instance == s.Instance {
			return e
		}
	}
	mu.Lock()
	onlyLoopback := resolvedOnlyOnLoopback(seen, isLoopbackIndex)
	mu.Unlock()
	if onlyLoopback && multicastBlocked(s.Type) {
		// A machine with no LAN multicast (a CI runner): its Bonjour has the service on lo0 only, which
		// no phone can reach. On a machine that can send multicast the same answer fails below.
		t.Skipf("NOT TESTED HERE: no LAN multicast on this machine; %s", describeResolve(seen))
	}
	t.Fatalf("%q not found", s.Instance)
	return Entry{}
}

// resolvedOnlyOnLoopback reports whether the system browse resolved the instance, and only ever on a
// loopback interface.
func resolvedOnlyOnLoopback(seen []resolveSummary, loopback func(string) bool) bool {
	resolved := false
	for _, r := range seen {
		if !r.Port {
			continue
		}
		if !loopback(r.Interface) {
			return false
		}
		resolved = true
	}
	return resolved
}

func isLoopbackIndex(index string) bool {
	n, err := strconv.Atoi(index)
	if err != nil {
		return false
	}
	ifi, err := net.InterfaceByIndex(n)
	return err == nil && ifi.Flags&net.FlagLoopback != 0
}

// multicastBlocked reports whether this process cannot send multicast at all (the builtin tests'
// NOT TESTED HERE case); it sends one browse query for typ, a valid service type.
func multicastBlocked(typ string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	entries, err := BrowseBuiltin(ctx, typ)
	if err == nil {
		for range entries {
		}
	}
	return errors.Is(err, ErrMulticastBlocked)
}

func TestResolvedOnlyOnLoopback(t *testing.T) {
	lo := func(i string) bool { return i == "1" }
	on := func(i string) resolveSummary { return resolveSummary{Port: true, Interface: i} }
	for _, c := range []struct {
		name string
		seen []resolveSummary
		want bool
	}{
		{"loopback only", []resolveSummary{on("1")}, true},
		{"loopback twice", []resolveSummary{on("1"), on("1")}, true},
		{"a LAN interface", []resolveSummary{on("15")}, false},
		{"loopback and a LAN interface", []resolveSummary{on("1"), on("15")}, false},
		{"not listed", nil, false},
		{"listed, never resolved", []resolveSummary{{}}, false},
		{"loopback, and one try that did not resolve", []resolveSummary{{}, on("1")}, true},
	} {
		if got := resolvedOnlyOnLoopback(c.seen, lo); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	if !isLoopbackIndex(strconv.Itoa(loopbackIndex(t))) || isLoopbackIndex("x") {
		t.Fatal("isLoopbackIndex")
	}
}

func loopbackIndex(t *testing.T) int {
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 {
			return i.Index
		}
	}
	t.Skip("no loopback interface")
	return 0
}

// describeResolve says what the system browse saw for one instance: listed or not by -B, resolved
// or not by -L (and on which interface), and how many loopback and other addresses -G v4 gave.
func describeResolve(seen []resolveSummary) string {
	if len(seen) == 0 {
		return "system browse: dns-sd -B did not list the instance"
	}
	var b strings.Builder
	b.WriteString("system browse: dns-sd -B listed the instance")
	for _, r := range seen {
		if !r.Port {
			b.WriteString("; -L gave no host and port, -G skipped")
			continue
		}
		fmt.Fprintf(&b, "; -L resolved it on interface %s; -G v4: %d loopback, %d other (%d on that interface)",
			r.Interface, r.Loopback, r.Other, r.OnInterface)
	}
	return b.String()
}

func advertiseBuiltin(t *testing.T, s Service) func() {
	t.Helper()
	stop, err := AdvertiseBuiltin(s)
	if errors.Is(err, ErrMulticastBlocked) {
		t.Skip("NOT TESTED HERE: this process may not send multicast (macOS Local Network privacy)")
	}
	if err != nil {
		t.Fatal(err)
	}
	return stop
}

func TestParseTXT(t *testing.T) {
	got := parseTXT(` v=1 k=a\ b n=\195\169`)
	if got["v"] != "1" || got["k"] != "a b" || got["n"] != "é" {
		t.Fatalf("%q", got)
	}
}

func TestBuiltinAdvertiseIsFoundByBrowse(t *testing.T) {
	needLAN(t)
	s := uniqueService(t)
	stop := advertiseBuiltin(t, s)
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	e := findIn(t, ctx, s)
	if e.Port != s.Port || len(e.IPv4) == 0 || e.TXT["v"] != "1" {
		t.Fatalf("entry %+v", e)
	}
}

// The system browser (mDNSResponder on macOS) must see the builtin responder: that is what
// iOS's NWBrowser and Android's NsdManager talk to on other devices.
func TestBuiltinAdvertiseIsSeenBySystemBrowser(t *testing.T) {
	needLAN(t)
	if runtime.GOOS != "darwin" {
		t.Skip("dns-sd browser check runs on macOS")
	}
	s := uniqueService(t)
	stop := advertiseBuiltin(t, s)
	defer stop()
	if !systemBrowserSees(t, s) {
		t.Fatalf("dns-sd -B did not list %q", s.Instance)
	}
}

func TestSystemAdvertiseIsFoundByBrowse(t *testing.T) {
	needLAN(t)
	if !SystemAvailable() {
		t.Skip("no system Bonjour tool")
	}
	s := uniqueService(t)
	stop, err := AdvertiseSystem(s)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	e := findIn(t, ctx, s)
	if e.Port != s.Port || len(e.IPv4) == 0 {
		t.Fatalf("entry %+v", e)
	}
	stop()
	time.Sleep(time.Second)
	if systemBrowserSees(t, s) {
		t.Fatal("still listed after stop")
	}
}

func TestBuiltinBrowseFindsSystemAdvertise(t *testing.T) {
	needLAN(t)
	if !SystemAvailable() {
		t.Skip("no system Bonjour tool")
	}
	s := uniqueService(t)
	stop, err := AdvertiseSystem(s)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	entries, err := BrowseBuiltin(ctx, s.Type)
	if errors.Is(err, ErrMulticastBlocked) {
		t.Skip("NOT TESTED HERE: this process may not send multicast (macOS Local Network privacy)")
	}
	if err != nil {
		t.Fatal(err)
	}
	for e := range entries {
		if e.Instance == s.Instance && e.Port == s.Port {
			return
		}
	}
	t.Fatal("not found")
}

// systemBrowserSees reports whether dns-sd -B lists s at the end of a short browse (an Add not
// followed by a Rmv).
func systemBrowserSees(t *testing.T, s Service) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/dns-sd", "-B", s.Type, "local")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = cmd.Wait() }()
	sc := bufio.NewScanner(out)
	listed := false
	for sc.Scan() {
		line := sc.Text()
		if strings.HasSuffix(line, s.Instance) {
			listed = strings.Contains(line, " Add ")
		}
	}
	return listed
}

// The failure summary tells loopback-only, usable and unresolved answers apart, and carries no
// instance name, host name, TXT or address from dns-sd's records into the (public) test log.
func TestResolveSummaryFixtures(t *testing.T) {
	tool := fakeDNSSD(t)
	resolved := " 4:02:35.137  secret\\032inst._x._tcp.local. can be reached at secret-host.local.:40123 (interface 7) Flags: 1\n k=secret-txt\n"
	cases := []struct {
		name, l, g, want string
		ok, calledG      bool
	}{
		{"loopback only", resolved, " 4:02:38.151  Add  40000002       1  secret-host.local.   127.0.0.1    4500\n",
			"-L resolved it on interface 7; -G v4: 1 loopback, 0 other (0 on that interface)", false, true},
		// The other interface first: Browse stops -G once the resolving interface answers.
		{"usable", resolved, " 4:02:38.151  Add  40000002       3  secret-host.local.   198.51.100.3 4500\n" +
			" 4:02:38.452  Add  40000002       7  secret-host.local.   192.0.2.10   4500\n",
			"-L resolved it on interface 7; -G v4: 0 loopback, 2 other (1 on that interface)", true, true},
		{"unresolved", "", "", "-L gave no host and port, -G skipped", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			for k, v := range map[string]string{"FIX_L": c.l, "FIX_G": c.g, "FIX_CALLS": ""} {
				_ = os.WriteFile(dir+"/"+k, []byte(v), 0o644)
				t.Setenv(k, dir+"/"+k)
			}
			var seen []resolveSummary
			ctx := context.WithValue(context.Background(), dnssdHooksKey{}, dnssdHooks{tool: tool,
				trace: func(_ string, r resolveSummary) { seen = append(seen, r) }})
			_, ok := resolveDNSSD(ctx, "secret inst", "_x._tcp")
			got := describeResolve(seen)
			calls, _ := os.ReadFile(dir + "/FIX_CALLS")
			if ok != c.ok || !strings.HasSuffix(got, "listed the instance; "+c.want) || strings.Contains(string(calls), "-G") != c.calledG {
				t.Fatalf("ok %v, %q, calls %q", ok, got, calls)
			}
			for _, leak := range []string{"secret", "192.0.2", "198.51", "127.0.0.1", "40123"} {
				if strings.Contains(got, leak) {
					t.Fatalf("summary leaks %q: %q", leak, got)
				}
			}
		})
	}
	if got := describeResolve(nil); got != "system browse: dns-sd -B did not list the instance" {
		t.Fatal(got)
	}
}

// findIn returns as soon as its instance resolves, while another instance on the same browse is still
// resolving; that one's report comes later and must not crash (it once hit a cleared global hook).
func TestFindInReturnsWhileAnotherInstanceResolves(t *testing.T) {
	tool := fakeDNSSD(t)
	if runtime.GOOS != "darwin" {
		t.Skip("findIn browses with dns-sd on macOS only")
	}
	dir := t.TempDir()
	add := " 4:02:32.143  Add        3   7 local.               _x._tcp.             %s\n"
	files := map[string]string{
		"FIX_B":     fmt.Sprintf(add, "slow") + fmt.Sprintf(add, "fast"),
		"FIX_L":     " 4:02:35.137  fast._x._tcp.local. can be reached at h.local.:40123 (interface 7) Flags: 1\n v=1\n",
		"FIX_G":     " 4:02:38.151  Add  40000002       7  h.local.   192.0.2.10   4500\n",
		"FIX_CALLS": "",
	}
	for k, v := range files {
		_ = os.WriteFile(dir+"/"+k, []byte(v), 0o644)
		t.Setenv(k, dir+"/"+k)
	}
	t.Setenv("FIX_SLOW", "slow")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, dnssdHooksKey{}, dnssdHooks{tool: tool})
	if e := findIn(t, ctx, Service{Instance: "fast", Type: "_x._tcp"}); e.Port != 40123 {
		t.Fatalf("entry %+v", e)
	}
	// The slow -L answers nothing after 500 ms, and its resolveDNSSD reports then.
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		calls, _ := os.ReadFile(dir + "/FIX_CALLS")
		if strings.Count(string(calls), "-L") == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the slow instance was never resolved")
		}
	}
	time.Sleep(time.Second)
}

// fakeDNSSD writes a dns-sd stand-in that prints $FIX_B, $FIX_L or $FIX_G (one line every 300 ms),
// appends its first argument to $FIX_CALLS, and for -L of $FIX_SLOW waits 500 ms and answers nothing.
func fakeDNSSD(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("the dns-sd fixture is a /bin/sh script")
	}
	tool := t.TempDir() + "/dns-sd"
	script := `#!/bin/sh
echo "$1" >> "$FIX_CALLS"
case "$1" in
-B) cat "$FIX_B"; exec sleep 5 ;;
-L) if [ -n "$FIX_SLOW" ] && [ "$2" = "$FIX_SLOW" ]; then sleep 0.5; exit 0; fi; cat "$FIX_L" ;;
-G) while IFS= read -r line; do echo "$line"; sleep 0.3; done < "$FIX_G" ;;
esac
`
	if err := os.WriteFile(tool, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return tool
}
