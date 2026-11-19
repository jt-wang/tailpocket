package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestConfigErrors(t *testing.T) {
	for name, edit := range map[string][2]string{
		"unknown field":               {`"state_file"`, `"stat_file": "x", "state_file"`},
		"no handle key":               {`"handle_key_file": "handle.key",`, ``},
		"no state file":               {`"state_file": "state.json",`, ``},
		"ttl over 30 days":            {`"state_file"`, `"handle_ttl_days": 31, "state_file"`},
		"key id 0 is taken":           {`"state_file"`, `"handle_key_id": 256, "state_file"`},
		"old key same id":             {`"state_file"`, `"old_handle_keys": [{"id": 1, "file": "x"}], "state_file"`},
		"duplicate app":               {`"id": "io.example.bravo"`, `"id": "io.example.alpha"`},
		"app id with NUL":             {`"id": "io.example.bravo"`, `"id": "io.example.bravo\u0000x"`},
		"bad env":                     {`"env": "sandbox"`, `"env": "staging"`},
		"bad team id":                 {`"team_id": "TEAM123456", "key_id": "KEY1234567", "key_file": "apns.p8", "topic": "io.example.alpha"`, `"team_id": "team", "key_id": "KEY1234567", "key_file": "apns.p8", "topic": "io.example.alpha"`},
		"no placeholder":              {`"placeholder": {"title": "Alpha", "body": "New activity"},`, ``},
		"topic header":                {`"topic": "io.example.alpha"`, `"topic": "io.example.alpha\r\nx: y"`},
		"no platform":                 {`,` + "\n" + `     "apns": {"team_id": "TEAM123456", "key_id": "KEY1234567", "key_file": "apns.p8", "topic": "io.example.bravo.app"}`, ``},
		"bad fcm project":             {`"project_id": "alpha-proj"`, `"project_id": "../x"`},
		"attest for fcm only, no fcm": {`"id": "io.example.bravo",`, `"id": "io.example.bravo", "attest": {"android": {}},`},
		"trailing data":               {"\n}", "\n} {}"},
		"bad trust_proxy":             {`"state_file"`, `"trust_proxy": ["10.0.0.1"], "state_file"`},
	} {
		cfg := strings.Replace(baseConfig, edit[0], edit[1], 1)
		if cfg == baseConfig {
			t.Fatalf("%s: edit not applied", name)
		}
		if _, err := parseConfig([]byte(cfg), t.TempDir()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	c, err := parseConfig([]byte(baseConfig), "/etc/push")
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != defaultListen || c.HandleKeyFile != "/etc/push/handle.key" || c.Apps[1].APNs.Env != "production" ||
		c.HandleTTLDays != 30 || c.HandleKeyID != 1 {
		t.Fatalf("defaults: %+v", c)
	}
}

func TestHandleKeyFileIsCreatedPrivateAndKept(t *testing.T) {
	g := newGateway(t)
	p := filepath.Join(g.dir, "handle.key")
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != 32 {
		t.Fatalf("handle key is %d bytes", fi.Size())
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("handle key mode %v, want 0600", fi.Mode().Perm())
	}
	before, _ := os.ReadFile(p)
	h := g.register(appA, "apns", apnsToken(1), 1, ipX)
	g.srv = g.build(baseConfig) // a restart
	after, _ := os.ReadFile(p)
	if !bytes.Equal(before, after) {
		t.Fatal("handle key changed on restart")
	}
	wantCode(t, g.send(h, g.ct(appA, 1), ipY, nil), 202, "")

	os.WriteFile(p, []byte("short"), 0o600)
	cfg, _ := parseConfig([]byte(baseConfig), g.dir)
	if _, err := loadHandleKeys(cfg, func(string, ...any) {}); err == nil {
		t.Fatal("a 5-byte handle key was taken")
	}
}

func TestStateFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "state.json")
	s, err := loadGenStore(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(p); err != nil || runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("state file not created 0600: %v %v", fi, err)
	}
	now := time.Unix(1_790_000_000, 0)
	if err := s.revoke("dev1", 4, now); err != nil {
		t.Fatal(err)
	}
	if err := s.register("dev2", 1, now); err != nil {
		t.Fatal(err)
	}
	s2, err := loadGenStore(p)
	if err != nil {
		t.Fatal(err)
	}
	if s2.min("dev1") != 5 || s2.min("dev2") != 0 || len(s2.m) != 1 {
		t.Fatalf("reloaded %v", s2.m)
	}
	if err := s2.register("dev1", 4, now); err != errStale {
		t.Fatalf("register below min: %v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".tailpocket-push-state-*")); len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}
	// Forgotten only once every handle below it has expired.
	s2.sweep(now.Add(maxHandleTTL))
	if s2.min("dev1") != 5 {
		t.Fatal("swept while handles below it may still be valid")
	}
	s2.sweep(now.Add(maxHandleTTL + 25*time.Hour))
	if s2.min("dev1") != 0 {
		t.Fatal("not swept")
	}

	// A full store refuses new devices rather than forget one.
	s2.max = 1
	s2.revoke("a", 1, now)
	if err := s2.revoke("b", 1, now); err != errStateFull {
		t.Fatalf("full store: %v", err)
	}

	// A damaged file stops the start: starting empty would bring revoked
	// handles back.
	os.WriteFile(p, []byte(`{"version":1,"min_generation":{"x":`), 0o600)
	if _, err := loadGenStore(p); err == nil {
		t.Fatal("a damaged state file was taken")
	}
}

func TestRunRefusesBadSetups(t *testing.T) {
	run1 := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return run(ctx, args, &out, &errb), out.String(), errb.String()
	}
	if code, _, stderr := run1(); code != 2 || !strings.Contains(stderr, "--config push.json") {
		t.Fatalf("no config: %d %s", code, stderr)
	}
	if code, out, _ := run1("--version"); code != 0 || !strings.HasPrefix(out, "tailpocket-push ") {
		t.Fatalf("--version: %d %q", code, out)
	}
	if code, _, stderr := run1("--config", filepath.Join(t.TempDir(), "none.json")); code != 2 || stderr == "" {
		t.Fatalf("missing config: %d %s", code, stderr)
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "push.json"), []byte(baseConfig), 0o600)
	if code, _, stderr := run1("--config", filepath.Join(dir, "push.json")); code != 2 || !strings.Contains(stderr, "apns.p8") {
		t.Fatalf("missing .p8: %d %s", code, stderr)
	}
}

// Every base image is pinned by digest, so a rebuild cannot pick up an image
// newer than the one that was checked (see the comment above each FROM).
func TestDockerfilePinsBaseImages(t *testing.T) {
	b, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	pinned := regexp.MustCompile(`^FROM\s+\S+@sha256:[0-9a-f]{64}(\s+AS\s+\S+)?$`)
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(strings.ReplaceAll(line, " ", "")), "#syntax=") {
			t.Errorf("syntax directive pulls an unpinned frontend image: %s", line)
		}
		if !strings.HasPrefix(strings.ToUpper(line), "FROM ") {
			continue
		}
		n++
		if !pinned.MatchString(line) {
			t.Errorf("base image not pinned by digest: %s", line)
		}
	}
	if n != 2 {
		t.Fatalf("found %d FROM lines, want the two stages", n)
	}
}
