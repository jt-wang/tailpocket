package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

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
		// A syntax directive pulls a frontend image by tag before any FROM.
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
