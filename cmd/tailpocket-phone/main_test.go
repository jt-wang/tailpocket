package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestUsageAndBadArguments(t *testing.T) {
	for _, args := range [][]string{{}, {"dance"}, {"pair"}, {"local"}, {"connect"}, {"dial"}} {
		var stderr bytes.Buffer
		if code := run(args, strings.NewReader(""), &bytes.Buffer{}, &stderr); code != 2 {
			t.Errorf("%v: exit %d", args, code)
		}
		if !strings.Contains(stderr.String(), "usage") {
			t.Errorf("%v: no usage in %q", args, stderr.String())
		}
	}
}

func TestPairRejectsGarbageInvite(t *testing.T) {
	var stderr bytes.Buffer
	if code := run([]string{"pair", "tailpocket1:garbage"}, strings.NewReader(""), &bytes.Buffer{}, &stderr); code != 1 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
}
