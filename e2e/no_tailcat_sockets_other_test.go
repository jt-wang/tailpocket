//go:build !linux

package e2e

import "testing"

// noTailcatSockets needs /proc (Linux); elsewhere the Tailcat start counter and the state check run.
func noTailcatSockets(*testing.T) func() { return func() {} }
