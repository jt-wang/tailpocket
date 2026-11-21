package e2e

import "testing"

// noTailcatSockets returns a check that every socket the process opened since is on loopback: no
// Tailcat UDP socket, no connection to tailcat.dev or a DERP node.
func noTailcatSockets(t *testing.T) func() {
	before := map[string]bool{}
	for _, s := range ownSockets(t) {
		before[s.String()] = true
	}
	return func() {
		t.Helper()
		for _, s := range ownSockets(t) {
			if before[s.String()] {
				continue
			}
			if !s.local.Addr().IsLoopback() || (!s.listen && s.remote.Addr().IsValid() && !s.remote.Addr().IsUnspecified() && !s.remote.Addr().IsLoopback()) {
				t.Errorf("socket beyond loopback without Tailcat: %s", s)
			}
		}
	}
}
