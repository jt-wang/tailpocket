package connectrelay

// SetAfterUpgrade has f run right after each WebSocket upgrade, with the
// request path; a test uses it to panic there. Set it before serving.
func (s *Server) SetAfterUpgrade(f func(path string)) { s.afterUpgrade = f }

// ConnsForTest is how many TCP connections the Listener counts now.
func (s *Server) ConnsForTest() int {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	return s.conns
}
