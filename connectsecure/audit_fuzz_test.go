package connectsecure

import (
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/flynn/noise"
)

// Audit (fail closed): what a stranger sends to the host before any key is checked. Accept must
// return an error and close the connection, whatever the bytes: no session, no panic, no hang.
func FuzzAuditHostFirstBytes(f *testing.F) {
	f.Add([]byte("TP2C\x00\x00"))
	f.Add([]byte("TP2P\x00\x10aaaaaaaaaaaaaaaa"))
	f.Add([]byte("TP1C"))
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Add(append([]byte("TP2C\xff\xff"), make([]byte, 300)...))
	id, err := NewIdentity()
	if err != nil {
		f.Fatal(err)
	}
	// A well-formed first message from someone who knows the host's public key, with nothing or
	// with junk after it: the fuzzer starts from the deepest point a stranger reaches.
	for _, pair := range []bool{false, true} {
		static, _ := noise.DH25519.GenerateKeypair(rand.Reader)
		hs, err := noise.NewHandshakeState(handshakeConfig(pair, true, static, id.Public[:], []byte(prologue), nil))
		if err != nil {
			f.Fatal(err)
		}
		mode, payload := byte(modeConnect), []byte(`{"proto":2}`)
		if pair {
			hs.SetPresharedKey(make([]byte, 32))
			mode, payload = modePair, []byte(`{"proto":2,"cid":"AAAAAAAAAAAAAAAA"}`)
		}
		m0, _, _, err := hs.WriteMessage(nil, payload)
		if err != nil {
			f.Fatal(err)
		}
		first := appendFrame([]byte{'T', 'P', '2', mode}, m0)
		f.Add(first)
		f.Add(append(append([]byte{}, first...), 0, 40, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
			21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		a, b := net.Pipe()
		done := make(chan error, 1)
		go func() {
			s, err := Accept(b, ServerConfig{Identity: id, Admit: admitAll,
				PSK:    func(string) ([32]byte, bool) { return [32]byte{}, true },
				Timing: Timing{First: 2 * time.Second, Handshake: 3 * time.Second}})
			if s != nil {
				s.Close()
			}
			done <- err
		}()
		go func() { // whatever the host answers is dropped
			buf := make([]byte, 1<<16)
			for {
				if _, err := a.Read(buf); err != nil {
					return
				}
			}
		}()
		a.SetWriteDeadline(time.Now().Add(4 * time.Second))
		a.Write(data) // returns once the host has read it all, or has closed
		a.Close()
		select {
		case err := <-done:
			if err == nil {
				t.Fatalf("bytes from a stranger opened a session: %x", data)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("Accept did not return")
		}
	})
}

// Audit (fail closed): frames a paired phone (or a host, to the phone) sends after the handshake.
// A frame the multiplexer does not know must end the session with an error, never be skipped, and
// never panic.
func FuzzAuditFrames(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, frameOpen, 0, 0}, false)
	f.Add([]byte{0, 0, 0, 1, frameData, 0, 1, 'x'}, false)
	f.Add([]byte{0, 0, 0, 0, frameRekey, 0, 0}, true)
	f.Add([]byte{0, 0, 0, 0, frameData, 0, 3, '{', '}', '\n'}, true)
	f.Add([]byte{0, 0, 0, 3, 9, 0, 0}, false)
	f.Add([]byte{0, 0, 0, 1, frameWindow, 0, 4, 0xff, 0xff, 0xff, 0xff}, true)
	f.Fuzz(func(t *testing.T, data []byte, phone bool) {
		var k [32]byte
		rand.Read(k[:])
		cs := func() *noise.CipherState { return noise.UnsafeNewCipherState(suite, k, 0) }
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		s := newSession(a, phone, cs(), cs(), [32]byte{}, Timing{}.withDefaults())
		// One frame, then the same bytes cut into several frames, as a peer could send them.
		for len(data) > 0 {
			n := min(len(data), 1+int(data[0])%64)
			frame := data[:n]
			data = data[n:]
			err := s.handleFrame(frame)
			_, typ, _, perr := parseFrame(frame)
			if err == nil && perr == nil && typ > frameRekey {
				t.Fatalf("frame type %d was accepted: %x", typ, frame)
			}
			if err != nil {
				return
			}
		}
		// Control lines: any bytes on stream 0.
		_ = s.ctrl.feed(data)
	})
}
