package connectsecure

// Tests added after the security review of the first version (review-04.md).

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/flynn/noise"
)

// Review 1: the pipe is cut mid-stream. A stream that never got a close frame
// must not look finished.
func TestCutPipeIsNotEOF(t *testing.T) {
	k := newKeys(t)
	a, b := pipe2(t)
	phone, comp := connectedOver(t, a, b, k.client(false), k.server(nil))
	c, _ := phone.Open()
	s, _ := comp.AcceptStream()
	c.Write([]byte("partial-upload"))
	time.Sleep(50 * time.Millisecond)
	a.Close() // a relay drops the connection; no close frame was sent

	got, err := io.ReadAll(s)
	if err == nil || errors.Is(err, io.EOF) || !errors.Is(err, ErrConnLost) || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("ReadAll after a cut: %q, err %v; want ErrConnLost, not io.EOF", got, err)
	}
	if string(got) != "partial-upload" {
		t.Fatalf("data before the cut: %q", got)
	}
	if _, err := comp.Control().Recv(); !errors.Is(err, ErrConnLost) || errors.Is(err, io.EOF) {
		t.Fatalf("Control.Recv after a cut: %v", err)
	}

	// The other side of the instrument: a real close is a clean EOF.
	phone2, comp2 := connected(t, k.client(false), k.server(nil))
	c2, _ := phone2.Open()
	s2, _ := comp2.AcceptStream()
	c2.Write([]byte("whole-upload"))
	c2.Close()
	if got, err := io.ReadAll(s2); err != nil || string(got) != "whole-upload" {
		t.Fatalf("real close: %q %v", got, err)
	}
}

// Review 2: the control stream has a byte budget: one line at most
// maxControlLine, lines nobody has read at most maxControlBytes in total.
func TestControlLineTooLong(t *testing.T) {
	k := newKeys(t)
	phone, comp := connected(t, k.client(false), k.server(nil))
	if err := phone.Control().Send(map[string]string{"type": "x", "v": strings.Repeat("a", maxControlLine)}); err == nil {
		t.Fatal("Send took a line over the limit")
	}
	// Bypass Send: one frame of maxControlLine bytes with no newline, then one more byte.
	line := []byte(strings.Repeat("a", maxControlLine))
	for len(line) > 0 {
		n := min(len(line), maxFramePayload)
		phone.writeFrame(0, frameData, line[:n])
		line = line[n:]
	}
	time.Sleep(50 * time.Millisecond)
	if !stillOpen(comp) {
		t.Fatalf("closed at exactly the limit: %v", comp.Err())
	}
	phone.writeFrame(0, frameData, []byte("a"))
	waitDone(t, comp, 2*time.Second, "the host")
	if !errors.Is(comp.Err(), ErrProtocol) {
		t.Fatalf("closed with %v", comp.Err())
	}
}

func TestControlQueueBytes(t *testing.T) {
	k := newKeys(t)
	phone, comp := connected(t, k.client(false), k.server(nil))
	line := strings.Repeat("b", 3900) // each line ~3.9 KiB; nobody calls Recv on the host
	for i := 0; i < 16; i++ {         // ~62 KiB: under the budget
		if err := phone.Control().Send(map[string]string{"type": "x", "v": line}); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if !stillOpen(comp) {
		t.Fatalf("closed at 16 lines (~62 KiB): %v", comp.Err())
	}
	phone.Control().Send(map[string]string{"type": "x", "v": line})
	waitDone(t, comp, 2*time.Second, "the host")
	if !errors.Is(comp.Err(), ErrProtocol) {
		t.Fatalf("closed with %v", comp.Err())
	}
}

// 64 control lines over 4 KiB, or 64 just under it that nobody reads: the session
// closes and the host's heap grows by less than 1 MiB.
func TestControlFloodMemory(t *testing.T) {
	for _, size := range []int{4100, 4000} {
		k := newKeys(t)
		phone, comp := connected(t, k.client(false), k.server(nil))
		line := []byte(`{"type":"x","v":"` + strings.Repeat("d", size-20) + `"}` + "\n")
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		for i := 0; i < 64; i++ {
			if phone.writeFrame(0, frameData, line) != nil {
				break // the host already closed
			}
		}
		waitDone(t, comp, 2*time.Second, "the host")
		runtime.GC()
		runtime.ReadMemStats(&after)
		if grew := int64(after.HeapAlloc) - int64(before.HeapAlloc); grew > 1<<20 {
			t.Fatalf("%d-byte lines: heap grew %d bytes", size, grew)
		}
		if !errors.Is(comp.Err(), ErrProtocol) {
			t.Fatalf("%d-byte lines: closed with %v", size, comp.Err())
		}
	}
}

// Reading a line gives its bytes back to the budget.
func TestControlQueueDrains(t *testing.T) {
	k := newKeys(t)
	phone, comp := connected(t, k.client(false), k.server(nil))
	line := strings.Repeat("c", 3900)
	for i := 0; i < 40; i++ { // 40 x 3.9 KiB, far over the budget, but read as it comes
		if err := phone.Control().Send(map[string]string{"type": "x", "v": line}); err != nil {
			t.Fatal(err)
		}
		if _, err := comp.Control().Recv(); err != nil {
			t.Fatal(err)
		}
	}
	if !stillOpen(comp) {
		t.Fatalf("closed though every line was read: %v", comp.Err())
	}
}

// countingConn counts what the host reads from the pipe.
type countingConn struct {
	net.Conn
	n atomic.Int64
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.n.Add(int64(n))
	return n, err
}

// phoneUpToHello is a phone that does the handshake, sends its hello, and does
// not wait for an answer. It returns the session (not started) and how many
// bytes it had written up to and including the hello record.
func phoneUpToHello(t *testing.T, conn net.Conn, cc ClientConfig) (*Session, int) {
	t.Helper()
	rec := &recorder{Conn: conn}
	hs, err := noise.NewHandshakeState(handshakeConfig(false, true, cc.Static, cc.Server[:], []byte(prologue), nil))
	if err != nil {
		t.Fatal(err)
	}
	m0, _, _, _ := hs.WriteMessage(nil, []byte(fmt.Sprintf(`{"proto":%d}`, Proto)))
	if _, err := rec.Write(appendFrame([]byte("TP2C"), m0)); err != nil {
		t.Fatal(err)
	}
	m1, err := readHandshake(rec)
	if err != nil {
		t.Fatal(err)
	}
	_, send, recv, err := hs.ReadMessage(nil, m1)
	if err != nil {
		t.Fatal(err)
	}
	s := newSession(rec, true, send, recv, cc.Server, Timing{}.withDefaults())
	if err := s.ctrl.Send(helloMsg{Type: "hello", Proto: Proto}); err != nil {
		t.Fatal(err)
	}
	return s, len(rec.bytes())
}

// Review 3: a key nobody paired. Admit says no; whatever the phone sends right
// after its hello (an open and 200 KB) is never read, and the phone gets bye unpaired.
func TestNotAdmittedReadsNothingMore(t *testing.T) {
	k := newKeys(t)
	stranger := newKeys(t)
	cc := stranger.client(false)
	cc.Server = k.comp.Public
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	acc := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); acc <- c }()
	pc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	cconn := &countingConn{Conn: <-acc}

	sc := k.server(nil)
	sc.Admit = func(Peer) (Admission, error) {
		time.Sleep(200 * time.Millisecond) // a slow device lookup: the phone's extra data is waiting by now
		return Admission{Bye: "unpaired"}, nil
	}
	admitted := make(chan error, 1)
	go func() { _, err := Accept(cconn, sc); admitted <- err }()

	phone, wrote := phoneUpToHello(t, pc, cc)
	go func() { // straight after the hello, without waiting for an answer
		phone.writeFrame(1, frameOpen, nil)
		chunk := make([]byte, maxFramePayload)
		for sent := 0; sent < 200<<10; sent += len(chunk) {
			if phone.writeFrame(1, frameData, chunk) != nil {
				return
			}
		}
	}()
	select {
	case err := <-admitted:
		if !errors.Is(err, ErrNotAdmitted) {
			t.Fatalf("Accept: %v, want ErrNotAdmitted", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Accept did not return")
	}
	if got := cconn.n.Load(); got != int64(wrote) {
		t.Fatalf("the host read %d bytes; the phone's handshake and hello were %d", got, wrote)
	}
	pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	m, err := phone.readFirst()
	if err != nil || m["type"] != "bye" || m["code"] != "unpaired" {
		t.Fatalf("phone got %v %v, want bye unpaired", m, err)
	}
}

// noDeadline is a conn whose deadlines do nothing, like some WebSocket adapters.
type noDeadline struct{ net.Conn }

func (noDeadline) SetDeadline(time.Time) error      { return nil }
func (noDeadline) SetReadDeadline(time.Time) error  { return nil }
func (noDeadline) SetWriteDeadline(time.Time) error { return nil }

// Review 4: the handshake time limit does not depend on the conn's deadlines.
func TestHandshakeLimitWithoutDeadlines(t *testing.T) {
	k := newKeys(t)
	a, b := pipe2(t)
	sc := k.server(nil)
	sc.Timing.First = 100 * time.Millisecond
	done := make(chan error, 1)
	go func() { _, err := Accept(noDeadline{b}, sc); done <- err }()
	a.Write([]byte("TP2C"))
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("no error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept still waiting after 2 s with Handshake=100ms on a conn without deadlines")
	}

	// Same for the phone: the host never answers.
	a2, b2 := pipe2(t)
	go io.Copy(io.Discard, b2)
	cc := k.client(false)
	cc.Timing.Handshake = 100 * time.Millisecond
	dd := make(chan error, 1)
	go func() { _, err := Dial(noDeadline{a2}, cc); dd <- err }()
	select {
	case err := <-dd:
		if err == nil {
			t.Fatal("no error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Dial still waiting after 2 s on a conn without deadlines")
	}
}

// Review 4: at most Limit handshakes at once; one more is closed at once.
func TestHandshakeConcurrencyLimit(t *testing.T) {
	k := newKeys(t)
	sc := k.server(nil)
	sc.Limit = NewLimiter(2)
	sc.Timing.Handshake = 300 * time.Millisecond
	for i := 0; i < 2; i++ { // two that only send a preamble and hold their slot
		a, b := pipe2(t)
		go Accept(b, sc)
		a.Write([]byte("TP2C"))
	}
	a, b := pipe2(t)
	done := make(chan error, 1)
	start := time.Now()
	go func() { _, err := Accept(b, sc); done <- err }()
	go a.Write([]byte("TP2C"))
	select {
	case err := <-done:
		if !errors.Is(err, ErrTooManyHandshakes) {
			t.Fatalf("third handshake: %v, want ErrTooManyHandshakes", err)
		}
		if el := time.Since(start); el > 200*time.Millisecond {
			t.Fatalf("third handshake waited %v instead of being turned away", el)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("third handshake neither ran nor was turned away")
	}
	// Once the two time out, a real phone gets through.
	time.Sleep(400 * time.Millisecond)
	d, r := handshakePipe(t, k.client(false), sc)
	if d.err != nil || r.err != nil {
		t.Fatalf("after the slots freed: dial %v, accept %v", d.err, r.err)
	}
	d.s.Close()
	r.s.Close()
}

// Review 5: the phone keeps pinging but never reads. The host's writes stall;
// after Timing.Write the session closes instead of every writer waiting forever.
// Run twice: with a working write deadline, and on a conn whose deadlines do
// nothing (then only the timer catches it).
func TestWriteStallCloses(t *testing.T) {
	for _, nodl := range []bool{false, true} {
		k := newKeys(t)
		a, b, px := newProxy()
		if nodl {
			b = noDeadline{b}
		}
		cc, sc := k.client(false), k.server(nil)
		cc.Timing = Timing{Ping: 20 * time.Millisecond, Idle: time.Minute}
		sc.Timing = Timing{Ping: time.Minute, Idle: time.Minute, Write: 100 * time.Millisecond}
		phone, comp := connectedOver(t, a, b, cc, sc)
		phone.Open()
		s, _ := comp.AcceptStream()
		px.set(func(p *proxy) { p.stall = true })
		time.Sleep(20 * time.Millisecond)
		werr := make(chan error, 1)
		go func() { _, err := s.Write(make([]byte, 200<<10)); werr <- err }()
		waitDone(t, comp, 2*time.Second, "the host")
		if !errors.Is(comp.Err(), ErrWriteStalled) {
			t.Fatalf("no deadlines %v: closed with %v, want ErrWriteStalled", nodl, comp.Err())
		}
		select {
		case err := <-werr:
			if err == nil {
				t.Fatal("Write reported success")
			}
		case <-time.After(time.Second):
			t.Fatal("Write still stuck after the session closed")
		}
	}
}

// Session.Close does not close the application's streams for it: a stream the
// application closed ends with a clean EOF, then the host says bye stopping.
func TestCloseSendsCloseAndBye(t *testing.T) {
	k := newKeys(t)
	phone, comp := connected(t, k.client(false), k.server(nil))
	c, _ := phone.Open()
	s, _ := comp.AcceptStream()
	s.Write([]byte("last words"))
	s.Close()
	comp.Close()
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "last words" {
		t.Fatalf("phone stream: %q %v, want the data and a clean EOF", got, err)
	}
	m, err := phone.Control().Recv()
	if err != nil || m["type"] != "bye" || m["code"] != "stopping" {
		t.Fatalf("phone control: %v %v, want bye stopping", m, err)
	}
	waitDone(t, phone, 2*time.Second, "phone")
}

// The host is writing 4 MiB on a stream when it shuts down. The stream was not
// finished, so the phone must not see a clean EOF.
func TestCloseMidWriteIsConnLost(t *testing.T) {
	k := newKeys(t)
	phone, comp := connected(t, k.client(false), k.server(nil))
	c, _ := phone.Open()
	s, _ := comp.AcceptStream()
	go s.Write(make([]byte, 4<<20))
	got := make(chan error, 1)
	go func() { _, err := io.ReadAll(c); got <- err }()
	time.Sleep(50 * time.Millisecond)
	comp.Close()
	select {
	case err := <-got:
		if !errors.Is(err, ErrConnLost) || errors.Is(err, io.EOF) {
			t.Fatalf("phone ReadAll: %v, want ErrConnLost", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("phone ReadAll did not return")
	}
	m, err := phone.Control().Recv()
	if err != nil || m["type"] != "bye" || m["code"] != "stopping" {
		t.Fatalf("phone control: %v %v, want bye stopping", m, err)
	}
}

// Review 6: the host closes a stream while the phone is still writing to it.
// The phone's Write must finish instead of waiting for credit forever.
func TestWriteAfterPeerClosedStream(t *testing.T) {
	k := newKeys(t)
	phone, comp := connected(t, k.client(false), k.server(nil))
	c, _ := phone.Open()
	s, _ := comp.AcceptStream()
	s.Close()
	done := make(chan error, 1)
	go func() { _, err := c.Write(make([]byte, 1<<20)); done <- err }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("phone Write still waiting for window 2 s after the host closed the stream")
	}
	if !stillOpen(phone) || !stillOpen(comp) {
		t.Fatal("session closed")
	}
}

// relayRefused stands in for a relay Dialer reporting close code 4404/4408.
var errRelayRefused = errors.New("relay: no computer in this room (4404)")

type refusingConn struct{ net.Conn }

func (refusingConn) Read([]byte) (int, error) { return 0, errRelayRefused }

// Review 7: only a clean EOF right after the first message becomes
// ErrHandshakeClosed; a transport's own error comes through as itself.
func TestRelayCloseIsNotHandshakeClosed(t *testing.T) {
	k := newKeys(t)
	for _, pair := range []bool{false, true} {
		a, b := pipe2(t)
		go io.Copy(io.Discard, b)
		_, err := Dial(refusingConn{a}, k.client(pair))
		if errors.Is(err, ErrHandshakeClosed) {
			t.Fatalf("pair=%v: relay refusal turned into %v", pair, err)
		}
		if !errors.Is(err, errRelayRefused) {
			t.Fatalf("pair=%v: relay error lost: %v", pair, err)
		}
	}
}

// Review 8: the device name from the first message is cut to maxDeviceName
// bytes of valid UTF-8 with no control characters.
func TestDeviceNameCleaned(t *testing.T) {
	k := newKeys(t)
	cc := k.client(true)
	cc.Device = "Test\nPhone\r\x1b[2J\u202e\u0085 " + strings.Repeat("é", 490) + "\xff" // about 1000 bytes
	d, r := handshakePipe(t, cc, k.server(newOnceCodes(testCode).PSK))
	if d.err != nil || r.err != nil {
		t.Fatalf("dial %v, accept %v", d.err, r.err)
	}
	defer d.s.Close()
	defer r.s.Close()
	got := r.peer.Device
	if len(got) > maxDeviceName || !utf8.ValidString(got) {
		t.Fatalf("device %q: %d bytes, valid %v", got, len(got), utf8.ValidString(got))
	}
	for _, c := range got {
		if unicode.IsControl(c) || unicode.Is(unicode.Cf, c) {
			t.Fatalf("device %q keeps %U", got, c)
		}
	}
	if !strings.HasPrefix(got, "Test Phone") {
		t.Fatalf("device %q lost its readable part", got)
	}
}

// Review 6: each multiplexing check has a test that fails without it.
func TestStreamIDRules(t *testing.T) {
	k := newKeys(t)
	cases := []struct {
		name string
		send func(phone, comp *Session) // the frames that break a rule
		bad  func(phone, comp *Session) *Session
	}{
		{"even id", func(p, c *Session) { p.writeFrame(2, frameOpen, nil) }, companionSide},
		{"reused id", func(p, c *Session) { p.writeFrame(7, frameOpen, nil); p.writeFrame(7, frameOpen, nil) }, companionSide},
		{"smaller id", func(p, c *Session) { p.writeFrame(7, frameOpen, nil); p.writeFrame(5, frameOpen, nil) }, companionSide},
		{"open with payload", func(p, c *Session) { p.writeFrame(9, frameOpen, []byte{1}) }, companionSide},
		{"the host opens", func(p, c *Session) { c.writeFrame(1, frameOpen, nil) }, phoneSide},
		{"data on a stream never opened", func(p, c *Session) { p.writeFrame(11, frameData, []byte{1}) }, companionSide},
		{"data after close", func(p, c *Session) {
			p.writeFrame(13, frameOpen, nil)
			p.writeFrame(13, frameClose, nil)
			p.writeFrame(13, frameData, []byte{1})
		}, companionSide},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			phone, comp := connected(t, k.client(false), k.server(nil))
			tc.send(phone, comp)
			s := tc.bad(phone, comp)
			waitDone(t, s, 2*time.Second, tc.name)
			if !errors.Is(s.Err(), ErrProtocol) {
				t.Fatalf("closed with %v, want ErrProtocol", s.Err())
			}
		})
	}
	// The instrument's other side: legal raw opens with gaps keep the session up.
	phone, comp := connected(t, k.client(false), k.server(nil))
	phone.writeFrame(7, frameOpen, nil)
	phone.writeFrame(9, frameOpen, nil)
	time.Sleep(50 * time.Millisecond)
	if !stillOpen(comp) {
		t.Fatalf("closed on legal opens: %v", comp.Err())
	}
}

func companionSide(_, c *Session) *Session { return c }
func phoneSide(p, _ *Session) *Session     { return p }

func TestStreamCountLimit(t *testing.T) {
	k := newKeys(t)
	phone, comp := connected(t, k.client(false), k.server(nil))
	id := uint32(1)
	for i := 0; i < 2*maxStreams; i++ {
		phone.writeFrame(id, frameOpen, nil)
		id += 2
	}
	time.Sleep(50 * time.Millisecond)
	if !stillOpen(comp) {
		t.Fatalf("closed at %d streams: %v", 2*maxStreams, comp.Err())
	}
	phone.writeFrame(id, frameOpen, nil)
	waitDone(t, comp, 2*time.Second, "the host")
	if !errors.Is(comp.Err(), ErrProtocol) {
		t.Fatalf("closed with %v", comp.Err())
	}
}

func TestWindowGrantLimit(t *testing.T) {
	k := newKeys(t)
	phone, comp := connected(t, k.client(false), k.server(nil))
	c, _ := phone.Open()
	comp.AcceptStream()
	id := c.(*stream).id
	inc := func(n uint32) {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], n)
		comp.writeFrame(id, frameWindow, b[:])
	}
	inc(64 << 10)
	time.Sleep(50 * time.Millisecond)
	if !stillOpen(phone) {
		t.Fatalf("closed on a normal grant: %v", phone.Err())
	}
	inc(maxWindow) // now over maxWindow in total
	waitDone(t, phone, 2*time.Second, "phone")
	if !errors.Is(phone.Err(), ErrProtocol) {
		t.Fatalf("closed with %v", phone.Err())
	}
}

// The relay swaps the preamble's mode byte. The mode decides the Noise protocol
// name, which is hashed into the handshake, so neither side completes.
func TestModeFlip(t *testing.T) {
	for _, pair := range []bool{false, true} {
		k := newKeys(t)
		pa, pp := pipe2(t)
		cp, cb := pipe2(t)
		go func() {
			pre := make([]byte, 4)
			if _, err := io.ReadFull(pp, pre); err != nil {
				return
			}
			pre[3] = map[byte]byte{'P': 'C', 'C': 'P'}[pre[3]]
			cp.Write(pre)
			go func() { io.Copy(cp, pp); cp.Close() }()
			io.Copy(pp, cp)
			pp.Close()
		}()
		// This the host would hand out the right psk for any cid.
		sc := k.server(func(string) ([32]byte, bool) { return PSKFor(testCode), true })
		d, r := handshake(t, pa, cb, k.client(pair), sc)
		if d.err == nil || r.err == nil || r.s != nil {
			t.Fatalf("pair=%v: flipped mode went through: dial %v, accept %v", pair, d.err, r.err)
		}
	}
}

// The relay sends one transport record twice: the copy does not decrypt.
func TestRecordReplay(t *testing.T) {
	k := newKeys(t)
	a, b, px := newProxy()
	phone, comp := connectedOver(t, a, b, k.client(false), k.server(nil))
	c, _ := phone.Open()
	s, _ := comp.AcceptStream()
	px.set(func(p *proxy) { p.dupNext = true })
	c.Write([]byte("once"))
	waitDone(t, comp, 2*time.Second, "the host")
	if !errors.Is(comp.Err(), ErrBadRecord) {
		t.Fatalf("closed with %v, want ErrBadRecord", comp.Err())
	}
	got, _ := io.ReadAll(s)
	if string(got) == "onceonce" {
		t.Fatal("the replayed record came out of the stream")
	}
}

// A the host whose Admit was never set turns phones away with bye busy, not bye
// unpaired: a missing Admit is the host's mistake and must not make phones drop
// their pairing.
func TestNilAdmitIsBusy(t *testing.T) {
	k := newKeys(t)
	sc := k.server(nil)
	sc.Admit = nil
	d, r := handshakePipe(t, k.client(false), sc)
	if !errors.Is(d.err, ErrBusy) || errors.Is(d.err, ErrUnpaired) {
		t.Fatalf("dial: %v, want ErrBusy and not ErrUnpaired", d.err)
	}
	if r.s != nil || !errors.Is(r.err, ErrNotAdmitted) {
		t.Fatalf("accept: session %v, err %v", r.s != nil, r.err)
	}
}

// failNthWrite fails the nth Write (1-based) and every one after.
type failNthWrite struct {
	net.Conn
	n, seen atomic.Int32
}

func (c *failNthWrite) Write(p []byte) (int, error) {
	if c.seen.Add(1) >= c.n.Load() {
		return 0, errors.New("test: write failed")
	}
	return c.Conn.Write(p)
}

// countUndo is an Admit that redeems (OK, paired) and counts Undo calls.
func countUndo(delay time.Duration, undos *atomic.Int32) func(Peer) (Admission, error) {
	return func(p Peer) (Admission, error) {
		time.Sleep(delay)
		a, err := admitAll(p)
		a.Undo = func() { undos.Add(1) }
		return a, err
	}
}

// Admit takes longer than the handshake may: the code was redeemed, the phone
// got nothing, so Undo runs once.
func TestUndoWhenAdmitTooSlow(t *testing.T) {
	k := newKeys(t)
	var undos atomic.Int32
	sc := k.server(newOnceCodes(testCode).PSK)
	sc.Timing.Handshake = 300 * time.Millisecond
	sc.Admit = countUndo(400*time.Millisecond, &undos)
	d, r := handshakePipe(t, k.client(true), sc)
	if r.err == nil || r.s != nil || d.err == nil {
		t.Fatalf("handshake went through: dial %v, accept %v", d.err, r.err)
	}
	if n := undos.Load(); n != 1 {
		t.Fatalf("Undo ran %d times, want 1", n)
	}
}

// Writing paired fails (the host writes msg 1, hello, paired: the third write).
func TestUndoWhenPairedWriteFails(t *testing.T) {
	k := newKeys(t)
	var undos atomic.Int32
	sc := k.server(newOnceCodes(testCode).PSK)
	sc.Admit = countUndo(0, &undos)
	a, b := pipe2(t)
	fb := &failNthWrite{Conn: b}
	fb.n.Store(3)
	d, r := handshake(t, a, fb, k.client(true), sc)
	if r.err == nil || r.s != nil {
		t.Fatalf("accept went through: %v", r.err)
	}
	if n := undos.Load(); n != 1 {
		t.Fatalf("Undo ran %d times, want 1 (dial %v, accept %v)", n, d.err, r.err)
	}
}

func TestNoUndoOnSuccess(t *testing.T) {
	k := newKeys(t)
	var undos atomic.Int32
	sc := k.server(newOnceCodes(testCode).PSK)
	sc.Admit = countUndo(0, &undos)
	d, r := handshakePipe(t, k.client(true), sc)
	if d.err != nil || r.err != nil {
		t.Fatalf("dial %v, accept %v", d.err, r.err)
	}
	d.s.Close()
	r.s.Close()
	if n := undos.Load(); n != 0 {
		t.Fatalf("Undo ran %d times after a good pairing", n)
	}
}

// Admit forgot to set OK and Bye: that is the host's mistake too, so busy.
// Only an explicit Bye "unpaired" may make the phone drop its pairing.
func TestZeroAdmissionIsBusy(t *testing.T) {
	k := newKeys(t)
	sc := k.server(nil)
	sc.Admit = func(Peer) (Admission, error) { return Admission{}, nil }
	d, r := handshakePipe(t, k.client(false), sc)
	if !errors.Is(d.err, ErrBusy) || errors.Is(d.err, ErrUnpaired) {
		t.Fatalf("dial: %v, want ErrBusy and not ErrUnpaired", d.err)
	}
	if r.s != nil || !errors.Is(r.err, ErrNotAdmitted) {
		t.Fatalf("accept: session %v, err %v", r.s != nil, r.err)
	}
	sc.Admit = func(Peer) (Admission, error) { return Admission{Bye: "unpaired"}, nil }
	d, _ = handshakePipe(t, k.client(false), sc)
	if !errors.Is(d.err, ErrUnpaired) {
		t.Fatalf("explicit unpaired: dial %v, want ErrUnpaired", d.err)
	}
}

// Admit redeemed the code, then failed and returned an error with its Undo:
// Accept takes the redeem back before saying busy.
func TestUndoWhenAdmitErrors(t *testing.T) {
	k := newKeys(t)
	var undos atomic.Int32
	sc := k.server(newOnceCodes(testCode).PSK)
	sc.Admit = func(p Peer) (Admission, error) {
		a, _ := admitAll(p)
		a.Undo = func() { undos.Add(1) }
		return a, errors.New("test: store failed after redeem")
	}
	d, r := handshakePipe(t, k.client(true), sc)
	if !errors.Is(d.err, ErrBusy) || r.s != nil {
		t.Fatalf("dial %v, accept session %v", d.err, r.s != nil)
	}
	if n := undos.Load(); n != 1 {
		t.Fatalf("Undo ran %d times, want 1", n)
	}
}

// Writing hello fails (the host writes msg 1, then hello: the second write).
func TestUndoWhenHelloWriteFails(t *testing.T) {
	k := newKeys(t)
	var undos atomic.Int32
	sc := k.server(newOnceCodes(testCode).PSK)
	sc.Admit = countUndo(0, &undos)
	a, b := pipe2(t)
	fb := &failNthWrite{Conn: b}
	fb.n.Store(2)
	d, r := handshake(t, a, fb, k.client(true), sc)
	if r.err == nil || r.s != nil {
		t.Fatalf("accept went through: %v", r.err)
	}
	if n := undos.Load(); n != 1 {
		t.Fatalf("Undo ran %d times, want 1 (dial %v, accept %v)", n, d.err, r.err)
	}
}
