package connectsecure

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// 5. One byte of one record changes on the way: the receiver closes the whole
// connection and the changed data never comes out of a stream.
func TestTamperedRecord(t *testing.T) {
	k := newKeys(t)
	a, b, px := newProxy()
	phone, comp := connectedOver(t, a, b, k.client(false), k.server(nil))

	c, err := phone.Open()
	if err != nil {
		t.Fatal(err)
	}
	sc, err := comp.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(sc, got); err != nil || string(got) != "first" {
		t.Fatalf("before tampering: %q %v", got, err)
	}

	px.set(func(p *proxy) { p.flipNext = true })
	c.Write([]byte("second"))
	<-px.flipped

	waitDone(t, comp, 2*time.Second, "the host")
	if !errors.Is(comp.Err(), ErrBadRecord) {
		t.Fatalf("the host closed with %v, want ErrBadRecord", comp.Err())
	}
	waitDone(t, phone, 2*time.Second, "phone")
	n, err := sc.Read(got)
	if err == nil || n > 0 {
		t.Fatalf("stream gave %q after the bad record", got[:n])
	}
}

// 7. One stream nobody reads does not stop another stream.
func TestStalledStreamDoesNotBlockOthers(t *testing.T) {
	k := newKeys(t)
	phone, comp := connected(t, k.client(false), k.server(nil))

	ca, err := phone.Open()
	if err != nil {
		t.Fatal(err)
	}
	cb, err := phone.Open()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := comp.AcceptStream(); err != nil { // stream A: the host never reads it
		t.Fatal(err)
	}
	sb, err := comp.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	go ca.Write(make([]byte, 1<<20)) // blocks once A's window is used up
	time.Sleep(50 * time.Millisecond)

	go func() { // the host echoes stream B
		b := make([]byte, 1024)
		if _, err := io.ReadFull(sb, b); err == nil {
			sb.Write(b)
		}
	}()
	done := make(chan error, 1)
	go func() {
		msg := make([]byte, 1024)
		rand.Read(msg)
		if _, err := cb.Write(msg); err != nil {
			done <- err
			return
		}
		back := make([]byte, 1024)
		if _, err := io.ReadFull(cb, back); err != nil {
			done <- err
			return
		}
		if !bytes.Equal(msg, back) {
			done <- errors.New("echo differs")
			return
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("1 KiB round trip on stream B took more than 1 s while stream A was not read")
	}
}

// 8. A sender that ignores the window gets the whole connection closed. Exactly
// the window is fine; one byte more is not.
func TestWindowOverrun(t *testing.T) {
	k := newKeys(t)
	phone, comp := connected(t, k.client(false), k.server(nil))
	c, err := phone.Open()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := comp.AcceptStream(); err != nil {
		t.Fatal(err)
	}
	id := c.(*stream).id
	sent := 0
	for sent < initialWindow { // bypass Write: it would stop at the window
		n := min(maxFramePayload, initialWindow-sent)
		if err := phone.writeFrame(id, frameData, make([]byte, n)); err != nil {
			t.Fatal(err)
		}
		sent += n
	}
	time.Sleep(100 * time.Millisecond)
	if !stillOpen(comp) {
		t.Fatalf("the host closed after exactly one window: %v", comp.Err())
	}
	if err := phone.writeFrame(id, frameData, []byte{1}); err != nil {
		t.Fatal(err)
	}
	waitDone(t, comp, 2*time.Second, "the host")
	if !errors.Is(comp.Err(), ErrFlowControl) {
		t.Fatalf("the host closed with %v, want ErrFlowControl", comp.Err())
	}
}

// 9. The other side goes silent: after Idle the session closes.
func TestPingTimeout(t *testing.T) {
	k := newKeys(t)
	a, b, px := newProxy()
	cc := k.client(false)
	cc.Timing = Timing{Ping: 50 * time.Millisecond, Idle: 100 * time.Millisecond}
	phone, _ := connectedOver(t, a, b, cc, k.server(nil))

	px.set(func(p *proxy) { p.freeze = true })
	start := time.Now()
	waitDone(t, phone, time.Second, "phone")
	if el := time.Since(start); el < 90*time.Millisecond {
		t.Fatalf("closed after %v, before Idle", el)
	}
	if !errors.Is(phone.Err(), ErrIdle) {
		t.Fatalf("closed with %v, want ErrIdle", phone.Err())
	}
}

// The other half of 9: when both sides answer, pings keep the session open, and
// ping/pong never come out of Control.Recv.
func TestPingKeepsAlive(t *testing.T) {
	k := newKeys(t)
	fast := Timing{Ping: 50 * time.Millisecond, Idle: 100 * time.Millisecond}
	cc, sc := k.client(false), k.server(nil)
	cc.Timing, sc.Timing = fast, fast
	phone, comp := connected(t, cc, sc)
	time.Sleep(500 * time.Millisecond)
	if !stillOpen(phone) || !stillOpen(comp) {
		t.Fatalf("closed while both answer: phone %v, the host %v", phone.Err(), comp.Err())
	}
	comp.Control().Send(map[string]any{"type": "routes"})
	m, err := phone.Control().Recv()
	if err != nil || m["type"] != "routes" {
		t.Fatalf("Recv gave %v %v", m, err)
	}
}

// 11. 32 MiB each way on one stream, at the same time, over local TCP.
func TestLargeTransfer(t *testing.T) {
	k := newKeys(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	acc := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); acc <- c }()
	a, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b := <-acc
	phone, comp := connectedOver(t, a, b, k.client(false), k.server(nil))

	const size = 32 << 20
	up, down := make([]byte, size), make([]byte, size)
	rand.Read(up)
	rand.Read(down)

	c, err := phone.Open()
	if err != nil {
		t.Fatal(err)
	}
	s, err := comp.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	sum := func(r io.Reader, out *[32]byte, errp *error) {
		defer wg.Done()
		h := sha256.New()
		n, err := io.CopyN(h, r, size)
		if err != nil {
			*errp = fmt.Errorf("after %d bytes: %w", n, err)
		}
		copy(out[:], h.Sum(nil))
	}
	var gotUp, gotDown [32]byte
	var errUp, errDown, errW1, errW2 error
	wg.Add(4)
	go sum(s, &gotUp, &errUp)
	go sum(c, &gotDown, &errDown)
	go func() { defer wg.Done(); _, errW1 = c.Write(up) }()
	go func() { defer wg.Done(); _, errW2 = s.Write(down) }()
	wg.Wait()
	for _, e := range []error{errUp, errDown, errW1, errW2} {
		if e != nil {
			t.Fatal(e)
		}
	}
	if gotUp != sha256.Sum256(up) || gotDown != sha256.Sum256(down) {
		t.Fatal("bytes differ")
	}
}

// http.Server and http.Client over streams: http.Server sets deadlines on every conn.
func TestHTTPOverStreams(t *testing.T) {
	k := newKeys(t)
	phone, comp := connected(t, k.client(false), k.server(nil))
	srv := &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			fmt.Fprintf(w, "%s %s %d", r.Method, r.URL.Path, len(body))
		}),
	}
	go srv.Serve(streamListener{comp})
	defer srv.Close()
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) { return phone.Open() },
	}}
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := strings.Repeat("x", i*10000)
			resp, err := client.Post(fmt.Sprintf("http://companion/api/n%d", i), "text/plain", strings.NewReader(body))
			if err != nil {
				errs <- err
				return
			}
			defer resp.Body.Close()
			got, _ := io.ReadAll(resp.Body)
			if want := fmt.Sprintf("POST /api/n%d %d", i, len(body)); string(got) != want {
				errs <- fmt.Errorf("got %q want %q", got, want)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

type streamListener struct{ s *Session }

func (l streamListener) Accept() (net.Conn, error) { return l.s.AcceptStream() }
func (l streamListener) Close() error              { return l.s.Close() } // unblocks Accept so Serve returns
func (l streamListener) Addr() net.Addr            { return l.s.conn.LocalAddr() }

func TestStreamDeadline(t *testing.T) {
	k := newKeys(t)
	phone, comp := connected(t, k.client(false), k.server(nil))
	c, _ := phone.Open()
	s, _ := comp.AcceptStream()

	s.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	start := time.Now()
	_, err := s.Read(make([]byte, 1))
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("Read error %v is not a timeout", err)
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("deadline fired after %v", el)
	}
	s.SetReadDeadline(time.Time{})
	c.Write([]byte("z"))
	b := make([]byte, 1)
	if _, err := io.ReadFull(s, b); err != nil || b[0] != 'z' {
		t.Fatalf("after clearing the deadline: %q %v", b, err)
	}

	// A Write stuck on a full window gives up at its deadline.
	c.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	n, err := c.Write(make([]byte, 2*initialWindow))
	if !errors.As(err, &ne) || !ne.Timeout() || n != initialWindow-1 { // one byte ("z") already used the window
		t.Fatalf("Write past the window: n=%d err=%v", n, err)
	}
}

func TestCloseStream(t *testing.T) {
	k := newKeys(t)
	phone, comp := connected(t, k.client(false), k.server(nil))
	c, _ := phone.Open()
	s, _ := comp.AcceptStream()
	c.Write([]byte("bye"))
	c.Close()
	got, err := io.ReadAll(s)
	if err != nil || string(got) != "bye" {
		t.Fatalf("ReadAll %q %v", got, err)
	}
	if _, err := c.Write([]byte("x")); err == nil {
		t.Fatal("Write after Close worked")
	}
	s.Close()
	// Both sides closed: the stream is gone from both tables.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if phone.streamCount() == 0 && comp.streamCount() == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if phone.streamCount() != 0 || comp.streamCount() != 0 {
		t.Fatalf("streams left: phone %d, the host %d", phone.streamCount(), comp.streamCount())
	}
	if _, err := comp.Open(); err == nil {
		t.Fatal("the host opened a stream; only the phone opens")
	}
}

func TestSessionCloseWakesEveryone(t *testing.T) {
	k := newKeys(t)
	phone, comp := connected(t, k.client(false), k.server(nil))
	c, _ := phone.Open()
	s, _ := comp.AcceptStream()
	errc := make(chan error, 3)
	go func() { _, err := s.Read(make([]byte, 1)); errc <- err }()
	go func() { _, err := comp.AcceptStream(); errc <- err }()
	go func() { _, err := comp.Control().Recv(); errc <- err }()
	time.Sleep(20 * time.Millisecond)
	comp.Close()
	for i := 0; i < 3; i++ {
		select {
		case err := <-errc:
			if err == nil {
				t.Fatal("a waiter got no error")
			}
		case <-time.After(time.Second):
			t.Fatal("a waiter stayed blocked after Close")
		}
	}
	waitDone(t, phone, time.Second, "phone")
	if _, err := c.Write([]byte("x")); err == nil {
		t.Fatal("phone Write worked after the session closed")
	}
}

// A request-response client half-closes: the host reads EOF, answers, and the phone reads the answer.
func TestCloseWriteKeepsReading(t *testing.T) {
	k := newKeys(t)
	phone, comp := connected(t, k.client(false), k.server(nil))
	c, _ := phone.Open()
	s, _ := comp.AcceptStream()
	c.Write([]byte("question"))
	if err := c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("x")); err == nil {
		t.Fatal("Write after CloseWrite worked")
	}
	got, err := io.ReadAll(s)
	if err != nil || string(got) != "question" {
		t.Fatalf("host read %q %v", got, err)
	}
	s.Write([]byte("answer"))
	s.Close()
	got, err = io.ReadAll(c)
	if err != nil || string(got) != "answer" {
		t.Fatalf("phone read %q %v", got, err)
	}
	c.Close()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && (phone.streamCount() != 0 || comp.streamCount() != 0) {
		time.Sleep(5 * time.Millisecond)
	}
	if phone.streamCount() != 0 || comp.streamCount() != 0 {
		t.Fatalf("streams left: phone %d, the host %d", phone.streamCount(), comp.streamCount())
	}
}

// Rekeying under load: both sides write at once and rekey every 8 records, many times, while the
// other side is mid-stream. Every byte comes out unchanged, in order, and the host's receive key
// at the end is not the one the session started with.
func TestRekeyKeepsStreamsIntact(t *testing.T) {
	setRekey(t, 8, time.Hour, 64)
	k := newKeys(t)
	phone, comp := connected(t, k.client(false), k.server(nil))
	first := comp.recv.UnsafeKey() // the reader only changes the nonce until the first rekey frame

	up, down := make([]byte, 512<<10), make([]byte, 512<<10)
	rand.Read(up)
	rand.Read(down)
	ps, err := phone.Open()
	if err != nil {
		t.Fatal(err)
	}
	cs, err := comp.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	check := func(name string, c net.Conn, want []byte) {
		defer wg.Done()
		got := make([]byte, len(want))
		if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s: read %v, equal %v", name, err, bytes.Equal(got, want))
		}
	}
	wg.Add(4)
	go func() { defer wg.Done(); ps.Write(up) }()
	go func() { defer wg.Done(); cs.Write(down) }()
	go check("host", cs, up)
	go check("phone", ps, down)
	wg.Wait()
	phone.Close()
	waitDone(t, comp, 5*time.Second, "the host")
	if comp.recv.UnsafeKey() == first {
		t.Fatal("the host's receive key never changed")
	}
}

// The time limit rekeys a quiet session too: the next record after rekeyAfter goes out under a new key.
func TestRekeyAfterTime(t *testing.T) {
	setRekey(t, 1<<40, 20*time.Millisecond, 1<<40)
	k := newKeys(t)
	phone, comp := connected(t, k.client(false), k.server(nil))
	first := comp.recv.UnsafeKey()
	time.Sleep(30 * time.Millisecond)
	ps, err := phone.Open() // the first record after the limit
	if err != nil {
		t.Fatal(err)
	}
	cs, err := comp.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	ps.Write([]byte("after"))
	b := make([]byte, 5)
	if _, err := io.ReadFull(cs, b); err != nil || string(b) != "after" {
		t.Fatalf("read %q %v", b, err)
	}
	phone.Close()
	waitDone(t, comp, 5*time.Second, "the host")
	if comp.recv.UnsafeKey() == first {
		t.Fatal("no rekey after rekeyAfter")
	}
}

// A sender that never rekeys: the receiver ends the session once one key brought more than
// rejectRecords records.
func TestTooManyRecordsUnderOneKey(t *testing.T) {
	setRekey(t, 1<<40, time.Hour, 16)
	k := newKeys(t)
	phone, comp := connected(t, k.client(false), k.server(nil))
	ps, err := phone.Open()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40 && stillOpen(comp); i++ {
		ps.Write([]byte{byte(i)})
	}
	waitDone(t, comp, 5*time.Second, "the host")
	if !errors.Is(comp.Err(), ErrProtocol) {
		t.Fatalf("host ended with %v, want ErrProtocol", comp.Err())
	}
}

// A rekey frame must be empty; one with a payload is a protocol error, and the key stays.
func TestRekeyFrameWithPayload(t *testing.T) {
	k := newKeys(t)
	phone, comp := connected(t, k.client(false), k.server(nil))
	plain := []byte{0, 0, 0, 0, frameRekey, 0, 1, 'x'}
	phone.wmu.Lock()
	phone.writeRecord(plain)
	phone.wmu.Unlock()
	waitDone(t, comp, 5*time.Second, "the host")
	if !errors.Is(comp.Err(), ErrProtocol) {
		t.Fatalf("host ended with %v, want ErrProtocol", comp.Err())
	}
}

// What a phone sends and the app does not read is bounded for the whole session (L4): 65 streams
// of a full window each is more than maxUnread, so the host ends the session.
func TestUnreadBytesBounded(t *testing.T) {
	k := newKeys(t)
	phone, comp := connected(t, k.client(false), k.server(nil))
	chunk := make([]byte, initialWindow)
	for i := 0; i <= maxUnread/initialWindow && stillOpen(comp); i++ {
		st, err := phone.Open()
		if err != nil {
			break
		}
		go st.Write(chunk)
	}
	waitDone(t, comp, 10*time.Second, "the host")
	if !errors.Is(comp.Err(), ErrFlowControl) {
		t.Fatalf("host ended with %v, want ErrFlowControl", comp.Err())
	}
}

// A path that goes silent after a write: the phone pings once, hears nothing, and ends the session
// with ErrStalled after 2×Stall. A peer that answers keeps it open; the host never runs the check.
func TestStallEndsSilentSession(t *testing.T) {
	k := newKeys(t)
	cc := k.client(false)
	cc.Timing.Stall = 100 * time.Millisecond
	a, b := net.Pipe()
	gate := &gatedConn{Conn: a}
	phone, comp := connectedOver(t, gate, b, cc, k.server(nil))
	ps, err := phone.Open()
	if err != nil {
		t.Fatal(err)
	}
	cs, err := comp.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	go io.Copy(cs, cs)       // the host echoes
	for i := 0; i < 5; i++ { // answered writes, spread over several Stall periods
		ps.Write([]byte("x"))
		io.ReadFull(ps, make([]byte, 1))
		time.Sleep(60 * time.Millisecond)
	}
	if !stillOpen(phone) {
		t.Fatalf("an answering session ended: %v", phone.Err())
	}
	gate.silent.Store(true)
	start := time.Now()
	ps.Write([]byte("y"))
	waitDone(t, phone, 2*time.Second, "phone")
	if !errors.Is(phone.Err(), ErrStalled) || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("phone ended with %v after %v, want ErrStalled within about 200 ms", phone.Err(), time.Since(start))
	}
}

// gatedConn drops what it would read once silent is set, like a path gone without a reset.
type gatedConn struct {
	net.Conn
	silent atomic.Bool
}

func (c *gatedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	for err == nil && c.silent.Load() {
		n, err = c.Conn.Read(p)
	}
	return n, err
}
