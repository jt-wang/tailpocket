package connectsecure

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// 2. Both handshakes work; each side learns the other's static key; a pairing
// The host learns cid and device.
func TestHandshakeConnect(t *testing.T) {
	k := newKeys(t)
	d, r := handshakePipe(t, k.client(false), k.server(nil))
	if d.err != nil || r.err != nil {
		t.Fatalf("dial %v, accept %v", d.err, r.err)
	}
	defer d.s.Close()
	defer r.s.Close()
	if d.s.RemoteStatic() != k.comp.Public {
		t.Fatal("phone did not end up with the host's key")
	}
	if !bytes.Equal(r.peer.Static[:], k.phone.Public) || r.s.RemoteStatic() != r.peer.Static {
		t.Fatal("the host did not end up with the phone's key")
	}
	if r.peer.Pair || r.peer.CID != "" || r.peer.Device != "" {
		t.Fatalf("connect handshake reported a pairing: %+v", r.peer)
	}
	if r.s.Device() != testDeviceID {
		t.Fatalf("Device() = %q", r.s.Device())
	}
	roundTrip(t, d.s, r.s)
}

func TestHandshakePair(t *testing.T) {
	k := newKeys(t)
	d, r := handshakePipe(t, k.client(true), k.server(newOnceCodes(testCode).PSK))
	if d.err != nil || r.err != nil {
		t.Fatalf("dial %v, accept %v", d.err, r.err)
	}
	defer d.s.Close()
	defer r.s.Close()
	if d.s.RemoteStatic() != k.comp.Public || !bytes.Equal(r.peer.Static[:], k.phone.Public) {
		t.Fatal("static keys not exchanged")
	}
	if !r.peer.Pair || r.peer.CID != CIDFor(testCode) || r.peer.Device != testDevice {
		t.Fatalf("the host got peer %+v", r.peer)
	}
	m, err := d.s.Control().Recv() // paired went out before the host started reading
	if err != nil || m["type"] != "paired" || m["payload"] != testToken || m["phone"] != testDeviceID {
		t.Fatalf("first control message %v %v, want paired", m, err)
	}
	roundTrip(t, d.s, r.s)
}

// pipe2 returns both ends of a net.Pipe as one value for handshake().
func pipe2(t *testing.T) (net.Conn, net.Conn) {
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

// roundTrip checks a session carries a control message and a stream both ways.
func roundTrip(t *testing.T, phone, comp *Session) {
	t.Helper()
	if err := comp.Control().Send(map[string]any{"type": "routes", "via": []any{}}); err != nil {
		t.Fatal(err)
	}
	m, err := phone.Control().Recv()
	if err != nil || m["type"] != "routes" {
		t.Fatalf("control: %v %v", m, err)
	}
	errc := make(chan error, 1)
	go func() {
		c, err := comp.AcceptStream()
		if err != nil {
			errc <- err
			return
		}
		defer c.Close()
		b := make([]byte, 5)
		if _, err := io.ReadFull(c, b); err != nil {
			errc <- err
			return
		}
		_, err = c.Write(bytes.ToUpper(b))
		errc <- err
	}()
	c, err := phone.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 5)
	if _, err := io.ReadFull(c, b); err != nil || string(b) != "HELLO" {
		t.Fatalf("stream: %q %v", b, err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

// 3. The phone holds the wrong the host key: the handshake fails and the phone
// can tell why.
func TestHandshakeClosedWrongKey(t *testing.T) {
	for _, pair := range []bool{false, true} {
		name := map[bool]string{false: "connect", true: "pair"}[pair]
		t.Run(name, func(t *testing.T) {
			k := newKeys(t)
			other, _ := NewIdentity()
			cc := k.client(pair)
			cc.Server = other.Public
			d, r := handshakePipe(t, cc, k.server(newOnceCodes(testCode).PSK))
			if d.err == nil || r.err == nil {
				t.Fatalf("handshake went through: dial %v, accept %v", d.err, r.err)
			}
			if !errors.Is(d.err, ErrHandshakeClosed) {
				t.Fatalf("dial error %v is not ErrHandshakeClosed", d.err)
			}
			if !errors.Is(r.err, ErrHandshake) {
				t.Fatalf("accept error %v is not ErrHandshake", r.err)
			}
		})
	}
}

// 4. The cid is known but the psk differs: the handshake fails. The cid is
// unknown: the host closes.
func TestWrongPSK(t *testing.T) {
	k := newKeys(t)
	cc := k.client(true)
	cc.Pair.PSK = PSKFor("OTHER-C0DE")
	d, r := handshakePipe(t, cc, k.server(newOnceCodes(testCode).PSK))
	if d.err == nil || r.err == nil {
		t.Fatalf("handshake went through: dial %v, accept %v", d.err, r.err)
	}
	if !errors.Is(d.err, ErrHandshake) {
		t.Fatalf("dial error %v is not ErrHandshake", d.err)
	}
	if r.s != nil || !errors.Is(r.err, ErrNoHello) { // the host wrote msg 1, then the phone hung up
		t.Fatalf("accept: session %v, err %v", r.s != nil, r.err)
	}
}

func TestUnknownCID(t *testing.T) {
	k := newKeys(t)
	a, b := pipe2(t)
	d, r := handshake(t, a, b, k.client(true), k.server(newOnceCodes("ANOTHER-1").PSK))
	if d.err == nil || !errors.Is(r.err, ErrUnknownCode) {
		t.Fatalf("dial %v, accept %v", d.err, r.err)
	}
	if !errors.Is(d.err, ErrHandshakeClosed) {
		t.Fatalf("dial error %v is not ErrHandshakeClosed", d.err)
	}
	if _, err := b.Write([]byte{0}); err == nil {
		t.Fatal("the host left the connection open")
	}
}

// 6. Someone captured a phone's first handshake message and plays it back. They do
// not have the phone's ephemeral key, so they cannot send a hello the host can
// decrypt, and Accept must not hand out a session.
func TestReplayConnect(t *testing.T) {
	k := newKeys(t)
	pa, pb := pipe2(t)
	rec := &recorder{Conn: pa}
	d, r := handshake(t, rec, pb, k.client(false), k.server(nil))
	if d.err != nil || r.err != nil {
		t.Fatalf("first connect: %v %v", d.err, r.err)
	}
	d.s.Close()
	r.s.Close()
	m0 := firstMessage(t, rec.bytes())

	for _, tc := range []struct {
		name  string
		after func(c net.Conn)
	}{
		{"junk record", func(c net.Conn) {
			junk := make([]byte, 2+40)
			binary.BigEndian.PutUint16(junk, 40)
			rand.Read(junk[2:])
			c.Write(junk)
		}},
		{"a few bytes then silence", func(c net.Conn) { c.Write([]byte{0, 200, 1, 2, 3}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attacker, comp := pipe2(t)
			sc := k.server(nil)
			sc.Timing.Handshake = 300 * time.Millisecond
			ac := make(chan acceptResult, 1)
			go func() { s, err := Accept(comp, sc); ac <- acceptResult{s: s, err: err} }()
			if _, err := attacker.Write(m0); err != nil {
				t.Fatal(err)
			}
			hdr := make([]byte, 2)
			if _, err := io.ReadFull(attacker, hdr); err != nil {
				t.Fatalf("the host did not answer the replayed message: %v", err)
			}
			io.ReadFull(attacker, make([]byte, binary.BigEndian.Uint16(hdr)))
			go io.Copy(io.Discard, attacker)
			tc.after(attacker)
			select {
			case res := <-ac:
				if res.err == nil || res.s != nil {
					if res.s != nil {
						res.s.Close()
					}
					t.Fatalf("replayed first message got a session (err %v)", res.err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Accept did not return within 10 s")
			}
		})
	}
}

// The pairing replay is refused because the code was already redeemed: the PSK
// callback (the caller's one-time code) returns false the second time.
func TestReplayPair(t *testing.T) {
	k := newKeys(t)
	codes := newOnceCodes(testCode)
	pa, pb := pipe2(t)
	rec := &recorder{Conn: pa}
	d, r := handshake(t, rec, pb, k.client(true), k.server(codes.PSK))
	if d.err != nil || r.err != nil {
		t.Fatalf("first pairing: %v %v", d.err, r.err)
	}
	d.s.Close()
	r.s.Close()
	m0 := firstMessage(t, rec.bytes())

	attacker, comp := pipe2(t)
	ac := make(chan acceptResult, 1)
	go func() { s, err := Accept(comp, k.server(codes.PSK)); ac <- acceptResult{s: s, err: err} }()
	if _, err := attacker.Write(m0); err != nil {
		t.Fatal(err)
	}
	if n, err := attacker.Read(make([]byte, 1)); err == nil {
		t.Fatalf("the host answered a replayed pairing (%d bytes)", n)
	}
	res := <-ac
	if res.s != nil || !errors.Is(res.err, ErrUnknownCode) {
		t.Fatalf("replayed pairing: session %v, err %v", res.s != nil, res.err)
	}
}

// 10. A phone speaking another proto gets bye proto-mismatch.
func TestProtoMismatch(t *testing.T) {
	for _, pair := range []bool{false, true} {
		name := map[bool]string{false: "connect", true: "pair"}[pair]
		t.Run(name, func(t *testing.T) {
			k := newKeys(t)
			cc := k.client(pair)
			cc.proto = Proto + 1
			d, r := handshakePipe(t, cc, k.server(newOnceCodes(testCode).PSK))
			var bye *ByeError
			if !errors.As(d.err, &bye) || bye.Code != "proto-mismatch" || !errors.Is(d.err, ErrProtoMismatch) {
				t.Fatalf("dial error %v, want bye proto-mismatch", d.err)
			}
			if !errors.Is(r.err, ErrProtoMismatch) || r.s != nil {
				t.Fatalf("accept: %v", r.err)
			}
		})
	}
}

func TestBadPreamble(t *testing.T) {
	k := newKeys(t)
	for _, pre := range []string{"TP2X", "TP1C", "GET "} {
		a, b := pipe2(t)
		ac := make(chan error, 1)
		go func() { _, err := Accept(b, k.server(nil)); ac <- err }()
		a.Write([]byte(pre))
		if err := <-ac; !errors.Is(err, ErrBadPreamble) {
			t.Fatalf("%q: %v", pre, err)
		}
		if _, err := a.Read(make([]byte, 1)); err == nil {
			t.Fatalf("%q: connection left open", pre)
		}
	}
}

// A phone that connects and says nothing is dropped after Timing.Handshake.
func TestHandshakeTimeout(t *testing.T) {
	k := newKeys(t)
	a, b := pipe2(t)
	sc := k.server(nil)
	sc.Timing.Handshake = 200 * time.Millisecond
	start := time.Now()
	ac := make(chan error, 1)
	go func() { _, err := Accept(b, sc); ac <- err }()
	a.Write([]byte("TP2C"))
	select {
	case err := <-ac:
		if err == nil {
			t.Fatal("no error")
		}
		if el := time.Since(start); el < 150*time.Millisecond {
			t.Fatalf("gave up after %v, before the timeout", el)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Accept still waiting after 5 s")
	}
}
