package connectsecure

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/flynn/noise"
)

// Made-up names; nothing here comes from a real phone or computer.
const (
	testCode    = "T3ST-C0DE"
	testDevice  = "Test Phone 7"
	testVersion = "0.0.0-test"
)

type keys struct {
	phone noise.DHKey
	comp  Identity
}

func newKeys(t *testing.T) keys {
	t.Helper()
	p, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return keys{phone: p, comp: c}
}

func (k keys) client(pair bool) ClientConfig {
	c := ClientConfig{Static: k.phone, Server: k.comp.Public, Version: testVersion}
	if pair {
		c.Pair = &PairHello{CID: CIDFor(testCode), PSK: PSKFor(testCode)}
		c.Device = testDevice
	}
	return c
}

const (
	testDeviceID = "dev-test-1"
	testToken    = "tok-test-not-real"
)

// admitAll lets every phone in, as if every key were in the device list and
// every pairing redeemed.
func admitAll(p Peer) (Admission, error) {
	a := Admission{OK: true, Device: testDeviceID}
	if p.Pair {
		a.Paired = &Paired{Phone: testDeviceID, Name: "Test Computer", Payload: testToken}
	}
	return a, nil
}

// onceCodes is a pairing-window stand-in: each code works once, like a real pairing window.
type onceCodes struct {
	mu   sync.Mutex
	open map[string][32]byte
}

func newOnceCodes(codes ...string) *onceCodes {
	o := &onceCodes{open: map[string][32]byte{}}
	for _, c := range codes {
		o.open[CIDFor(c)] = PSKFor(c)
	}
	return o
}

func (o *onceCodes) PSK(cid string) ([32]byte, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	p, ok := o.open[cid]
	delete(o.open, cid)
	return p, ok
}

func (k keys) server(psk func(string) ([32]byte, bool)) ServerConfig {
	return ServerConfig{Identity: k.comp, PSK: psk, Admit: admitAll, Version: testVersion}
}

type dialResult struct {
	s   *Session
	err error
}

type acceptResult struct {
	s    *Session
	peer Peer
	err  error
}

// handshake runs Dial on a and Accept on b at the same time.
func handshake(t *testing.T, a, b net.Conn, cc ClientConfig, sc ServerConfig) (dialResult, acceptResult) {
	t.Helper()
	dc := make(chan dialResult, 1)
	ac := make(chan acceptResult, 1)
	var peer Peer
	if admit := sc.Admit; admit != nil {
		sc.Admit = func(p Peer) (Admission, error) { peer = p; return admit(p) }
	}
	go func() { s, err := Dial(a, cc); dc <- dialResult{s, err} }()
	go func() { s, err := Accept(b, sc); ac <- acceptResult{s, peer, err} }()
	var d dialResult
	var r acceptResult
	timeout := time.After(15 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case d = <-dc:
		case r = <-ac:
		case <-timeout:
			t.Fatal("handshake did not finish in 15 s")
		}
	}
	return d, r
}

// connected returns a phone and a the host session over net.Pipe.
func connected(t *testing.T, cc ClientConfig, sc ServerConfig) (*Session, *Session) {
	t.Helper()
	a, b := net.Pipe()
	return connectedOver(t, a, b, cc, sc)
}

func connectedOver(t *testing.T, a, b net.Conn, cc ClientConfig, sc ServerConfig) (*Session, *Session) {
	t.Helper()
	d, r := handshake(t, a, b, cc, sc)
	if d.err != nil || r.err != nil {
		t.Fatalf("handshake: dial %v, accept %v", d.err, r.err)
	}
	t.Cleanup(func() { d.s.Close(); r.s.Close() })
	return d.s, r.s
}

func waitDone(t *testing.T, s *Session, within time.Duration, who string) {
	t.Helper()
	select {
	case <-s.Done():
	case <-time.After(within):
		t.Fatalf("%s: session still open after %v", who, within)
	}
}

func stillOpen(s *Session) bool {
	select {
	case <-s.Done():
		return false
	default:
		return true
	}
}

// recorder keeps a copy of everything written through it.
type recorder struct {
	net.Conn
	mu  sync.Mutex
	buf bytes.Buffer
}

func (r *recorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	r.buf.Write(p)
	r.mu.Unlock()
	return r.Conn.Write(p)
}

func (r *recorder) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.buf.Bytes()...)
}

// firstMessage cuts the preamble and the first handshake message out of what a phone wrote.
func firstMessage(t *testing.T, wrote []byte) []byte {
	t.Helper()
	if len(wrote) < 6 {
		t.Fatalf("phone wrote only %d bytes", len(wrote))
	}
	n := int(binary.BigEndian.Uint16(wrote[4:6]))
	if len(wrote) < 6+n {
		t.Fatalf("first message cut short")
	}
	return append([]byte(nil), wrote[:6+n]...)
}

// proxy sits between the phone (a side) and the host (b side) and can change bytes.
type proxy struct {
	phone, comp net.Conn // the proxy's ends: phone talks to phone, the host to comp
	mu          sync.Mutex
	flipNext    bool // flip one byte of the next phone->the host record
	freeze      bool // drop everything the host sends to the phone
	dupNext     bool // send the next phone->the host record twice
	stall       bool // stop reading what the host sends (its writes block)
	flipped     chan struct{}
}

// newProxy returns the conn the phone uses, the conn the host uses, and the proxy.
func newProxy() (net.Conn, net.Conn, *proxy) {
	phoneSide, pPhone := net.Pipe()
	pComp, compSide := net.Pipe()
	p := &proxy{phone: pPhone, comp: pComp, flipped: make(chan struct{})}
	go p.phoneToComp()
	go p.compToPhone()
	return phoneSide, compSide, p
}

func (p *proxy) phoneToComp() {
	defer p.comp.Close()
	pre := make([]byte, 4)
	if _, err := io.ReadFull(p.phone, pre); err != nil {
		return
	}
	if _, err := p.comp.Write(pre); err != nil {
		return
	}
	hdr := make([]byte, 2)
	for {
		if _, err := io.ReadFull(p.phone, hdr); err != nil {
			return
		}
		body := make([]byte, binary.BigEndian.Uint16(hdr))
		if _, err := io.ReadFull(p.phone, body); err != nil {
			return
		}
		p.mu.Lock()
		if p.flipNext && len(body) > 0 {
			body[len(body)/2] ^= 0x01
			p.flipNext = false
			close(p.flipped)
		}
		dup := p.dupNext
		p.dupNext = false
		p.mu.Unlock()
		if _, err := p.comp.Write(append(hdr, body...)); err != nil {
			return
		}
		if dup {
			if _, err := p.comp.Write(append(hdr, body...)); err != nil {
				return
			}
		}
		hdr = make([]byte, 2)
	}
}

func (p *proxy) compToPhone() {
	defer p.phone.Close()
	buf := make([]byte, 32<<10)
	for {
		for {
			p.mu.Lock()
			st := p.stall
			p.mu.Unlock()
			if !st {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		n, err := p.comp.Read(buf)
		if n > 0 {
			p.mu.Lock()
			drop := p.freeze
			p.mu.Unlock()
			if !drop {
				if _, werr := p.phone.Write(buf[:n]); werr != nil {
					return
				}
			}
		}
		if err != nil {
			return
		}
	}
}

func (p *proxy) set(f func(*proxy)) {
	p.mu.Lock()
	f(p)
	p.mu.Unlock()
}

func isErr(err error, targets ...error) bool {
	for _, t := range targets {
		if errors.Is(err, t) {
			return true
		}
	}
	return false
}

func handshakePipe(t *testing.T, cc ClientConfig, sc ServerConfig) (dialResult, acceptResult) {
	t.Helper()
	a, b := pipe2(t)
	return handshake(t, a, b, cc, sc)
}

// setRekey lowers the rekey thresholds for one test.
func setRekey(t *testing.T, records uint64, after time.Duration, reject uint64) {
	t.Helper()
	r, a, j := rekeyRecords, rekeyAfter, rejectRecords
	rekeyRecords, rekeyAfter, rejectRecords = records, after, reject
	t.Cleanup(func() { rekeyRecords, rekeyAfter, rejectRecords = r, a, j })
}
