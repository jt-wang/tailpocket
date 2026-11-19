package connectsecure

// Independent security review of v0.3 (session keys). Tests named TestReview* that fail on
// c13ffdf mark findings; the others record checked behaviour.

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/flynn/noise"
)

// firstRecord cuts the first transport record (the phone's hello, nonce 0) out of what the phone
// wrote: after the preamble and the first handshake message.
func firstRecord(t *testing.T, wrote []byte) []byte {
	t.Helper()
	off := len(firstMessage(t, wrote))
	if len(wrote) < off+2 {
		t.Fatal("no record after the handshake")
	}
	n := int(binary.BigEndian.Uint16(wrote[off : off+2]))
	return append([]byte(nil), wrote[off+2:off+2+n]...)
}

// Finding (session keys never change): whoever reads the host's current receive key from memory,
// after any amount of time or traffic, decrypts the whole session from its first record (the hello
// with the phone's nodekey). After a rekey the current key must not open earlier records.
//
// The test sends 1<<16 records; a fix should rekey by then, or give its threshold a test knob and
// use it here. The key is read once the host's reader has stopped (no race with Decrypt).
func TestReviewCurrentKeyOpensWholeSession(t *testing.T) {
	setRekey(t, 1<<10, rekeyAfter, rejectRecords)
	k := newKeys(t)
	a, b := net.Pipe()
	rec := &recorder{Conn: a}
	cc := k.client(false)
	cc.Phone = "nodekey:review-marker"
	phone, comp := connectedOver(t, rec, b, cc, k.server(nil))
	first := firstRecord(t, rec.bytes())

	for i := 0; i < 1<<16; i++ {
		if err := phone.Control().Send(map[string]string{"type": "ping"}); err != nil {
			t.Fatal(err)
		}
	}
	phone.Close()
	waitDone(t, comp, 5*time.Second, "the host")
	cs := noise.UnsafeNewCipherState(suite, comp.recv.UnsafeKey(), 0)
	if pt, err := cs.Decrypt(nil, nil, first); err == nil {
		t.Fatalf("the current receive key, after %d records, still opens record 0: %q", comp.recv.Nonce(), pt)
	}
}

// Checked: a counter at the end fails the session closed, it never wraps. One record at nonce
// 2^64-2 goes through; the next Write returns ErrMaxNonce and the phone's session ends.
func TestNonceEndFailsClosed(t *testing.T) {
	k := newKeys(t)
	phone, comp := connected(t, k.client(false), k.server(nil))
	phone.wmu.Lock()
	phone.send.SetNonce(noise.MaxNonce)
	phone.wmu.Unlock()
	comp.recv.SetNonce(noise.MaxNonce) // the reader is parked in ReadFull until the record arrives
	if err := phone.Control().Send(map[string]string{"type": "ping"}); err != nil {
		t.Fatalf("record at the last nonce: %v", err)
	}
	err := phone.Control().Send(map[string]string{"type": "ping"})
	if !errors.Is(err, noise.ErrMaxNonce) {
		t.Fatalf("record past the last nonce: %v, want ErrMaxNonce", err)
	}
	waitDone(t, phone, 2*time.Second, "phone")
	if !errors.Is(phone.Err(), noise.ErrMaxNonce) {
		t.Fatalf("phone ended with %v", phone.Err())
	}
}

// Checked: every Dial is a new handshake with new ephemeral keys; nothing is resumed, so two
// sessions between the same keys share no traffic key.
func TestReconnectHasFreshKeys(t *testing.T) {
	k := newKeys(t)
	p1, c1 := connected(t, k.client(false), k.server(nil))
	p2, c2 := connected(t, k.client(false), k.server(nil))
	if p1.send.UnsafeKey() == p2.send.UnsafeKey() || c1.send.UnsafeKey() == c2.send.UnsafeKey() {
		t.Fatal("two sessions share a traffic key")
	}
	if p1.send.UnsafeKey() != c1.recv.UnsafeKey() || p1.send.UnsafeKey() == p1.recv.UnsafeKey() {
		t.Fatal("directions are not split as Noise says")
	}
}
