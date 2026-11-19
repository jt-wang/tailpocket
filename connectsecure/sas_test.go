package connectsecure

import (
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

func TestSASTableIsDistinct(t *testing.T) {
	seen := map[string]bool{}
	names := map[string]bool{}
	for i, e := range SASEmoji {
		if e == "" || seen[e] || SASNames[i] == "" || names[SASNames[i]] {
			t.Fatalf("entry %d (%q %q) is empty or repeated", i, e, SASNames[i])
		}
		for _, r := range e {
			if r == 0xFE0F || r == 0x200D {
				t.Fatalf("entry %d %q has a variation selector or joiner", i, e)
			}
		}
		seen[e], names[SASNames[i]] = true, true
	}
}

// SAS reads 24 bits big-endian, 6 per emoji; a fixed binding pins that against a mistake in the
// shifts that would still give both sides the same four.
func TestSASBits(t *testing.T) {
	got := SAS([]byte("tailpocket sas test binding"))
	again := SAS([]byte("tailpocket sas test binding"))
	other := SAS([]byte("tailpocket sas test binding."))
	// Expected value computed outside Go: HKDF-SHA256(salt 32 zero bytes, info "tailpocket2 sas"), 3 bytes.
	if got != [4]int{8, 15, 61, 32} {
		t.Fatalf("SAS = %v, want [8 15 61 32]", got)
	}
	if got != again || got == other {
		t.Fatalf("SAS not a function of the binding: %v %v %v", got, again, other)
	}
	for _, n := range got {
		if n < 0 || n > 63 {
			t.Fatalf("index %d out of range", n)
		}
	}
	// Spread: 4096 bindings use every index of the table.
	used := map[int]bool{}
	for i := range 4096 {
		for _, n := range SAS([]byte{byte(i), byte(i >> 8)}) {
			used[n] = true
		}
	}
	if len(used) != 64 {
		t.Fatalf("4096 bindings used %d of 64 emoji", len(used))
	}
}

// The phone shows the same four emoji the host computes from the session it admits, and its hello
// says it shows them.
func TestPairingSASMatchesBothSides(t *testing.T) {
	k := newKeys(t)
	var shown []string
	cc := k.client(true)
	cc.OnSAS = func(e []string) { shown = e }
	var host []string
	var flagged bool
	sc := k.server(newOnceCodes(testCode).PSK)
	sc.Admit = func(p Peer) (Admission, error) {
		host, flagged = SASText(p.Binding), p.SAS
		if err := p.Pending(); err != nil {
			return Admission{}, err
		}
		return admitAll(p)
	}
	d, r := handshakePipe(t, cc, sc)
	if d.err != nil || r.err != nil {
		t.Fatalf("dial %v, accept %v", d.err, r.err)
	}
	if len(shown) != 4 || !slices.Equal(shown, host) || !flagged {
		t.Fatalf("phone showed %v, host computed %v, hello sas %v", shown, host, flagged)
	}
	if !slices.Equal(SASText(d.s.ChannelBinding()), shown) {
		t.Fatal("the phone's emoji are not its session's")
	}
}

// Without OnSAS the hello does not claim the emoji are shown.
func TestPairingWithoutOnSASSaysSo(t *testing.T) {
	k := newKeys(t)
	var flagged atomic.Bool
	sc := k.server(newOnceCodes(testCode).PSK)
	sc.Admit = func(p Peer) (Admission, error) { flagged.Store(p.SAS); return admitAll(p) }
	if d, r := handshakePipe(t, k.client(true), sc); d.err != nil || r.err != nil {
		t.Fatalf("dial %v, accept %v", d.err, r.err)
	}
	if flagged.Load() {
		t.Fatal("hello said sas without OnSAS")
	}
}

// Only a pairing waits for the host's user: a connecting phone's Admit still has Handshake, not
// Handshake+Confirm, so a slow connect cannot hold a handshake slot for a minute.
func TestConnectGetsNoConfirmTime(t *testing.T) {
	k := newKeys(t)
	sc := k.server(nil)
	sc.Timing.Handshake, sc.Timing.Confirm = 300*time.Millisecond, 5*time.Second
	sc.Admit = func(p Peer) (Admission, error) { time.Sleep(500 * time.Millisecond); return admitAll(p) }
	if _, r := handshakePipe(t, k.client(false), sc); r.err == nil {
		t.Fatal("a connect waited past Handshake")
	}
	// The same wait is fine for a pairing.
	sc.PSK = newOnceCodes(testCode).PSK
	if d, r := handshakePipe(t, k.client(true), sc); d.err != nil || r.err != nil {
		t.Fatalf("a pairing within Handshake+Confirm failed: dial %v, accept %v", d.err, r.err)
	}
}

// The phone shows the emoji only once the host says it waits for its user: a refused pairing (busy,
// wrong window) shows none, so the user never compares a stranger's.
func TestNoEmojiWithoutPending(t *testing.T) {
	k := newKeys(t)
	var shown atomic.Bool
	cc := k.client(true)
	cc.OnSAS = func([]string) { shown.Store(true) }
	sc := k.server(newOnceCodes(testCode).PSK)
	sc.Admit = func(Peer) (Admission, error) { return Admission{Bye: "busy"}, nil }
	if d, _ := handshakePipe(t, cc, sc); d.err == nil {
		t.Fatal("a refused pairing went through")
	}
	if shown.Load() {
		t.Fatal("the phone showed emoji for a pairing the host refused")
	}
}

// A host that waits for an emoji check this phone does not show gets no pairing from it.
func TestPendingWithoutOnSASFails(t *testing.T) {
	k := newKeys(t)
	sc := k.server(newOnceCodes(testCode).PSK)
	sc.Admit = func(p Peer) (Admission, error) { _ = p.Pending(); return admitAll(p) }
	if d, _ := handshakePipe(t, k.client(true), sc); d.err == nil || d.s != nil {
		t.Fatalf("phone without OnSAS paired after pending: %v", d.err)
	}
}

// A pre.4 host pairs only with proto 3 (a pre.3 phone would not show the emoji), and still takes
// connects at proto 2, which pre.2 and pre.3 phones speak.
func TestProtoForPairAndConnect(t *testing.T) {
	k := newKeys(t)
	cc := k.client(true)
	cc.proto = 2
	if d, _ := handshakePipe(t, cc, k.server(newOnceCodes(testCode).PSK)); !errors.Is(d.err, ErrProtoMismatch) {
		t.Fatalf("a proto 2 pairing got %v, want proto-mismatch", d.err)
	}
	cc = k.client(false)
	cc.proto = 2
	if d, r := handshakePipe(t, cc, k.server(nil)); d.err != nil || r.err != nil {
		t.Fatalf("a proto 2 connect: dial %v, accept %v", d.err, r.err)
	}
	cc.proto = 3
	if d, _ := handshakePipe(t, cc, k.server(nil)); !errors.Is(d.err, ErrProtoMismatch) {
		t.Fatalf("a proto 3 connect got %v, want proto-mismatch", d.err)
	}
}

// A phone that hangs up while the host's user decides closes Peer.Gone, so the host stops asking.
func TestGoneWhenPhoneHangsUp(t *testing.T) {
	k := newKeys(t)
	a, b := pipe2(t)
	cc := k.client(true)
	cc.OnSAS = func([]string) { go a.Close() } // the phone gives up as soon as it shows the emoji
	sc := k.server(newOnceCodes(testCode).PSK)
	gone := make(chan bool, 1)
	sc.Admit = func(p Peer) (Admission, error) {
		_ = p.Pending()
		select {
		case <-p.Gone:
			gone <- true
		case <-time.After(5 * time.Second):
			gone <- false
		}
		return Admission{Bye: "denied"}, nil
	}
	go func() { _, _ = Dial(a, cc) }()
	_, _ = Accept(b, sc)
	if !<-gone {
		t.Fatal("Gone stayed open after the phone hung up")
	}
}
