package connectsecure

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/flynn/noise"
	"golang.org/x/crypto/chacha20poly1305"
)

type vector struct {
	name                         string
	initStatic, respStatic       []byte
	initEphemeral, respEphemeral []byte
	prologue, psk                []byte
	msgs                         []vectorMsg
}

type vectorMsg struct{ payload, ciphertext []byte }

func readVectors(t *testing.T) []vector {
	t.Helper()
	f, err := os.Open("testdata/vectors.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []vector
	var cur *vector
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("bad line %q", line)
		}
		if k == "handshake" {
			out = append(out, vector{name: v})
			cur = &out[len(out)-1]
			continue
		}
		b, err := hex.DecodeString(v)
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		switch {
		case k == "init_static":
			cur.initStatic = b
		case k == "resp_static":
			cur.respStatic = b
		case k == "gen_init_ephemeral":
			cur.initEphemeral = b
		case k == "gen_resp_ephemeral":
			cur.respEphemeral = b
		case k == "prologue":
			cur.prologue = b
		case k == "preshared_key":
			cur.psk = b
		case strings.HasPrefix(k, "msg_"):
			i, err := strconv.Atoi(strings.SplitN(k, "_", 3)[1])
			if err != nil {
				t.Fatal(err)
			}
			for len(cur.msgs) <= i {
				cur.msgs = append(cur.msgs, vectorMsg{})
			}
			if strings.HasSuffix(k, "_payload") {
				cur.msgs[i].payload = b
			} else {
				cur.msgs[i].ciphertext = b
			}
		default:
			t.Fatalf("unknown key %q", k)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestVectors replays flynn/noise's own vectors through handshakeConfig, with the
// psk set the way Dial and Accept set it, and expects the same bytes.
func TestVectors(t *testing.T) {
	vs := readVectors(t)
	counts := map[string]int{}
	for _, v := range vs {
		counts[v.name]++
	}
	if counts[protocolName(false)] != 4 || counts[protocolName(true)] != 4 || len(vs) != 8 {
		t.Fatalf("want 4 vectors each of %s and %s, got %v", protocolName(false), protocolName(true), counts)
	}
	for i, v := range vs {
		t.Run(fmt.Sprintf("%d_%s", i, v.name), func(t *testing.T) { replayVector(t, v) })
	}
}

func replayVector(t *testing.T, v vector) {
	pair := strings.Contains(v.name, "psk2")
	si, err := noise.DH25519.GenerateKeypair(bytes.NewReader(v.initStatic))
	if err != nil {
		t.Fatal(err)
	}
	sr, err := noise.DH25519.GenerateKeypair(bytes.NewReader(v.respStatic))
	if err != nil {
		t.Fatal(err)
	}
	hi, err := noise.NewHandshakeState(handshakeConfig(pair, true, si, sr.Public, v.prologue, bytes.NewReader(v.initEphemeral)))
	if err != nil {
		t.Fatal("initiator:", err)
	}
	hr, err := noise.NewHandshakeState(handshakeConfig(pair, false, sr, nil, v.prologue, bytes.NewReader(v.respEphemeral)))
	if err != nil {
		t.Fatal("responder:", err)
	}
	if pair {
		if err := hi.SetPresharedKey(v.psk); err != nil {
			t.Fatal(err)
		}
	}
	if len(v.msgs) < 3 {
		t.Fatalf("vector has %d messages", len(v.msgs))
	}

	// msg 0: phone -> the host.
	m0, _, _, err := hi.WriteMessage(nil, v.msgs[0].payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m0, v.msgs[0].ciphertext) {
		t.Fatalf("msg 0:\n got %x\nwant %x", m0, v.msgs[0].ciphertext)
	}
	p0, _, _, err := hr.ReadMessage(nil, m0)
	if err != nil || !bytes.Equal(p0, v.msgs[0].payload) {
		t.Fatalf("msg 0 read: %v %x", err, p0)
	}
	if pair { // the host learns which psk only now.
		if err := hr.SetPresharedKey(v.psk); err != nil {
			t.Fatal(err)
		}
	}
	// msg 1: the host -> phone; the handshake ends here.
	m1, rRecv, rSend, err := hr.WriteMessage(nil, v.msgs[1].payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m1, v.msgs[1].ciphertext) {
		t.Fatalf("msg 1:\n got %x\nwant %x", m1, v.msgs[1].ciphertext)
	}
	p1, iSend, iRecv, err := hi.ReadMessage(nil, m1)
	if err != nil || !bytes.Equal(p1, v.msgs[1].payload) {
		t.Fatalf("msg 1 read: %v %x", err, p1)
	}
	if rRecv == nil || iSend == nil {
		t.Fatal("handshake did not finish after two messages")
	}
	// Transport messages alternate, phone first.
	for i := 2; i < len(v.msgs); i++ {
		enc, dec := iSend, rRecv
		if i%2 == 1 {
			enc, dec = rSend, iRecv
		}
		c, err := enc.Encrypt(nil, nil, v.msgs[i].payload)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(c, v.msgs[i].ciphertext) {
			t.Fatalf("msg %d:\n got %x\nwant %x", i, c, v.msgs[i].ciphertext)
		}
		p, err := dec.Decrypt(nil, nil, c)
		if err != nil || !bytes.Equal(p, v.msgs[i].payload) {
			t.Fatalf("msg %d decrypt: %v", i, err)
		}
	}
}

func TestPSKAndCID(t *testing.T) {
	// Fixed inputs; expected values computed independently with:
	//   printf 'tailpocket2 psk%s' 'K7Q2-M9XD' | shasum -a 256
	//   printf 'tailpocket2 cid%s' 'K7Q2-M9XD' | shasum -a 256 | head -c 24 | xxd -r -p | base64 | tr '+/' '-_' | tr -d =
	const code = "K7Q2-M9XD"
	if got := hex.EncodeToString(func() []byte { p := PSKFor(code); return p[:] }()); got != wantPSKHex {
		t.Fatalf("PSKFor = %s, want %s", got, wantPSKHex)
	}
	if got := CIDFor(code); got != wantCID || len(got) != 16 {
		t.Fatalf("CIDFor = %q, want %q", got, wantCID)
	}
}

const (
	wantPSKHex = "8f14e1c1fb5fa88198284021414a4fd7a15d02259253aed198defcf500953ed8"
	wantCID    = "Lxg4KIARYwS-0pjk"
)

// Rekey is the spec's (Noise rev 34, 4.2): the new key is the first 32 bytes of
// ENCRYPT(k, 2^64-1, "", 32 zero bytes), and the nonce goes on. Computed here with x/crypto's
// ChaCha20-Poly1305 directly, so a flynn/noise change to Rekey fails this test.
func TestRekeyMatchesSpec(t *testing.T) {
	var k [32]byte
	for i := range k {
		k[i] = byte(i + 1)
	}
	aead, err := chacha20poly1305.New(k[:])
	if err != nil {
		t.Fatal(err)
	}
	var nonce [12]byte // ChaChaPoly: 4 zero bytes, then the counter little-endian
	binary.LittleEndian.PutUint64(nonce[4:], ^uint64(0))
	want := aead.Seal(nil, nonce[:], make([]byte, 32), nil)[:32]

	cs := noise.UnsafeNewCipherState(suite, k, 7)
	cs.Rekey()
	got := cs.UnsafeKey()
	if !bytes.Equal(got[:], want) {
		t.Fatalf("rekeyed key %x, want %x", got, want)
	}
	if cs.Nonce() != 7 {
		t.Fatalf("nonce %d after rekey, want 7", cs.Nonce())
	}
}
