package connectlocal

// Audit H1 (v0.3, 83d4174): in wire v1 the phone sent its key in the clear, so a machine in the middle
// picked the key it gave one side after it had seen both codes' inputs and made the two codes equal
// in about a second. The user compared two equal codes, approved, and the host sealed the invite to
// the attacker.
//
// Rewritten for wire v2, where the phone commits to SHA256(label ‖ "commit" ‖ phonePub ‖ nonce) before
// it sees the host's key. The attacker below is the strongest one the order of messages allows:
//
//   - phone first: it plays host to the phone and learns the phone's code; towards the real host it
//     sees hostPub and only then picks what it reveals, grinding the nonce until the host's code equals
//     the phone's (the v1 attack, moved to the only input still open). The host must refuse the reveal
//     because it does not match the commitment, before its user sees any code.
//   - host first: it finishes the host side and learns the host's code, then has to give the phone a
//     key while the phone's key and nonce are still hidden behind the commitment, so there is nothing
//     to grind; the codes match only by chance (10^-6) and the user denies.
//
// With the commitment check removed from the host, the phone-first attacker steals the invite.

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
)

var auditInvite = []byte(`{"v":1,"key":"privkey:secret","proof":"secret"}`)

// codeV2 is NewSession's code, written out so the grind costs two SHA-256 per try.
func codeV2(label string, phonePub, hostPub, nonce, shared []byte) string {
	commit := Commit(label, phonePub, nonce)
	d := sha256.New()
	d.Write([]byte(label))
	d.Write([]byte("code"))
	d.Write(commit[:])
	d.Write(phonePub)
	d.Write(hostPub)
	d.Write(nonce)
	d.Write(shared)
	return fmt.Sprintf("%06d", binary.BigEndian.Uint64(d.Sum(nil)[:8])%1_000_000)
}

// grindNonce finds a nonce for which the host computes want from the attacker's key and hostPub.
// The commitment inside the code is recomputed from the revealed key and nonce, as the host does.
func grindNonce(t *testing.T, label string, own KeyPair, hostPub []byte, want string) []byte {
	t.Helper()
	shared, err := curve25519.X25519(own.Private[:], hostPub)
	if err != nil {
		t.Fatal(err)
	}
	found := make(chan []byte, 1)
	done := make(chan struct{})
	var once sync.Once
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			nonce := make([]byte, NonceSize)
			_, _ = rand.Read(nonce)
			for i := uint64(0); ; i++ {
				if i%4096 == 0 {
					select {
					case <-done:
						return
					default:
					}
				}
				binary.BigEndian.PutUint64(nonce, i)
				if codeV2(label, own.Public[:], hostPub, nonce, shared) == want {
					once.Do(func() { found <- append([]byte{}, nonce...); close(done) })
					return
				}
			}
		}()
	}
	select {
	case n := <-found:
		wg.Wait()
		return n
	case <-time.After(3 * time.Minute):
		close(done)
		wg.Wait()
		t.Fatal("no matching nonce in 3 minutes")
	}
	return nil
}

type auditHost struct {
	s         served
	phoneCode chan string
	prompts   chan string    // codes the host showed its user
	compared  chan [2]string // host's code, phone's code, as the user compared them
}

// auditServe runs a host whose user approves only when the phone shows the same code.
func auditServe(t *testing.T, ctx context.Context) *auditHost {
	h := &auditHost{phoneCode: make(chan string, 1), prompts: make(chan string, 8), compared: make(chan [2]string, 8)}
	// The reveal gets two minutes instead of HelloTimeout's 5 s, so the grind is never cut short by time.
	h.s = serve(t, ctx, HostOptions{Plaintext: auditInvite, Expires: time.Now().Add(3 * time.Minute), HelloTimeout: 2 * time.Minute,
		Confirm: func(ctx context.Context, code, _ string) bool {
			h.prompts <- code
			select {
			case pc := <-h.phoneCode:
				h.compared <- [2]string{code, pc}
				return pc == code
			case <-ctx.Done():
				return false
			}
		}})
	return h
}

// mitmListen is where the phone connects instead of the host (a spoofed Bonjour answer or ARP).
func mitmListen(t *testing.T) net.Listener {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

type wire struct {
	c net.Conn
	r *bufio.Reader
}

func (w wire) send(t *testing.T, m map[string]any) {
	if err := writeLine(w.c, m); err != nil {
		t.Errorf("mitm write: %v", err)
	}
}

func (w wire) recv(v any) error {
	line, err := readLine(w.r)
	if err != nil {
		return err
	}
	return decodeStrict(line, v)
}

type v2hello struct {
	V      int    `json:"v"`
	Commit string `json:"commit"`
	Device string `json:"device"`
}

type v2reveal struct {
	V         int    `json:"v"`
	PublicKey string `json:"publicKey"`
	Nonce     string `json:"nonce"`
}

var enc = base64.StdEncoding.EncodeToString

func TestAuditLocalPairingMITMMatchesCodes(t *testing.T) {
	t.Run("phone first, reveal ground after seeing the host key", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
		defer cancel()
		host := auditServe(t, ctx)
		hostAddr := host.s.addr(t)
		mitm := mitmListen(t)
		outcome := make(chan string, 1)
		go func() {
			pc, err := mitm.Accept()
			if err != nil {
				return
			}
			defer pc.Close()
			phone := wire{pc, bufio.NewReader(pc)}
			var hello v2hello
			if err := phone.recv(&hello); err != nil {
				outcome <- "phone hello: " + err.Error()
				return
			}
			// Play host to the phone: its reveal gives away the code it shows.
			fake, _ := NewKeyPair()
			phone.send(t, map[string]any{"publicKey": enc(fake.Public[:]), "v": wireVersion})
			var rv v2reveal
			if err := phone.recv(&rv); err != nil {
				outcome <- "phone reveal: " + err.Error()
				return
			}
			phonePub, _ := base64.StdEncoding.DecodeString(rv.PublicKey)
			phoneNonce, _ := base64.StdEncoding.DecodeString(rv.Nonce)
			toPhone, err := NewSession(DefaultLabel, fake, phonePub, false, phoneNonce)
			if err != nil {
				outcome <- "phone session: " + err.Error()
				return
			}
			phoneCode := toPhone.Code

			// Play phone to the host. The commitment has to go first; everything after hostPub is ground.
			hc, err := net.Dial("tcp", hostAddr)
			if err != nil {
				outcome <- err.Error()
				return
			}
			defer hc.Close()
			hostSide := wire{hc, bufio.NewReader(hc)}
			own, _ := NewKeyPair()
			committed, _ := NewNonce()
			commit := Commit(DefaultLabel, own.Public[:], committed)
			hostSide.send(t, map[string]any{"commit": enc(commit[:]), "device": hello.Device, "v": wireVersion})
			hostHello, err := readMessage(hostSide.r)
			if err != nil {
				outcome <- "host hello: " + err.Error()
				return
			}
			hostPub, _ := base64.StdEncoding.DecodeString(hostHello.PublicKey)
			if honest, _ := NewSession(DefaultLabel, own, hostPub, true, committed); honest == nil ||
				codeV2(DefaultLabel, own.Public[:], hostPub, committed, mustShared(t, own, hostPub)) != honest.Code {
				outcome <- "codeV2 does not match NewSession"
				return
			}
			start := time.Now()
			nonce := grindNonce(t, DefaultLabel, own, hostPub, phoneCode)
			t.Logf("nonce giving the phone's code %s found in %v", phoneCode, time.Since(start))
			hostSide.send(t, map[string]any{"nonce": enc(nonce), "publicKey": enc(own.Public[:]), "v": wireVersion})
			toHost, _ := NewSession(DefaultLabel, own, hostPub, true, nonce)
			approval, err := readMessage(hostSide.r)
			if err != nil {
				outcome <- "host closed after the reveal: " + err.Error()
				return
			}
			box, _ := base64.StdEncoding.DecodeString(approval.Sealed)
			if plain, err := toHost.Open(box); err == nil {
				outcome <- "STOLEN " + string(plain)
				return
			}
			outcome <- "host replied " + approval.Status
		}()
		go func() {
			_, _ = Pair(ctx, mitm.Addr().String(), PhoneOptions{Label: DefaultLabel, Device: "Pixel 9",
				OnCode: func(code string) { host.phoneCode <- code }})
		}()

		var got string
		select {
		case got = <-outcome:
		case <-ctx.Done():
			t.Fatal("attack did not finish")
		}
		t.Log(got)
		if plain, ok := strings.CutPrefix(got, "STOLEN "); ok {
			t.Fatalf("the user compared two equal codes (%v) and approved; the attacker decrypted the invite: %s", <-host.compared, plain)
		}
		select {
		case code := <-host.prompts:
			t.Fatalf("the host showed its user code %s for a reveal that does not match the commitment", code)
		default:
		}
		if !strings.HasPrefix(got, "host closed after the reveal") {
			t.Fatalf("attack stopped somewhere else: %s", got)
		}
	})

	t.Run("host first, phone key hidden behind its commitment", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		host := auditServe(t, ctx)
		hostAddr := host.s.addr(t)
		mitm := mitmListen(t)
		outcome := make(chan string, 1)
		go func() {
			pc, err := mitm.Accept()
			if err != nil {
				return
			}
			defer pc.Close()
			phone := wire{pc, bufio.NewReader(pc)}
			var hello v2hello
			if err := phone.recv(&hello); err != nil {
				outcome <- "phone hello: " + err.Error()
				return
			}
			// Finish the host side first: the attacker knows the code the host shows.
			hc, err := net.Dial("tcp", hostAddr)
			if err != nil {
				outcome <- err.Error()
				return
			}
			defer hc.Close()
			hostSide := wire{hc, bufio.NewReader(hc)}
			own, _ := NewKeyPair()
			nonce, _ := NewNonce()
			commit := Commit(DefaultLabel, own.Public[:], nonce)
			hostSide.send(t, map[string]any{"commit": enc(commit[:]), "device": hello.Device, "v": wireVersion})
			hostHello, err := readMessage(hostSide.r)
			if err != nil {
				outcome <- "host hello: " + err.Error()
				return
			}
			hostPub, _ := base64.StdEncoding.DecodeString(hostHello.PublicKey)
			hostSide.send(t, map[string]any{"nonce": enc(nonce), "publicKey": enc(own.Public[:]), "v": wireVersion})
			toHost, _ := NewSession(DefaultLabel, own, hostPub, true, nonce)
			// The phone's code depends on its key and nonce, which only its commitment stands for:
			// no key the attacker sends now can be chosen to give toHost.Code.
			fake, _ := NewKeyPair()
			phone.send(t, map[string]any{"publicKey": enc(fake.Public[:]), "v": wireVersion})
			var rv v2reveal
			_ = phone.recv(&rv)
			approval, err := readMessage(hostSide.r)
			if err != nil {
				outcome <- "host: " + err.Error()
				return
			}
			box, _ := base64.StdEncoding.DecodeString(approval.Sealed)
			if plain, err := toHost.Open(box); err == nil {
				outcome <- "STOLEN " + string(plain)
				return
			}
			outcome <- "host replied " + approval.Status
		}()
		go func() {
			_, _ = Pair(ctx, mitm.Addr().String(), PhoneOptions{Label: DefaultLabel, Device: "Pixel 9",
				OnCode: func(code string) { host.phoneCode <- code }})
		}()
		var got string
		select {
		case got = <-outcome:
		case <-ctx.Done():
			t.Fatal("attack did not finish")
		}
		codes := <-host.compared
		t.Logf("host showed %s, phone showed %s: %s", codes[0], codes[1], got)
		if got != "host: "+ErrDenied.Error() {
			t.Fatalf("the user should have seen two different codes and denied: %s", got)
		}
	})
}

func mustShared(t *testing.T, own KeyPair, peer []byte) []byte {
	s, err := curve25519.X25519(own.Private[:], peer)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
