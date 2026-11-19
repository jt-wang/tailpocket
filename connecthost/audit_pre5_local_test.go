package connecthost

// Audit, pre.5 review (3e33f26), H1 retries: connectlocal.Serve now hands its key to at most
// connectlocal.MaxAttempts commitments and then ends with ErrTooManyAttempts, so one Serve call gives
// a machine in the middle at most 3 guesses at the phone's code. The count lives in that one call.
// Pairing.ServeLocal can be called again on the same pairing window (the helper refuses a second
// "local" for a pairing id; the Go API does not), and every call starts at zero. An app that calls
// ServeLocal again when it fails, without a user action in between, gives 3 more keys each time for
// as long as the pairing window is open (up to MaxTTL), which is the unbounded retry again.
//
// The source addresses below are three loopback addresses, as a machine on the Wi-Fi takes three
// addresses of the subnet: SourceGap is per address, so it does not slow this down.

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/jt-wang/tailpocket/connectlocal"
	"github.com/jt-wang/tailpocket/connectmdns"
)

// abandonedKey sends one honest commitment from source and reports whether the host answered it
// with its key. It never reveals.
func abandonedKey(source string, port int) bool {
	kp, _ := connectlocal.NewKeyPair()
	nonce, _ := connectlocal.NewNonce()
	commit := connectlocal.Commit(connectlocal.DefaultLabel, kp.Public[:], nonce)
	d := net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}
	c, err := d.Dial("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return false
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	line, _ := json.Marshal(map[string]any{"commit": base64.StdEncoding.EncodeToString(commit[:]), "device": "x", "v": 2})
	if _, err := c.Write(append(line, '\n')); err != nil {
		return false
	}
	reply, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil {
		return false
	}
	var m struct {
		PublicKey string `json:"publicKey"`
	}
	return json.Unmarshal(reply, &m) == nil && m.PublicKey != ""
}

func TestAuditServeLocalAgainGivesNewAttempts(t *testing.T) {
	h, _, _ := newTestHost(t, Config{})
	p, err := h.Pair(context.Background(), PairOptions{TTL: MaxTTL})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sources := []string{"127.0.0.2", "127.0.0.3", "127.0.0.4"}
	prompts, keys, calls := 0, 0, 0
	const measure = 3 * time.Second
	start := time.Now()
	for time.Since(start) < measure {
		port := make(chan int, 1)
		errc := make(chan error, 1)
		go func() {
			errc <- p.ServeLocal(ctx, LocalOptions{Service: "_tailpocket-demo._tcp",
				Bindings:  []connectlocal.Binding{{IP: net.IPv4(127, 0, 0, 1).To4(), Mask: net.CIDRMask(8, 32)}},
				Advertise: func(s connectmdns.Service) (func(), error) { port <- s.Port; return func() {}, nil },
				Confirm:   func(context.Context, string, string) bool { prompts++; return false }})
		}()
		var at int
		select {
		case at = <-port:
		case err := <-errc:
			// The fix: the pairing is spent, ServeLocal does not open another window on it.
			t.Logf("ServeLocal call %d refused: %v", calls+1, err)
			goto done
		}
		calls++
		for _, src := range sources {
			// The host serves one peer at a time: while the last attempt's handler still holds the
			// slot the answer is a denial, which costs nothing. Try again until this address has its key.
			for try := 0; try < 100; try++ {
				if abandonedKey(src, at) {
					keys++
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
		}
		select {
		case err := <-errc:
			if !errors.Is(err, connectlocal.ErrTooManyAttempts) {
				t.Fatalf("ServeLocal: %v, want ErrTooManyAttempts", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the window stayed open after MaxAttempts abandoned commitments")
		}
	}
done:
	elapsed := time.Since(start)
	rate := float64(keys) / elapsed.Seconds()
	t.Logf("one pairing window: %d ServeLocal calls in %v handed out %d keys (%.0f/s), %d prompts", calls, elapsed.Round(time.Millisecond), keys, rate, prompts)
	if keys > connectlocal.MaxAttempts {
		t.Fatalf("one pairing window handed its key to %d abandoned commitments over %d ServeLocal calls (want at most %d for the window): "+
			"an app that calls ServeLocal again on ErrTooManyAttempts has no bound", keys, calls, connectlocal.MaxAttempts)
	}
}

// L2: a window whose same-Wi-Fi pairing ran out of attempts ends, so its QR code pairs nobody either,
// and a second ServeLocal on it is refused at once.
func TestTooManyLocalAttemptsEndsTheWindow(t *testing.T) {
	h, _, _ := newTestHost(t, Config{})
	p, err := h.Pair(context.Background(), PairOptions{TTL: MaxTTL})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	port := make(chan int, 1)
	errc := make(chan error, 1)
	opts := LocalOptions{Service: "_tailpocket-demo._tcp",
		Bindings:  []connectlocal.Binding{{IP: net.IPv4(127, 0, 0, 1).To4(), Mask: net.CIDRMask(8, 32)}},
		Advertise: func(s connectmdns.Service) (func(), error) { port <- s.Port; return func() {}, nil },
		Confirm:   func(context.Context, string, string) bool { return false }}
	go func() { errc <- p.ServeLocal(ctx, opts) }()
	at := <-port
	for _, src := range []string{"127.0.0.2", "127.0.0.3", "127.0.0.4"} {
		for try := 0; try < 100 && !abandonedKey(src, at); try++ {
			time.Sleep(5 * time.Millisecond)
		}
	}
	if err := <-errc; !errors.Is(err, connectlocal.ErrTooManyAttempts) {
		t.Fatalf("ServeLocal: %v, want ErrTooManyAttempts", err)
	}
	select {
	case <-p.ended:
	case <-time.After(3 * time.Second):
		t.Fatal("the pairing window stayed open after its same-Wi-Fi attempts ran out")
	}
	if err := p.ServeLocal(ctx, opts); !errors.Is(err, ErrLocalUsed) {
		t.Fatalf("second ServeLocal: %v, want ErrLocalUsed", err)
	}
}
