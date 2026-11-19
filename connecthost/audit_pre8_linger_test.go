package connecthost

// Audit, pre.8 review (8371b6f): after the computer's user says no, the pairing window ends at once
// but its one-time Tailcat node now stays up for byeLinger (3 s), so the bye reaches the phone.
//
// TestAuditLingeringNodePairsNobody: what that node still does for the holder of the invite during
// those 3 s. It must be nothing: no Noise pairing, no v1 /pair, no second question to the user.
//
// TestAuditHostCloseLeavesRefusedWindowNode: Host.Close and Pairing.Close after a refusal. The
// refusal already ran the window's end (endOnce) and took it out of the host's pairings, so neither
// reaches the node any more: it keeps running until the timer fires, after Host.Close has returned.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/types/key"

	"github.com/jt-wang/tailpocket/connectsecure"
)

func refusedWindow(t *testing.T, asked *atomic.Int32) (*Host, *Pairing, *fakeNode) {
	t.Helper()
	h, f, _ := newTestHost(t, Config{TailcatOnly: true})
	p, err := h.Pair(context.Background(), PairOptions{Confirm: func(context.Context, PairRequest) bool {
		asked.Add(1)
		return false
	}})
	if err != nil {
		t.Fatal(err)
	}
	node := pairingNode(t, f)
	if _, err := noisePairOverTailcat(t, node, p.InviteV2(), key.NewNode(), func([]string) {}); !errors.Is(err, connectsecure.ErrDenied) {
		t.Fatalf("refused pairing: %v, want ErrDenied", err)
	}
	select {
	case <-p.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the window stayed open after the refusal")
	}
	return h, p, node
}

func nodeClosed(n *fakeNode) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.closed
}

func TestAuditLingeringNodePairsNobody(t *testing.T) {
	var asked atomic.Int32
	h, p, node := refusedWindow(t, &asked)
	if nodeClosed(node) {
		t.Skip("the node closed with the window: nothing lingers")
	}
	inv := p.InviteV2()
	// The same code again, over the node that is still up.
	for i := 0; i < 3; i++ {
		if _, err := noisePairOverTailcat(t, node, inv, key.NewNode(), func([]string) {}); err == nil {
			t.Fatal("the code paired a phone over the lingering node")
		}
	}
	// v1 /pair with the window's proof.
	v1 := *inv.Via[0].Inv
	_, phone := phoneKey(t)
	// The window's HTTP server is closed: the request must end without a 200 (an error counts).
	done := make(chan int, 1)
	go func() {
		body := fmt.Sprintf(`{"phoneKey":%q,"device":"Mallory"}`, phone)
		req, _ := http.NewRequest(http.MethodPost, "http://pairing.invalid/pair", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+v1.Proof)
		resp, err := client(node, uint16(v1.Port)).Do(req)
		if err != nil {
			done <- 0
			return
		}
		resp.Body.Close()
		done <- resp.StatusCode
	}()
	select {
	case code := <-done:
		t.Logf("/pair on the lingering node: status %d (0 is a closed connection)", code)
		if code == http.StatusOK {
			t.Fatal("/pair answered 200 on the lingering node")
		}
	case <-time.After(byeLinger + 2*time.Second):
		t.Fatal("/pair on the lingering node neither answered nor closed")
	}
	if n := asked.Load(); n != 1 {
		t.Fatalf("the user was asked %d times; the refusal was the last question this window may ask", n)
	}
	h.mu.Lock()
	phones := len(h.allowed)
	h.mu.Unlock()
	if phones != 0 {
		t.Fatalf("%d phones paired", phones)
	}
}

func TestAuditHostCloseLeavesRefusedWindowNode(t *testing.T) {
	var asked atomic.Int32
	h, p, node := refusedWindow(t, &asked)
	p.Close()
	afterPairingClose := nodeClosed(node)
	_ = h.Close()
	afterHostClose := nodeClosed(node)
	start := time.Now()
	for !nodeClosed(node) && time.Since(start) < byeLinger+2*time.Second {
		time.Sleep(20 * time.Millisecond)
	}
	t.Logf("window's node closed: after Pairing.Close %v, after Host.Close %v, by itself %v later",
		afterPairingClose, afterHostClose, time.Since(start).Round(100*time.Millisecond))
	if !afterHostClose {
		t.Fatalf("Host.Close returned while the refused window's Tailcat node was still running (it closed %v later)",
			time.Since(start).Round(100*time.Millisecond))
	}
}
