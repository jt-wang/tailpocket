package connecthost

// Audit, push-phone review (d2c0020): "a phone never chooses where the host connects: its gateway
// must be one of Config.PushGateways". The host compares a phone's gateway URL with its list after
// strings.ToLower, and then dials the phone's own string. ToLower is Unicode-aware: U+0130 (İ)
// becomes ASCII "i", so "https://push.jİngtao.io" passes for "https://push.jingtao.io". The HTTP
// client then turns that host into its IDNA form, push.xn--jingtao-7he.io, a different domain, and
// sends the phone's handle and every sealed note there. A paired phone can so point the computer at
// a server of its choice whenever the gateway's host name has an "i" in it. (U+212A, the Kelvin
// sign, is accepted for "k" the same way, but IDNA maps it back to "k", so that one reaches the
// configured host: the third case is a control and passes.)
//
// The fix is structural: dial the configured string, never the phone's.

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"testing"

	"github.com/jt-wang/tailpocket/connectpush"
)

func TestAuditPhoneGatewayLookalikeIsDialed(t *testing.T) {
	for _, c := range []struct{ configured, want, lookalike string }{
		{"https://push.jingtao.io", "push.jingtao.io:443", "https://push.j\u0130ngtao.io"},
		{"https://push.jingtao.io", "push.jingtao.io:443", "https://push.jingtao.\u0130o"},
		{"https://push.kite.example", "push.kite.example:443", "https://push.\u212Aite.example"},
	} {
		t.Run(c.lookalike, func(t *testing.T) {
			var mu sync.Mutex
			var dialed []string
			hc := &http.Client{Transport: &http.Transport{DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
				mu.Lock()
				dialed = append(dialed, addr)
				mu.Unlock()
				return nil, errors.New("audit: no network in this test")
			}}}
			_, phone := phoneKey(t)
			h, f, _ := newTestHost(t, Config{Allowed: []string{phone}, PushGateways: []string{c.configured}, PushClient: hc})
			main := f.live(DefaultPort)

			// Control: an unrelated gateway is refused.
			if code, body := postPush(t, main, phone, map[string]any{"target": target("https://evil.example")}); code != http.StatusBadRequest {
				t.Fatalf("control: unrelated gateway: %d %s", code, body)
			}
			code, body := postPush(t, main, phone, map[string]any{"target": target(c.lookalike)})
			if code != http.StatusOK {
				t.Logf("refused: %d %s", code, body)
				return
			}
			_ = h.Push(context.Background(), phone, connectpush.Note{Body: "x"}, connectpush.SendOptions{})
			mu.Lock()
			defer mu.Unlock()
			if len(dialed) == 0 {
				t.Errorf("the host took %q as %s", c.lookalike, c.configured)
			}
			for _, addr := range dialed {
				if addr != c.want {
					t.Errorf("the phone gave gateway %q, the host took it as %s and connected to %s", c.lookalike, c.configured, addr)
				}
			}
		})
	}
}
