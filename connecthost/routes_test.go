package connecthost

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jt-wang/tailpocket/connectinvite"
	"github.com/jt-wang/tailpocket/connectphone"
)

// Config.Routes (v0.3.2): every contradiction is refused with ErrInvalidRoutes and a message that
// names it; the configurations from before v0.3.2 are unchanged.
func TestRoutesConfig(t *testing.T) {
	ok := func(State) error { return nil }
	relays := []Relay{{URL: "wss://relay.example", Token: "t"}}
	for name, tc := range map[string]struct {
		cfg  Config
		want string
	}{
		"empty":                    {Config{Routes: []string{}}, "Routes is empty"},
		"unknown":                  {Config{Routes: []string{"wifi"}}, `unknown route "wifi"`},
		"twice":                    {Config{Routes: []string{RouteLAN, RouteLAN}}, "twice"},
		"relay without relays":     {Config{Routes: []string{RouteRelay}}, "Relays is empty"},
		"relays without relay":     {Config{Routes: []string{RouteLAN}, Relays: relays}, "Routes has no relay"},
		"listen without lan":       {Config{Routes: []string{RouteTailcat}, Listen: []string{"203.0.113.20:7681"}}, "Routes has no lan"},
		"with tailcat-only":        {Config{Routes: []string{RouteTailcat}, TailcatOnly: true}, "set Routes alone"},
		"with nolan":               {Config{Routes: []string{RouteTailcat}, NoLAN: true}, "set Routes alone"},
		"derp map without tailcat": {Config{Routes: []string{RouteLAN}, DERPMapURL: "https://derp.example/map.json"}, "DERPMapURL"},
		"tailcat-only with relay":  {Config{TailcatOnly: true, Relays: relays}, "TailcatOnly takes no Relays"},
		"nolan with listen":        {Config{NoLAN: true, Listen: []string{"203.0.113.20:7681"}}, "NoLAN with Listen"},
	} {
		tc.cfg.Save = ok
		_, err := New(tc.cfg)
		if !errors.Is(err, ErrInvalidRoutes) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want ErrInvalidRoutes mentioning %q", name, err, tc.want)
		}
	}
	for name, tc := range map[string]struct {
		cfg          Config
		tailcat, lan bool
	}{
		"default (v0.3.1)": {Config{}, true, true},
		"nolan":            {Config{NoLAN: true}, true, false},
		"tailcat-only":     {Config{TailcatOnly: true}, true, false},
		"lan only":         {Config{Routes: []string{RouteLAN}}, false, true},
		"relay only":       {Config{Routes: []string{RouteRelay}, Relays: relays}, false, false},
		"all three":        {Config{Routes: []string{RouteRelay, RouteTailcat, RouteLAN}, Relays: relays}, true, true},
	} {
		tc.cfg.Save = ok
		h, err := New(tc.cfg)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if h.tailcat != tc.tailcat || h.autoLANOn != tc.lan {
			t.Errorf("%s: tailcat %v lan %v, want %v %v", name, h.tailcat, h.autoLANOn, tc.tailcat, tc.lan)
		}
		h.Close()
	}
}

func types(rs []connectinvite.Route) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.T)
	}
	slices.Sort(out)
	return out
}

// Every subset of the routes, end to end on one machine: what the invite and routes list, whether a
// Tailcat node ever starts, pairing with the emoji over each subset's route, a connection, revoke and
// a bounded Close. Tailcat itself is the fake network here; a host without it must start no node.
func TestRouteSubsets(t *testing.T) {
	for _, set := range [][]string{
		{RouteTailcat}, {RouteLAN}, {RouteRelay}, {RouteTailcat, RouteLAN}, {RouteTailcat, RouteRelay},
		{RouteLAN, RouteRelay}, {RouteTailcat, RouteLAN, RouteRelay},
	} {
		t.Run(strings.Join(set, "+"), func(t *testing.T) {
			noUpgrade(t)
			has := func(r string) bool { return slices.Contains(set, r) }
			cfg := Config{Routes: set}
			if has(RouteRelay) {
				cfg.Relays = []Relay{{URL: startRelay(t), Token: relayToken}}
			}
			if has(RouteLAN) {
				cfg.Listen = []string{freeAddr(t)}
			}
			h, f, _ := newTestHost(t, cfg)
			if has(RouteRelay) {
				waitRelay(t, h)
			}
			serveApp(t, h)
			var emoji []string
			p, err := h.Pair(context.Background(), PairOptions{Confirm: func(_ context.Context, r PairRequest) bool {
				emoji = r.Emoji
				return true
			}})
			if err != nil {
				t.Fatal(err)
			}
			inv := p.InviteV2()
			if got := types(inv.Via); !slices.Equal(got, slices.Sorted(slices.Values(set))) {
				t.Fatalf("invite lists %v, want %v", got, set)
			}
			if _, err := p.QR2(connectinvite.DefaultPrefix2); err != nil {
				t.Fatalf("QR2: %v", err)
			}
			if _, err := p.QR(connectinvite.DefaultPrefix); has(RouteTailcat) != (err == nil) {
				t.Fatalf("QR (v1): %v", err)
			}
			if !has(RouteTailcat) {
				if err := p.ServeLocal(context.Background(), LocalOptions{Service: "_x._tcp", Confirm: func(context.Context, string, string) bool { return true }}); !errors.Is(err, ErrNoTailcat) {
					t.Fatalf("ServeLocal without Tailcat: %v", err)
				}
			}
			if len(f.nodes) != map[bool]int{true: 1, false: 0}[has(RouteTailcat)] {
				t.Fatalf("%d Tailcat nodes after Pair", len(f.nodes))
			}
			if has(RouteTailcat) && !has(RouteLAN) && !has(RouteRelay) {
				return // pairing over the fake Tailcat window: emoji_test.go
			}

			// The phone allows only the host's encrypted routes, so it never touches the fake Tailcat.
			phoneRoutes := slices.DeleteFunc(slices.Clone(set), func(r string) bool { return r == RouteTailcat })
			w := &wire{}
			opts := connectphone.Options{Device: "Phone", OnSAS: func([]string) {}, HTTPClient: w.client(), Routes: phoneRoutes}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			phoneKey := connectphone.NewKey()
			link, err := connectphone.PairV2(ctx, inv, phoneKey, opts)
			if err != nil {
				t.Fatalf("PairV2: %v", err)
			}
			if len(emoji) != 4 {
				t.Fatalf("emoji %v", emoji)
			}
			if has(RouteTailcat) != (link.Address != "") {
				t.Fatalf("link Tailcat address %q", link.Address)
			}
			if got := types(h.Routes()); !slices.Equal(got, slices.Sorted(slices.Values(set))) {
				t.Fatalf("routes after pairing %v, want %v", got, set)
			}
			if !has(RouteTailcat) && (h.Address() != "" || len(f.nodes) != 0) {
				t.Fatalf("host without Tailcat: address %q, %d nodes", h.Address(), len(f.nodes))
			}
			s, err := connectphone.Connect(link, opts)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			pub, _ := connectphone.PublicKey(phoneKey)
			if body, err := get(t, s); err != nil || body != pub+" "+marker {
				t.Fatalf("connection: %q %v", body, err)
			}
			r, err := s.Route(context.Background())
			// The first route the link lists answers, and noUpgrade keeps the session there.
			if want := link.Via[0].T; err != nil || r.Kind != want {
				t.Fatalf("Route %+v %v, want %s", r, err, want)
			}
			if _, err := s.Sync(context.Background()); err != nil && !has(RouteTailcat) {
				t.Fatalf("Sync without Tailcat: %v", err)
			}

			// Revoke reaches the phone, encrypted, on its route.
			if err := h.Revoke(context.Background(), pub); err != nil {
				t.Fatal(err)
			}
			for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
				_, err := get(t, s)
				if errors.Is(err, connectphone.ErrRevoked) {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("revoked phone: %v, want ErrRevoked", err)
				}
			}
			start := time.Now()
			if err := h.Close(); err != nil {
				t.Fatal(err)
			}
			if d := time.Since(start); d > 5*time.Second {
				t.Fatalf("Close took %v", d)
			}
			if !has(RouteTailcat) && len(f.nodes) != 0 {
				t.Fatalf("a host without Tailcat started %d nodes", len(f.nodes))
			}
		})
	}
}

// LAN and relay without Tailcat: a phone that reached the host over the relay moves to lan in the
// background, as with Tailcat.
func TestUpgradeWithoutTailcat(t *testing.T) {
	h, f, _ := newTestHost(t, Config{Routes: []string{RouteRelay, RouteLAN}, Relays: []Relay{{URL: startRelay(t), Token: relayToken}}, Listen: []string{freeAddr(t)}})
	waitRelay(t, h)
	serveApp(t, h)
	p, err := h.Pair(context.Background(), PairOptions{Confirm: confirmAll})
	if err != nil {
		t.Fatal(err)
	}
	opts := connectphone.Options{OnSAS: func([]string) {}}
	link, err := connectphone.PairV2(context.Background(), relayOnly(p.InviteV2()), connectphone.NewKey(), opts)
	if err != nil {
		t.Fatal(err)
	}
	// The relay first, as a phone off the Wi-Fi would.
	slices.SortStableFunc(link.Via, func(a, b connectinvite.Route) int { return strings.Compare(b.T, a.T) })
	s, err := connectphone.Connect(link, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := get(t, s); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if r, _ := s.Route(context.Background()); r.Kind == connectphone.KindLAN {
			break
		}
		if time.Now().After(deadline) {
			r, err := s.Route(context.Background())
			t.Fatalf("still on %+v %v", r, err)
		}
	}
	if len(f.nodes) != 0 {
		t.Fatalf("%d Tailcat nodes", len(f.nodes))
	}
}

// A host without Tailcat restarted without State.Keys: its phone is told unpaired, and pairing again
// with the same phone key works (before, the host still listed the phone and refused the pairing).
func TestRepairAfterLostKeysWithoutTailcat(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	addr := freeAddr(t)
	h, _, sv := newTestHost(t, Config{Routes: []string{RouteLAN}, Listen: []string{addr}})
	p, err := h.Pair(ctx, PairOptions{Confirm: confirmAll})
	if err != nil {
		t.Fatal(err)
	}
	opts := connectphone.Options{OnSAS: func([]string) {}, Routes: []string{RouteLAN}}
	key := connectphone.NewKey()
	link, err := connectphone.PairV2(ctx, p.InviteV2(), key, opts)
	if err != nil {
		t.Fatal(err)
	}
	st := sv.last()
	h.Close()
	h2, _, sv2 := newTestHost(t, Config{Routes: []string{RouteLAN}, Listen: []string{addr}, Identity: st.Identity, Allowed: st.Allowed})
	serveApp(t, h2)
	if len(h2.Allowed()) != 0 || len(sv2.last().Allowed) != 0 {
		t.Fatalf("a phone without a key is still allowed: %v, saved %v", h2.Allowed(), sv2.last().Allowed)
	}
	s, err := connectphone.Connect(link, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := get(t, s); !errors.Is(err, connectphone.ErrRevoked) {
		t.Fatalf("phone without a key on the host: %v, want ErrRevoked", err)
	}
	p2, err := h2.Pair(ctx, PairOptions{Confirm: confirmAll})
	if err != nil {
		t.Fatal(err)
	}
	link2, err := connectphone.PairV2(ctx, p2.InviteV2(), key, opts)
	if err != nil {
		t.Fatalf("pairing again with the same key: %v", err)
	}
	s2, _ := connectphone.Connect(link2, opts)
	defer s2.Close()
	if _, err := get(t, s2); err != nil {
		t.Fatalf("after pairing again: %v", err)
	}
}

// On a host without Tailcat, SetAllowed keeps only phones whose Noise key it holds: a phone given
// without one could reach it on no route and could not pair again.
func TestSetAllowedWithoutTailcatNeedsAKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	h, _, _ := newTestHost(t, Config{Routes: []string{RouteLAN}, Listen: []string{freeAddr(t)}})
	serveApp(t, h)
	key := connectphone.NewKey()
	pub, _ := connectphone.PublicKey(key)
	if err := h.SetAllowed(ctx, []string{pub}); err != nil {
		t.Fatal(err)
	}
	if len(h.Allowed()) != 0 {
		t.Fatalf("SetAllowed kept a phone without a key: %v", h.Allowed())
	}
	p, err := h.Pair(ctx, PairOptions{Confirm: confirmAll})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connectphone.PairV2(ctx, p.InviteV2(), key, connectphone.Options{OnSAS: func([]string) {}, Routes: []string{RouteLAN}}); err != nil {
		t.Fatalf("pairing after SetAllowed: %v", err)
	}
	if err := h.SetAllowed(ctx, []string{pub}); err != nil || len(h.Allowed()) != 1 {
		t.Fatalf("SetAllowed dropped a phone with a key: %v %v", err, h.Allowed())
	}
}
