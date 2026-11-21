package connectphone

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/jt-wang/tailpocket/connectinvite"
	"github.com/jt-wang/tailpocket/internal/testhook"
)

// A phone set to Tailcat only never dials the relay or lan routes a host lists, takes none from the
// host, and registers no Noise key.
func TestTailcatOnlyPhone(t *testing.T) {
	via := []connectinvite.Route{{T: connectinvite.RouteRelay, U: "wss://relay.example", R: "AAAAAAAAAAAAAAAAAAAAAA"},
		{T: connectinvite.RouteLAN, A: []string{"192.168.1.20:7681"}}}
	link := Link{Address: testAddress(t), Port: 48931, Name: "Mac", Key: NewKey(), HostKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Via: via}
	s, err := Connect(link, Options{TailcatOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.mu.Lock()
	got := s.attemptsLocked()
	s.mu.Unlock()
	if len(got) != 1 || got[0].T != connectinvite.RouteTailcat {
		t.Fatalf("Tailcat-only phone tries %+v", got)
	}
	// Control: the same link without the preference tries all three.
	s2, _ := Connect(link, Options{})
	defer s2.Close()
	s2.mu.Lock()
	if n := len(s2.attemptsLocked()); n != 3 {
		t.Fatalf("control: %d routes", n)
	}
	s2.mu.Unlock()
	if l, err := s.Sync(context.Background()); err != nil || len(l.Via) != len(via) {
		t.Fatalf("Sync on a Tailcat-only phone: %v %+v", err, l)
	}

	// Pairing with an invite that has only relay and lan routes finds nothing it may use.
	inv := connectinvite.V2{Version: connectinvite.Version2, Name: "Mac", ExpiresAt: 1 << 40,
		PK: link.HostKey, PSK: connectinvite.NewCode(), Via: via}
	if _, err := PairV2(context.Background(), inv, NewKey(), Options{TailcatOnly: true, OnSAS: func([]string) {}}); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("Tailcat-only PairV2 over relay/lan routes: %v", err)
	}
}

func TestPairV2NeedsOnSAS(t *testing.T) {
	inv := connectinvite.V2{Version: connectinvite.Version2, Name: "Mac", ExpiresAt: 1 << 40,
		PK: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", PSK: connectinvite.NewCode(),
		Via: []connectinvite.Route{{T: connectinvite.RouteLAN, A: []string{"192.168.1.20:7681"}}}}
	if _, err := PairV2(context.Background(), inv, NewKey(), Options{}); !errors.Is(err, ErrNoSAS) {
		t.Fatalf("PairV2 without OnSAS: %v", err)
	}
}

// Options.Routes (v0.3.2): a phone without tailcat creates no Tailcat client, even for a link and an
// invite that list Tailcat, and tries only the route types it allows. Bad lists are refused.
func TestRoutesPhone(t *testing.T) {
	via := []connectinvite.Route{{T: connectinvite.RouteRelay, U: "wss://relay.example", R: "AAAAAAAAAAAAAAAAAAAAAA"},
		{T: connectinvite.RouteLAN, A: []string{"192.168.1.20:7681"}}}
	link := Link{Address: testAddress(t), Port: 48931, Name: "Mac", Key: NewKey(), HostKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Via: via}
	for name, tc := range map[string]struct {
		routes []string
		want   []string
	}{
		"lan":         {[]string{connectinvite.RouteLAN}, []string{connectinvite.RouteLAN}},
		"relay":       {[]string{connectinvite.RouteRelay}, []string{connectinvite.RouteRelay}},
		"lan+relay":   {[]string{connectinvite.RouteLAN, connectinvite.RouteRelay}, []string{connectinvite.RouteRelay, connectinvite.RouteLAN}},
		"tailcat+lan": {[]string{connectinvite.RouteTailcat, connectinvite.RouteLAN}, []string{connectinvite.RouteTailcat, connectinvite.RouteLAN}},
		"all (nil)":   {nil, []string{connectinvite.RouteTailcat, connectinvite.RouteRelay, connectinvite.RouteLAN}},
	} {
		starts := testhook.TailcatStarts.Load()
		s, err := Connect(link, Options{Routes: tc.routes})
		if err != nil {
			t.Fatal(err)
		}
		s.mu.Lock()
		var got []string
		for _, r := range s.attemptsLocked() {
			got = append(got, r.T)
		}
		s.mu.Unlock()
		s.Close()
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: tries %v, want %v", name, got, tc.want)
		}
		if made := testhook.TailcatStarts.Load() - starts; (made > 0) != slices.Contains(tc.want, connectinvite.RouteTailcat) {
			t.Errorf("%s: %d Tailcat clients", name, made)
		}
	}
	for name, o := range map[string]Options{
		"empty":   {Routes: []string{}},
		"unknown": {Routes: []string{"wifi"}},
		"twice":   {Routes: []string{"lan", "lan"}},
		"both":    {Routes: []string{"lan"}, TailcatOnly: true},
	} {
		if _, err := Connect(link, o); !errors.Is(err, ErrInvalidRoutes) {
			t.Errorf("%s: %v, want ErrInvalidRoutes", name, err)
		}
	}
	// A v1 invite pairs over Tailcat only: refused at once without a client.
	starts := testhook.TailcatStarts.Load()
	v1 := connectinvite.Invite{Version: connectinvite.Version, Address: testAddress(t), Port: 48932, Key: NewKey(),
		Proof: connectinvite.NewProof(), ExpiresAt: 1 << 40, Name: "Mac"}
	if _, err := Pair(context.Background(), v1, NewKey(), Options{Routes: []string{"lan"}}); !errors.Is(err, ErrUnreachable) {
		t.Errorf("v1 Pair without Tailcat: %v", err)
	}
	if testhook.TailcatStarts.Load() != starts {
		t.Error("v1 Pair without Tailcat made a client")
	}
}
