package connectphone

import (
	"context"
	"errors"
	"testing"

	"github.com/jt-wang/tailpocket/connectinvite"
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
