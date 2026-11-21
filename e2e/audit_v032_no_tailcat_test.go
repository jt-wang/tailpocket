package e2e

// Audit of v0.3.2 (42d9679): the "no Tailcat" claim through the layer the phone apps ship
// (connectmobile, which the Swift, Kotlin, NSH and React Native bindings call), and through the
// host's automatic lan route, which TestNoTailcat* does not run (it gives Listen a loopback address).
// The names start with TestNoTailcat so scripts/e2e-no-tailcat.sh counts their packets too.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/jt-wang/tailpocket/connecthost"
	"github.com/jt-wang/tailpocket/connectinvite"
	"github.com/jt-wang/tailpocket/connectmobile"
	"github.com/jt-wang/tailpocket/connectphone"
	"github.com/jt-wang/tailpocket/internal/testhook"
)

// decoyAddress is a well-formed Tailcat address of a server that does not exist. Its DERP node has a
// name, so a Tailcat client started for it would ask DNS for it: a packet the iptables count sees.
func decoyAddress() string {
	ci := tailcat.ConnInfo{
		ServerPublic:      tailcat.NodePublic{NodePublic: key.NewNode().Public()},
		ServerDiscoPublic: tailcat.DiscoPublic{DiscoPublic: key.NewDisco().Public()},
		PresharedKey:      tailcat.NewPresharedKey(),
		Region:            []*tailcfg.DERPRegion{{RegionID: 900, Nodes: []*tailcfg.DERPNode{{Name: "900a", RegionID: 900, HostName: "derp.audit-v032.example.com"}}}},
	}
	return string(ci.Addr())
}

func mobileError(s string) string {
	var v struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal([]byte(s), &v)
	return v.Error
}

// A phone app that called setRoutes(["lan","relay"]) pairs with the emoji (the same four on both
// ends), connects, reads its route, syncs and hears a revoke, all through connectmobile, and creates
// no Tailcat client: not for an invite whose first route is a Tailcat window, not for a link that
// carries a Tailcat address, not for a v1 invite (refused).
func TestNoTailcatAuditMobileLayer(t *testing.T) {
	checkHome := noTailcatHome(t)
	checkSockets := noTailcatSockets(t)
	starts := testhook.TailcatStarts.Load()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	st := &store{}
	h, err := connecthost.New(connecthost.Config{Name: "audit", Save: st.save,
		Routes: []string{connectinvite.RouteLAN, connectinvite.RouteRelay}, Listen: []string{freeLoopback(t)},
		Relays: []connecthost.Relay{{URL: localRelay(t), Token: "e2e-relay-token"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if err := h.Start(ctx); err != nil {
		t.Fatal(err)
	}
	serveEcho(h)

	if out := connectmobile.SetRoutes("lan,relay"); out != "" {
		t.Fatalf("SetRoutes: %s", out)
	}
	defer connectmobile.SetRoutes("")

	hostEmoji, approve := make(chan []string, 1), make(chan bool, 1)
	p, err := h.Pair(ctx, connecthost.PairOptions{Confirm: func(_ context.Context, r connecthost.PairRequest) bool {
		hostEmoji <- r.Emoji
		return <-approve
	}})
	if err != nil {
		t.Fatal(err)
	}
	inv := p.InviteV2()
	// As a host that also runs Tailcat would list it: first, with its pairing window.
	decoy := connectinvite.Invite{Version: connectinvite.Version, Address: decoyAddress(), Port: 48932, Key: connectphone.NewKey(),
		Proof: connectinvite.NewProof(), ExpiresAt: inv.ExpiresAt, Name: inv.Name}
	inv.Via = append([]connectinvite.Route{{T: connectinvite.RouteTailcat, Inv: &decoy}}, inv.Via...)
	if err := inv.Validate(); err != nil {
		t.Fatal(err)
	}
	invJSON, _ := json.Marshal(inv)
	phoneKey := connectmobile.NewKey()
	pub := connectmobile.PublicKey(phoneKey)

	out := connectmobile.Pair2(71, string(invJSON), phoneKey, "Audit phone", "", 20000)
	var shown struct {
		Emoji []string `json:"emoji"`
	}
	if json.Unmarshal([]byte(out), &shown) != nil || len(shown.Emoji) != 4 {
		t.Fatalf("Pair2: %s", out)
	}
	select {
	case e := <-hostEmoji:
		if !slices.Equal(e, shown.Emoji) {
			t.Fatalf("the computer shows %v, the phone %v", e, shown.Emoji)
		}
	case <-ctx.Done():
		t.Fatal("the computer never asked")
	}
	approve <- true
	linkJSON := connectmobile.Pair2Finish(71, 20000)
	var link map[string]any
	if json.Unmarshal([]byte(linkJSON), &link) != nil || link["error"] != nil || link["address"] != nil || link["pk"] != inv.PK {
		t.Fatalf("link: %s", linkJSON)
	}

	// A v1 invite pairs over Tailcat only: refused, no client.
	v1JSON, _ := json.Marshal(decoy)
	if got := mobileError(connectmobile.Pair(72, string(v1JSON), phoneKey, "Audit phone", "", 3000)); got != "unreachable" {
		t.Fatalf("v1 Pair without Tailcat: %q", got)
	}

	// The same link as a host that runs Tailcat too would have sent it.
	link["address"], link["port"] = decoyAddress(), 48931
	withTailcat, _ := json.Marshal(link)
	var conn struct {
		Handle int64  `json:"handle"`
		Port   int    `json:"port"`
		Token  string `json:"token"`
		Error  string `json:"error"`
	}
	if json.Unmarshal([]byte(connectmobile.Connect(string(withTailcat), "")), &conn) != nil || conn.Error != "" || conn.Handle == 0 {
		t.Fatalf("Connect: %+v", conn)
	}
	defer connectmobile.Stop(conn.Handle)
	roundTrip(t, ctx, func(ctx context.Context) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(conn.Port)))
		if err != nil {
			return nil, err
		}
		if _, err := io.WriteString(c, "TP-FWD "+conn.Token+"\n"); err != nil {
			c.Close()
			return nil, err
		}
		return c, nil
	}, pub)
	var path struct {
		Kind  string `json:"kind"`
		Error string `json:"error"`
	}
	if json.Unmarshal([]byte(connectmobile.Path(conn.Handle, 3000)), &path) != nil || (path.Kind != connectphone.KindLAN && path.Kind != connectphone.KindRelay) {
		t.Fatalf("Path: %+v", path)
	}
	if got := mobileError(connectmobile.Sync(conn.Handle, 3000)); got != "" {
		t.Fatalf("Sync: %q", got)
	}
	if got := mobileError(connectmobile.Link(conn.Handle)); got != "" {
		t.Fatalf("Link: %q", got)
	}

	if err := h.Revoke(ctx, pub); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(10 * time.Second); mobileError(connectmobile.Path(conn.Handle, 1000)) != "revoked"; time.Sleep(50 * time.Millisecond) {
		if c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(conn.Port))); err == nil {
			_, _ = io.WriteString(c, "TP-FWD "+conn.Token+"\n") // a dial is what hears the bye
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			_, _ = io.Copy(io.Discard, c)
			c.Close()
		}
		if time.Now().After(deadline) {
			t.Fatalf("after revoke: %s", connectmobile.Path(conn.Handle, 1000))
		}
	}
	connectmobile.Stop(conn.Handle)
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if n := testhook.TailcatStarts.Load() - starts; n != 0 {
		t.Fatalf("%d Tailcat servers or clients created", n)
	}
	checkSockets()
	checkHome()
}

// The automatic lan route (no Listen), the default of {"routes":["lan"]}: the host listens on the
// computer's private addresses only, pairs and serves a phone there, and creates no Tailcat node.
// Its sockets are not on loopback, so only the start counter and the state check run here; the
// iptables count of scripts/e2e-no-tailcat.sh covers its packets (a connection to the machine's own
// address stays on lo).
func TestNoTailcatAuditAutoLAN(t *testing.T) {
	checkHome := noTailcatHome(t)
	starts := testhook.TailcatStarts.Load()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st := &store{}
	h, err := connecthost.New(connecthost.Config{Name: "audit", Save: st.save, Routes: []string{connectinvite.RouteLAN}})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if err := h.Start(ctx); err != nil {
		t.Fatal(err)
	}
	serveEcho(h)
	routes := h.Routes()
	if len(routes) == 0 {
		t.Skip("this machine has no private address")
	}
	if len(routes) != 1 || routes[0].T != connectinvite.RouteLAN {
		t.Fatalf("routes %+v", routes)
	}
	for _, a := range routes[0].A {
		host, _, _ := net.SplitHostPort(a)
		if ip := net.ParseIP(host); ip == nil || !ip.IsPrivate() {
			t.Fatalf("the lan route lists %s", a)
		}
	}
	p, err := h.Pair(ctx, connecthost.PairOptions{Confirm: func(context.Context, connecthost.PairRequest) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	opts := connectphone.Options{Device: "audit", Routes: []string{connectinvite.RouteLAN}, OnSAS: func([]string) {}}
	phoneKey := connectphone.NewKey()
	pub, _ := connectphone.PublicKey(phoneKey)
	link, err := connectphone.PairV2(ctx, p.InviteV2(), phoneKey, opts)
	if err != nil {
		t.Fatalf("pair over %v: %v", routes[0].A, err)
	}
	s, err := connectphone.Connect(link, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	roundTrip(t, ctx, s.Dial, pub)
	s.Close()
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if n := testhook.TailcatStarts.Load() - starts; n != 0 {
		t.Fatalf("%d Tailcat servers or clients created", n)
	}
	checkHome()
	t.Log(fmt.Sprintf("lan route %v", routes[0].A))
}
