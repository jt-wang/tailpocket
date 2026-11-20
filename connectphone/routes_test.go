package connectphone

import (
	"testing"

	"github.com/tailscale/tailcat"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// A pong names the route exactly: direct, or DERP with the region the address carries (the code
// tailcat makes up is dropped, the host name comes from the address), or DERP from the fetched map.
func TestRouteOfPong(t *testing.T) {
	ci := tailcat.ConnInfo{
		ServerPublic: tailcat.NodePublic{NodePublic: key.NewNode().Public()},
		Region: []*tailcfg.DERPRegion{
			{Nodes: []*tailcfg.DERPNode{{HostName: "derp-a.example.com"}}},
			{Nodes: []*tailcfg.DERPNode{{HostName: "derp-b.example.com"}, {HostName: "derp-b2.example.com"}}},
		},
	}
	embedded := string(ci.Addr())
	byID := string((&tailcat.ConnInfo{ServerPublic: ci.ServerPublic, RegionID: 7}).Addr())
	for _, c := range []struct {
		name    string
		res     ipnstate.PingResult
		address string
		want    Route
		path    [2]string
	}{
		{"direct", ipnstate.PingResult{Endpoint: "203.0.113.20:41641", DERPRegionID: 2, DERPRegionCode: "2"}, embedded,
			Route{Kind: KindDirect}, [2]string{"direct", ""}},
		{"derp from the address", ipnstate.PingResult{DERPRegionID: 2, DERPRegionCode: "2"}, embedded,
			Route{Kind: KindDERP, DERPRegion: 2, DERPHost: "derp-b.example.com"}, [2]string{"relay", "derp-b.example.com"}},
		{"derp from the map", ipnstate.PingResult{DERPRegionID: 7, DERPRegionCode: "nyc"}, byID,
			Route{Kind: KindDERP, DERPRegion: 7, DERPCode: "nyc"}, [2]string{"relay", "nyc"}},
	} {
		got, err := routeOf(&c.res, nil, c.address)
		if err != nil || got != c.want {
			t.Errorf("%s: %+v %v, want %+v", c.name, got, err, c.want)
		}
		if r, rel := got.Path(); [2]string{r, rel} != c.path {
			t.Errorf("%s: Path %q %q, want %q", c.name, r, rel, c.path)
		}
	}
	if r, rel := (Route{Kind: KindDERP, DERPRegion: 9}).Path(); r != "relay" || rel != "tailcat-derp" {
		t.Errorf("derp without code or host: Path %q %q", r, rel)
	}
	if r, rel := (Route{Kind: KindRelay, RelayHost: "relay.example.com"}).Path(); r != "relay" || rel != "relay.example.com" {
		t.Errorf("relay Path %q %q", r, rel)
	}
}
