package connectmobile

import (
	"encoding/json"
	"slices"
	"testing"
)

// Audit v0.3.2 (42d9679), finding 2. SetRoutes("") is documented as "allows every route again" and as
// turning SetTailcatOnly off ("the last of the two calls decides"), and every binding documents
// setRoutes(null) the same way. After SetTailcatOnly(true) it clears only the route list: the phone
// stays Tailcat only, so an app that moves a user from "Tailcat only" back to "every route" with
// setRoutes(null) keeps a phone that cannot use a host that runs lan or relay only (a host without
// Tailcat is unreachable: "no route to pair over").
func TestAuditV032SetRoutesNullAllowsEveryRouteAgain(t *testing.T) {
	defer SetRoutes("")
	defer SetTailcatOnly(false)
	SetTailcatOnly(true)
	if got := SetRoutes(""); got != "" {
		t.Fatalf("SetRoutes(\"\") = %q", got)
	}
	if only, routes := prefs(); only || routes != nil {
		t.Fatalf("after SetTailcatOnly(true), SetRoutes(\"\"): tailcatOnly %v routes %v, want every route", only, routes)
	}
	// The other orders, as documented.
	SetRoutes("lan")
	SetTailcatOnly(true)
	if only, routes := prefs(); !only || routes != nil {
		t.Fatalf("SetRoutes then SetTailcatOnly(true): %v %v", only, routes)
	}
	SetRoutes("lan,relay")
	if only, routes := prefs(); only || !slices.Equal(routes, []string{"lan", "relay"}) {
		t.Fatalf("SetTailcatOnly(true) then SetRoutes: %v %v", only, routes)
	}
	// SetTailcatOnly(false) is not a route choice: it leaves the list alone.
	SetTailcatOnly(false)
	if only, routes := prefs(); only || !slices.Equal(routes, []string{"lan", "relay"}) {
		t.Fatalf("SetTailcatOnly(false) changed the routes: %v %v", only, routes)
	}
	// A refused list changes nothing: the phone keeps the narrower set it had.
	if got := SetRoutes("lan,wifi"); got != `{"error":"invalid-routes"}` {
		t.Fatalf("SetRoutes(lan,wifi) = %q", got)
	}
	if only, routes := prefs(); only || !slices.Equal(routes, []string{"lan", "relay"}) {
		t.Fatalf("a refused SetRoutes changed the setting: %v %v", only, routes)
	}
}

// prefs() (the earlier review's lock): while SetRoutes and SetTailcatOnly race, a reader never sees
// both settings at once, which connectphone refuses (ErrInvalidRoutes: Connect would answer
// invalid-link for a valid link) and never sees a list that was not set. Run with -race.
func TestAuditV032PrefsNeverYieldsBothSettings(t *testing.T) {
	defer SetRoutes("")
	defer SetTailcatOnly(false)
	stop := make(chan struct{})
	done := make(chan struct{}, 3)
	go func() {
		for i := 0; ; i++ {
			select {
			case <-stop:
				done <- struct{}{}
				return
			default:
			}
			SetRoutes([]string{"lan", "lan,relay", "relay", ""}[i%4])
		}
	}()
	go func() {
		for i := 0; ; i++ {
			select {
			case <-stop:
				done <- struct{}{}
				return
			default:
			}
			SetTailcatOnly(i%2 == 0)
		}
	}()
	link := `{"address":"` + testAddress(t) + `","port":48931,"name":"Mac","key":"` + NewKey() + `"}`
	for i := 0; i < 20000; i++ {
		only, routes := prefs()
		if only && routes != nil {
			t.Fatalf("prefs: TailcatOnly with routes %v", routes)
		}
		if routes != nil && !slices.Equal(routes, []string{"lan"}) && !slices.Equal(routes, []string{"lan", "relay"}) && !slices.Equal(routes, []string{"relay"}) {
			t.Fatalf("prefs: routes %v", routes)
		}
		if i%500 == 0 {
			out := Connect(link, "")
			var h struct {
				Handle int64  `json:"handle"`
				Error  string `json:"error"`
			}
			_ = json.Unmarshal([]byte(out), &h)
			if h.Error != "" {
				t.Fatalf("Connect while the settings change: %s", out)
			}
			Stop(h.Handle)
		}
	}
	close(stop)
	<-done
	<-done
}
