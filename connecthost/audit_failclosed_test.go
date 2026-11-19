package connecthost

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jt-wang/tailpocket/connectphone"
	"github.com/jt-wang/tailpocket/connectrelay"
)

// Audit (fail closed), O1: on an opaque relay route the host hands every connection to the app
// without asking Authorize. The room is not a secret (the relay, every invite and every paired or
// revoked phone know it), so a stranger who never paired reaches the app's port, and so does a
// phone the host revoked. An app that set Authorize to deny everyone still gets the bytes.
func TestAuditOpaqueRelaySkipsAuthorize(t *testing.T) {
	url := startRelay(t)
	var asked atomic.Int32
	h, _, _ := newTestHost(t, Config{Relays: []Relay{{URL: url, Token: relayToken, Opaque: true, AppAuth: true}},
		Authorize: func(phone, route string) error {
			asked.Add(1)
			return errors.New("nobody is signed in")
		}})
	waitRelay(t, h)
	got := make(chan net.Conn, 1)
	go func() {
		if c, err := h.Listener().Accept(); err == nil {
			got <- c
		}
	}()

	// The stranger holds no key and no invite: only the relay URL and the room.
	room := h.Routes()[0].R
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := connectrelay.DialPhone(ctx, url, room, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	const hello = "stranger says hi\n"
	if _, err := io.WriteString(c, hello); err != nil {
		t.Fatal(err)
	}
	select {
	case app := <-got:
		defer app.Close()
		buf := make([]byte, len(hello))
		app.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _ := io.ReadFull(app, buf)
		t.Fatalf("the app got %q from a stranger on the opaque route (PhoneOf %q); Authorize, which denies everyone, ran %d times",
			buf[:n], PhoneOf(app), asked.Load())
	case <-time.After(2 * time.Second):
	}
	if asked.Load() == 0 {
		t.Fatal("Authorize never ran for the opaque connection")
	}
}

// Audit (fail closed), O1 continued: a revoked phone keeps the opaque route. Nothing tells whose an
// opaque connection is, so revoking any phone closes every open one; a new one reaches the app only
// because the app declared AppAuth, with identity "" (the app's own credential decides).
func TestAuditRevokedPhoneKeepsOpaqueRoute(t *testing.T) {
	url, opaqueURL := startRelay(t), startRelay(t)
	h, _, _ := newTestHost(t, Config{Relays: []Relay{{URL: url, Token: relayToken}, {URL: opaqueURL, Token: relayToken, Opaque: true, AppAuth: true}}})
	waitRelay(t, h)
	conns := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := h.Listener().Accept()
			if err != nil {
				return
			}
			conns <- c
		}
	}()
	s, link := pairOverRelay(t, h, &wire{}, "x")
	defer s.Close()
	s2, _ := pairOverRelay(t, h, &wire{}, "y") // another phone stays paired, so the host keeps running
	defer s2.Close()
	pub, _ := connectphone.PublicKey(link.Key)
	var room string
	for _, r := range link.Via {
		if r.M == "opaque" {
			room = r.R
		}
	}
	if room == "" {
		t.Fatalf("control: the paired phone's link has no opaque route: %+v", link.Via)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := connectrelay.DialPhone(ctx, opaqueURL, room, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "x")
	var app net.Conn
	select {
	case app = <-conns:
		defer app.Close()
		if PhoneOf(app) != "" {
			t.Fatalf("opaque connection with phone %q", PhoneOf(app))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("control: the opaque connection never reached the app")
	}
	if err := h.Revoke(ctx, pub); err != nil {
		t.Fatal(err)
	}
	// A relay connection reports its deadline as "context canceled", not a timeout: time it instead.
	start := time.Now()
	app.SetReadDeadline(start.Add(5 * time.Second))
	buf := make([]byte, 8)
	for {
		if _, err := app.Read(buf); err != nil {
			break
		}
	}
	if time.Since(start) > 4*time.Second {
		t.Fatal("the opaque connection open at the revoke was not closed")
	}
}

// Audit (fail closed), K1: a host that restarts without State.Keys (HOST-IPC.md: "Without it,
// phones paired over the encrypted routes have to sync their key again over Tailcat") tells a
// phone that is still in its allowlist "bye unpaired" on relay and lan. The phone library turns
// that into ErrRevoked, mobile code "revoked: delete the link", so a pairing the host still holds
// is thrown away and the user must pair again. Only a phone the host removed should hear unpaired.
func TestAuditLostKeysUnpairAPairedPhone(t *testing.T) {
	url := startRelay(t)
	h, _, st := newTestHost(t, Config{Relays: []Relay{{URL: url, Token: relayToken}}})
	waitRelay(t, h)
	serveApp(t, h)
	s, link := pairOverRelay(t, h, &wire{}, "x")
	if _, err := get(t, s); err != nil {
		t.Fatal(err)
	}
	s.Close()
	state := st.last()
	pub, _ := connectphone.PublicKey(link.Key)
	h.Close()

	// The app restores identity and allowed, and not keys.
	h2, _, _ := newTestHost(t, Config{Identity: state.Identity, Allowed: state.Allowed, Relays: []Relay{{URL: url, Token: relayToken}}})
	waitRelay(t, h2)
	serveApp(t, h2)
	if got := h2.Allowed(); len(got) != 1 || got[0] != pub {
		t.Fatalf("control: the restarted host's allowlist is %v", got)
	}
	s2, err := connectphone.Connect(link, connectphone.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	_, err = get(t, s2)
	if errors.Is(err, connectphone.ErrRevoked) || s2.Revoked() {
		t.Fatalf("a phone still in the host's allowlist was told it is unpaired (%v): its app now deletes the link", err)
	}
}

// A1: a flood of refusals reaches Audit at most deniedPerMinute times a minute per reason; the next
// one reported after the minute says how many were left out. Other reasons and kinds are not held back.
func TestDeniedAuditEventsAreLimited(t *testing.T) {
	var got []Event
	h := &Host{audit: func(e Event) { got = append(got, e) }}
	t0 := time.Unix(1_700_000_000, 0)
	for i := 0; i < 500; i++ {
		h.record(Event{Time: t0.Add(time.Duration(i) * 10 * time.Millisecond), Kind: EventDenied, Reason: "unpaired"})
	}
	h.record(Event{Time: t0.Add(time.Second), Kind: EventDenied, Reason: "authorize"})
	h.record(Event{Time: t0.Add(time.Second), Kind: EventRevoked})
	if len(got) != deniedPerMinute+2 {
		t.Fatalf("%d events reached Audit", len(got))
	}
	h.record(Event{Time: t0.Add(61 * time.Second), Kind: EventDenied, Reason: "unpaired"})
	last := got[len(got)-1]
	if last.Reason != "unpaired" || last.Dropped != 500-deniedPerMinute {
		t.Fatalf("after the minute: %+v", last)
	}
}
