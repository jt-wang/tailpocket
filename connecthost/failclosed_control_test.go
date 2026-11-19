package connecthost

// Fail-closed checks for the control port (POST /v2/sync on the main Tailcat node).

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"tailscale.com/wgengine/filter"
)

func TestFailClosedControlPortOnlySync(t *testing.T) {
	k, phone := phoneKey(t)
	h, f, saved := newTestHost(t, Config{Allowed: []string{phone}})
	main := f.live(DefaultPort)
	states := len(saved.states)
	do := func(method, path string, body []byte) int {
		req, _ := http.NewRequest(method, "http://control.invalid"+path, bytes.NewReader(body))
		resp, err := controlClient(main, phone).Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	for _, tc := range []struct {
		method, path string
		body         []byte
		want         int
	}{
		{"GET", "/v2/sync", nil, http.StatusMethodNotAllowed},
		{"PUT", "/v2/sync", []byte("{}"), http.StatusMethodNotAllowed},
		{"DELETE", "/v2/sync", nil, http.StatusMethodNotAllowed},
		{"POST", "/", []byte("{}"), http.StatusNotFound},
		{"POST", "/pair", []byte("{}"), http.StatusNotFound},
		{"POST", "/v2/sync/", []byte("{}"), http.StatusNotFound},
		{"POST", "//v2/sync", []byte("{}"), http.StatusNotFound},
		{"POST", "/v2/%73ync", []byte("{}"), http.StatusNotFound},
		{"POST", "/v2/sync?x=1", []byte("{}"), http.StatusNotFound},
		{"POST", "/v2/sync", bytes.Repeat([]byte("x"), maxBody+1), http.StatusRequestEntityTooLarge},
		{"POST", "/v2/sync", []byte(`{"noise":` + strings.Repeat(" ", maxBody) + `""}`), http.StatusRequestEntityTooLarge},
		{"POST", "/v2/sync", []byte("not json"), http.StatusBadRequest},
		{"POST", "/v2/sync", []byte(`{"noise":"short"}`), http.StatusBadRequest},
		{"POST", "/v2/sync", []byte(`{"noise":"` + noisePublicOf(k) + `"}`), http.StatusForbidden}, // no proof
		{"POST", "/v2/sync", []byte("{}"), http.StatusOK},                                          // routes and host key only
	} {
		if got := do(tc.method, tc.path, tc.body); got != tc.want {
			t.Errorf("%s %s (%d bytes): %d, want %d", tc.method, tc.path, len(tc.body), got, tc.want)
		}
	}
	if len(saved.states) != states {
		t.Errorf("refused requests saved state: %d saves, want %d", len(saved.states), states)
	}
	// A real sync still works after all of that.
	if got := do("POST", "/v2/sync", syncBody(h, k, phone, noisePublicOf(k))); got != http.StatusOK {
		t.Fatalf("real sync: %d", got)
	}
}

// Only a paired phone's Tailcat address reaches the control port at all: another node key is
// closed before any byte is read, and a connection that is not a phone's gets 403.
func TestFailClosedControlPortOnlyPairedPhones(t *testing.T) {
	_, phone := phoneKey(t)
	_, stranger := phoneKey(t)
	h, f, _ := newTestHost(t, Config{Allowed: []string{phone}})
	req, _ := http.NewRequest("POST", "http://control.invalid/v2/sync", strings.NewReader("{}"))
	if resp, err := controlClient(f.live(DefaultPort), stranger).Do(req); err == nil {
		resp.Body.Close()
		t.Fatalf("an unpaired node key got %d from the control port", resp.StatusCode)
	}
	rec := httptest.NewRecorder()
	h.handleControl(rec, httptest.NewRequest("POST", "/v2/sync", strings.NewReader("{}")))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("no phone on the connection: %d, want 403", rec.Code)
	}
	// The main node serves its port and the control port, nothing else (no SSH on 22).
	spec := f.live(DefaultPort).spec
	for _, port := range []uint16{22, 80, 443, DefaultPairingPort, 1} {
		if spec.onTCP(port) != nil {
			t.Errorf("port %d has a handler", port)
		}
	}
	want := []filter.PortRange{{First: DefaultPort, Last: DefaultPort}, {First: DefaultControlPort, Last: DefaultControlPort}}
	if got := servedPorts(spec); len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("served ports %v, want %v", got, want)
	}
}

// After Revoke the phone's open control connection is closed and a new one is refused.
func TestFailClosedControlPortRevoked(t *testing.T) {
	_, phone := phoneKey(t)
	h, f, _ := newTestHost(t, Config{Allowed: []string{phone}})
	main := f.live(DefaultPort)
	c, s := net.Pipe()
	go main.spec.onTCP(DefaultControlPort)(&addrConn{Conn: s, remote: &net.TCPAddr{IP: clientIP(mustPhone(phone)).AsSlice(), Port: 40000}})
	defer c.Close()
	if err := h.Revoke(t.Context(), phone); err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte("POST /v2/sync HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}")); err == nil {
		buf := make([]byte, 64)
		if n, err := c.Read(buf); err == nil {
			t.Fatalf("revoked phone's control connection answered %q", buf[:n])
		}
	}
	req, _ := http.NewRequest("POST", "http://control.invalid/v2/sync", strings.NewReader("{}"))
	if resp, err := controlClient(main, phone).Do(req); err == nil {
		resp.Body.Close()
		t.Fatalf("revoked phone got %d", resp.StatusCode)
	}
}
