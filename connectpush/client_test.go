package connectpush

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestClient(t *testing.T) {
	var got []map[string]any
	status := http.StatusAccepted
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("%s %s with %q", r.Method, r.URL.Path, r.Header.Get("Content-Type"))
		}
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		json.Unmarshal(b, &m)
		m["path"] = r.URL.Path
		got = append(got, m)
		switch r.URL.Path {
		case "/v1/register":
			io.WriteString(w, `{"handle":"H1"}`)
		case "/v1/revoke":
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(status)
			if status == http.StatusForbidden {
				io.WriteString(w, `{"error":"revoked"}`)
			}
		}
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL + "/"}
	ctx := context.Background()
	h, err := c.Register(ctx, "io.jingtao.herdr", "apns", "abcd", 3)
	if err != nil || h != "H1" {
		t.Fatalf("Register: %q %v", h, err)
	}
	if err := c.Revoke(ctx, "io.jingtao.herdr", "apns", "abcd", 3); err != nil {
		t.Fatal(err)
	}
	if err := c.Send(ctx, "H1", "CT", SendOptions{Collapse: "c1", Priority: "normal"}); err != nil {
		t.Fatal(err)
	}
	status = http.StatusGone
	if err := c.Send(ctx, "H1", "CT", SendOptions{}); !errors.Is(err, ErrGone) {
		t.Fatalf("410: %v, want ErrGone", err)
	}
	status = http.StatusForbidden
	var e *Error
	if err := c.Send(ctx, "H1", "CT", SendOptions{}); !errors.As(err, &e) || e.Status != 403 || e.Code != "revoked" || errors.Is(err, ErrGone) {
		t.Fatalf("403: %v", err)
	}
	if got[0]["path"] != "/v1/register" || got[0]["generation"] != 3.0 || got[0]["token"] != "abcd" {
		t.Fatalf("register body %v", got[0])
	}
	if got[2]["path"] != "/v1/send" || got[2]["collapse"] != "c1" || got[2]["priority"] != "normal" || got[2]["app"] != nil {
		t.Fatalf("send body %v", got[2])
	}
	if _, ok := got[3]["collapse"]; ok {
		t.Fatalf("empty collapse sent: %v", got[3])
	}
}

func TestClientRefusesUnsafeURLsAndRedirects(t *testing.T) {
	var elsewhere atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere.Add(1) }))
	defer other.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer redir.Close()
	ctx := context.Background()
	if err := (&Client{URL: redir.URL}).Send(ctx, "H", "CT", SendOptions{}); err == nil {
		t.Fatal("a redirect counted as success")
	}
	if elsewhere.Load() != 0 {
		t.Fatal("the client followed a redirect with the handle")
	}
	for _, u := range []string{"http://push.example.com", "ftp://push.example.com", "https://u:p@push.example.com", "push.example.com", ""} {
		if err := (&Client{URL: u}).Send(ctx, "H", "CT", SendOptions{}); err == nil || errors.As(err, new(*Error)) {
			t.Errorf("URL %q: %v, want a refusal before any request", u, err)
		}
	}
}

// Gateway URLs are ASCII: a lookalike such as U+0130 in the host would be dialled under its
// punycode name, which is another host.
func TestValidGatewayIsASCII(t *testing.T) {
	for _, u := range []string{"https://push.j\u0130ngtao.io", "https://push.example.\u0130o", "https://\u212Aite.example"} {
		if ValidGateway(u) == nil {
			t.Errorf("%q accepted", u)
		}
	}
	if err := ValidGateway("https://push.example.test"); err != nil {
		t.Fatal(err)
	}
}
