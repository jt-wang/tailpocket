package connectpush

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The same vector is in the Swift and Kotlin tests: every side must build the
// same client data.
func TestAttestClientDataVector(t *testing.T) {
	got := string(AttestClientData("register", "io.jingtao.herdr", "apns", "ab01", 7, "CHALLENGE"))
	if got != "tailpocket push attest 1\nregister\nio.jingtao.herdr\napns\nab01\n7\nCHALLENGE" {
		t.Fatalf("client data %q", got)
	}
	if h := AttestRequestHash("register", "io.jingtao.herdr", "apns", "ab01", 7, "CHALLENGE"); h != "sheS7aeIcwOE_y7yGLnYIxbFa7mWPSMvt3jDBZY0N4Q" {
		t.Fatalf("request hash %s", h)
	}
	if AttestRequestHash("revoke", "io.jingtao.herdr", "apns", "ab01", 7, "CHALLENGE") == AttestRequestHash("register", "io.jingtao.herdr", "apns", "ab01", 7, "CHALLENGE") {
		t.Fatal("op not bound")
	}
}

func TestNewKey(t *testing.T) {
	k1, key1, err := NewKey()
	k2, key2, _ := NewKey()
	if err != nil || len(k1) != 22 || !IsBase64URL(k1) || k1 == k2 || key1 == key2 || key1 == [32]byte{} {
		t.Fatalf("NewKey %q %q %v", k1, k2, err)
	}
}

func TestClientChallengeAndAttest(t *testing.T) {
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		json.Unmarshal(b, &m)
		m["path"] = r.URL.Path
		got = append(got, m)
		switch r.URL.Path {
		case "/v1/challenge":
			io.WriteString(w, `{"challenge":"Q0hBTExFTkdF","expires":1}`)
		case "/v1/register":
			io.WriteString(w, `{"handle":"H","expires":99}`)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL}
	ctx := context.Background()
	ch, err := c.Challenge(ctx, "io.x.y")
	if err != nil || ch != "Q0hBTExFTkdF" {
		t.Fatalf("Challenge %q %v", ch, err)
	}
	r, err := c.RegisterDevice(ctx, Device{App: "io.x.y", Platform: "fcm", Token: "t", Generation: 2, Attest: json.RawMessage(`{"challenge":"Q0hBTExFTkdF","token":"it"}`)})
	if err != nil || r.Handle != "H" || r.Expires != 99 {
		t.Fatalf("RegisterDevice %+v %v", r, err)
	}
	if err := c.RevokeDevice(ctx, Device{App: "io.x.y", Platform: "fcm", Token: "t", Generation: 2}); err != nil {
		t.Fatal(err)
	}
	if got[0]["app"] != "io.x.y" || got[1]["attest"].(map[string]any)["token"] != "it" || got[2]["path"] != "/v1/revoke" {
		t.Fatalf("requests %v", got)
	}
	if _, ok := got[2]["attest"]; ok {
		t.Fatal("empty attest sent")
	}
}
