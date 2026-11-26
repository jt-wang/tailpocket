package connectmobile

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPushFunctions(t *testing.T) {
	var key map[string]string
	if json.Unmarshal([]byte(PushNewKey()), &key) != nil || len(key["kid"]) != 22 {
		t.Fatalf("PushNewKey %v", key)
	}
	if b, err := base64.RawURLEncoding.DecodeString(key["key"]); err != nil || len(b) != 32 {
		t.Fatal("key is not 32 bytes")
	}
	var got []map[string]any
	status, answer := 200, `{"handle":"H","expires":5}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		json.Unmarshal(b, &m)
		m["path"] = r.URL.Path
		got = append(got, m)
		w.WriteHeader(status)
		io.WriteString(w, answer)
	}))
	defer srv.Close()
	if out := PushRegister(srv.URL, "io.x.y", "apns", "abcd", 2, `{"challenge":"c"}`, 5000); out != `{"handle":"H","expires":5}` {
		t.Fatalf("register %s", out)
	}
	if got[0]["generation"] != 2.0 || got[0]["attest"].(map[string]any)["challenge"] != "c" {
		t.Fatalf("sent %v", got[0])
	}
	for _, c := range []struct {
		status int
		body   string
		want   string
	}{
		{409, `{"error":"stale_generation","min_generation":7}`, `{"error":"stale-generation","minGeneration":7}`},
		{401, `{"error":"attestation_required"}`, `{"error":"attestation-required"}`},
		{401, `{"error":"attest_key_unknown"}`, `{"error":"attest-key-unknown"}`},
		{401, `{"error":"attestation_failed"}`, `{"error":"attestation-failed"}`},
		{429, `{"error":"rate_limited"}`, `{"error":"rate-limited"}`},
		{503, `x`, `{"error":"failed"}`},
	} {
		status, answer = c.status, c.body
		if out := PushRegister(srv.URL, "io.x.y", "apns", "abcd", 2, "", 5000); out != c.want {
			t.Errorf("%d %s: %s, want %s", c.status, c.body, out, c.want)
		}
	}
	status, answer = 204, ""
	if out := PushRevoke(srv.URL, "io.x.y", "fcm", "tok", 3, "", 5000); out != "{}" || got[len(got)-1]["path"] != "/v1/revoke" {
		t.Fatalf("revoke %s", out)
	}
	for _, out := range []string{
		PushRegister("http://example.com", "io.x.y", "apns", "abcd", 1, "", 1000),
		PushRegister(srv.URL, "io.x.y", "sms", "abcd", 1, "", 1000),
		PushRegister(srv.URL, "io.x.y", "apns", "abcd", 0, "", 1000),
		PushRegister(srv.URL, "io.x.y", "apns", "abcd", 1, "{", 1000),
	} {
		if out != `{"error":"invalid-arguments"}` {
			t.Errorf("bad arguments: %s", out)
		}
	}
	if out := PushGive(999, "{}", 1000); !strings.Contains(out, "unknown-handle") {
		t.Fatal(out)
	}
	if out := PushRegister("https://127.0.0.1:1", "io.x.y", "apns", "abcd", 1, "", 2000); out != `{"error":"unreachable"}` {
		t.Fatalf("no gateway: %s", out)
	}
}
