package connectpush

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite testdata/vectors.json")

var (
	testKey = [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	testNow = time.Unix(1_790_000_000, 0)
)

func keyFor(kid string) func(string) ([32]byte, bool) {
	return func(k string) ([32]byte, bool) { return testKey, k == kid }
}

func lastZero(string) uint64 { return 0 }

func note(body string) Note {
	return Note{Title: "build", Body: body, Thread: "t1", Kind: "agent", Sent: testNow.Unix(), Seq: 7}
}

func TestRoundTrip(t *testing.T) {
	n := Note{Title: "Herdr", Body: "tests passed <&> \u2028 ü 🐑", Thread: "s/1", URL: "herdr://s/1", Kind: "done", Sent: testNow.Unix(), Seq: 42}
	ct, err := Seal(testKey, "k1", "io.jingtao.herdr", n)
	if err != nil {
		t.Fatal(err)
	}
	got, kid, err := Open(keyFor("k1"), "io.jingtao.herdr", ct, testNow, lastZero)
	if err != nil {
		t.Fatal(err)
	}
	if got != n || kid != "k1" {
		t.Fatalf("got %+v kid %q, want %+v k1", got, kid, n)
	}
	// Two seals of one note differ: the nonce is random.
	ct2, _ := Seal(testKey, "k1", "io.jingtao.herdr", n)
	if ct == ct2 {
		t.Fatal("two seals gave the same ciphertext")
	}
}

func mustFail(t *testing.T, want error, ct, app string, keys func(string) ([32]byte, bool), now time.Time, last func(string) uint64) {
	t.Helper()
	n, kid, err := Open(keys, app, ct, now, last)
	if err == nil {
		t.Fatalf("opened: %+v", n)
	}
	if want != nil && !errors.Is(err, want) {
		t.Fatalf("err %v, want %v", err, want)
	}
	if n != (Note{}) || kid != "" {
		t.Fatalf("failed Open returned note %+v kid %q", n, kid)
	}
}

func TestEveryByteIsChecked(t *testing.T) {
	ct, err := Seal(testKey, "k1", "app", note("hello"))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(ct)
	for i := range raw {
		b := bytes.Clone(raw)
		b[i] ^= 0x01
		mustFail(t, nil, base64.RawURLEncoding.EncodeToString(b), "app", keyFor("k1"), testNow, lastZero)
	}
	// Truncated, extended, and not base64url.
	mustFail(t, nil, ct[:len(ct)-1], "app", keyFor("k1"), testNow, lastZero)
	mustFail(t, ErrMalformed, ct+"AA", "app", keyFor("k1"), testNow, lastZero)
	mustFail(t, ErrMalformed, ct[:10]+"\n"+ct[10:], "app", keyFor("k1"), testNow, lastZero)
	mustFail(t, ErrMalformed, ct+"=", "app", keyFor("k1"), testNow, lastZero)
}

func TestBoundToAppAndKid(t *testing.T) {
	ct, _ := Seal(testKey, "k1", "io.jingtao.herdr", note("x"))
	mustFail(t, ErrAuth, ct, "io.jingtao.boop", keyFor("k1"), testNow, lastZero)
	mustFail(t, ErrAuth, ct, "io.jingtao.herd", keyFor("k1"), testNow, lastZero)

	// Same key under another kid: the kid is in the associated data.
	raw, _ := base64.RawURLEncoding.DecodeString(ct)
	raw[2] = '2' // "k1" -> "k2"
	any := func(string) ([32]byte, bool) { return testKey, true }
	mustFail(t, ErrAuth, base64.RawURLEncoding.EncodeToString(raw), "io.jingtao.herdr", any, testNow, lastZero)

	// Unknown kid, and the right kid with another key.
	mustFail(t, ErrUnknownKey, ct, "io.jingtao.herdr", keyFor("k9"), testNow, lastZero)
	other := func(string) ([32]byte, bool) { return [32]byte{9}, true }
	mustFail(t, ErrAuth, ct, "io.jingtao.herdr", other, testNow, lastZero)
}

func TestTimeWindow(t *testing.T) {
	ct, _ := Seal(testKey, "k1", "app", note("x"))
	ok := func(now time.Time) {
		t.Helper()
		if _, _, err := Open(keyFor("k1"), "app", ct, now, lastZero); err != nil {
			t.Fatalf("at %v: %v", now.Sub(testNow), err)
		}
	}
	ok(testNow.Add(MaxAge))
	ok(testNow.Add(-MaxSkew))
	mustFail(t, ErrExpired, ct, "app", keyFor("k1"), testNow.Add(MaxAge+time.Second), lastZero)
	mustFail(t, ErrFuture, ct, "app", keyFor("k1"), testNow.Add(-MaxSkew-time.Second), lastZero)
}

func TestReplay(t *testing.T) {
	ct, _ := Seal(testKey, "k1", "app", note("x")) // seq 7
	var asked string
	last := func(v uint64) func(string) uint64 {
		return func(kid string) uint64 { asked = kid; return v }
	}
	if _, _, err := Open(keyFor("k1"), "app", ct, testNow, last(6)); err != nil {
		t.Fatal(err)
	}
	if asked != "k1" {
		t.Fatalf("last asked for %q, want k1", asked)
	}
	mustFail(t, ErrReplay, ct, "app", keyFor("k1"), testNow, last(7))
	mustFail(t, ErrReplay, ct, "app", keyFor("k1"), testNow, last(8))

	// A phone that stores the seq it accepts refuses the same note twice.
	high := map[string]uint64{}
	open := func() error {
		n, kid, err := Open(keyFor("k1"), "app", ct, testNow, func(k string) uint64 { return high[k] })
		if err == nil {
			high[kid] = n.Seq
		}
		return err
	}
	if err := open(); err != nil {
		t.Fatal(err)
	}
	if err := open(); !errors.Is(err, ErrReplay) {
		t.Fatalf("second delivery: %v, want ErrReplay", err)
	}

	if _, err := Seal(testKey, "k1", "app", Note{Sent: testNow.Unix()}); err == nil {
		t.Fatal("Seal took seq 0")
	}
}

func TestLengthOnlyShowsTier(t *testing.T) {
	kid := "k1"
	want := map[int]bool{}
	for _, tier := range Tiers {
		want[base64.RawURLEncoding.EncodedLen(1+len(kid)+nonceSize+tier+tagSize)] = true
	}
	got := map[int]int{}
	for n := 0; n < 2100; n += 7 {
		ct, err := Seal(testKey, kid, "app", note(strings.Repeat("a", n)))
		if errors.Is(err, ErrTooLarge) {
			got[-1]++
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if !want[len(ct)] {
			t.Fatalf("body of %d bytes gave %d characters, not a tier length %v", n, len(ct), want)
		}
		got[len(ct)]++
		if _, _, err := Open(keyFor(kid), "app", ct, testNow, lastZero); err != nil {
			t.Fatalf("body of %d bytes: %v", n, err)
		}
	}
	if len(got) != len(Tiers)+1 {
		t.Fatalf("lengths seen %v: want every tier and ErrTooLarge", got)
	}

	// The longest kid with the largest tier stays under MaxCiphertext.
	long := strings.Repeat("k", MaxKid)
	js, _ := marshalNote(note("b"))
	body := strings.Repeat("b", Tiers[len(Tiers)-1]-2-len(js)+1) // fills the tier exactly
	ct, err := Seal(testKey, long, "app", note(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) > MaxCiphertext || len(ct) != 2855 {
		t.Fatalf("largest sealed note is %d characters", len(ct))
	}
	if _, err := Seal(testKey, long, "app", note(body+"b")); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("one byte over the largest tier: %v", err)
	}
	if _, err := Seal(testKey, long+"k", "app", note("")); err == nil {
		t.Fatal("Seal took a kid longer than MaxKid")
	}
}

// sealRaw seals a plaintext as it is, padding or not.
func sealRaw(t *testing.T, pt []byte) string {
	t.Helper()
	ct, err := sealPadded(bytes.NewReader(make([]byte, 12)), testKey, "k1", "app", pt)
	if err != nil {
		t.Fatal(err)
	}
	return ct
}

func TestPaddingIsChecked(t *testing.T) {
	js, _ := marshalNote(note("pad"))
	good, _ := pad(js)
	if _, _, err := Open(keyFor("k1"), "app", sealRaw(t, good), testNow, lastZero); err != nil {
		t.Fatal(err)
	}
	for i := 2 + len(js); i < len(good); i += 37 {
		b := bytes.Clone(good)
		b[i] = 1
		mustFail(t, ErrMalformed, sealRaw(t, b), "app", keyFor("k1"), testNow, lastZero)
	}
	b := bytes.Clone(good)
	b[len(b)-1] = 0x80
	mustFail(t, ErrMalformed, sealRaw(t, b), "app", keyFor("k1"), testNow, lastZero)

	b = bytes.Clone(good)
	binary.BigEndian.PutUint16(b, uint16(len(good)-1)) // runs past the end
	mustFail(t, ErrMalformed, sealRaw(t, b), "app", keyFor("k1"), testNow, lastZero)
	binary.BigEndian.PutUint16(b, 0xffff)
	mustFail(t, ErrMalformed, sealRaw(t, b), "app", keyFor("k1"), testNow, lastZero)
	binary.BigEndian.PutUint16(b, uint16(len(js)-1)) // cuts the JSON short
	mustFail(t, ErrMalformed, sealRaw(t, b), "app", keyFor("k1"), testNow, lastZero)

	// A plaintext that is not a tier long, even with good padding inside.
	odd := make([]byte, 300)
	binary.BigEndian.PutUint16(odd, uint16(len(js)))
	copy(odd[2:], js)
	mustFail(t, ErrMalformed, sealRaw(t, odd), "app", keyFor("k1"), testNow, lastZero)
	if err := Check(sealRaw(t, odd)); err == nil {
		t.Fatal("Check took a ciphertext that is not a tier long")
	}
}

// ---- vectors ----

type vectorFile struct {
	Comment       string         `json:"comment"`
	Label         string         `json:"label"`
	Tiers         []int          `json:"tiers"`
	MaxCiphertext int            `json:"max_ciphertext"`
	Seal          []sealVector   `json:"seal"`
	Reject        []rejectVector `json:"reject"`
}

type sealVector struct {
	Name         string `json:"name"`
	Key          string `json:"key_hex"`
	Kid          string `json:"kid"`
	App          string `json:"app"`
	Nonce        string `json:"nonce_hex"`
	Note         Note   `json:"note"`
	JSON         string `json:"json"`
	AAD          string `json:"aad_hex"`
	Plaintext    string `json:"plaintext_hex"`
	Ciphertext   string `json:"ct"`
	CiphertextLn int    `json:"ct_length"`
}

type rejectVector struct {
	Name  string `json:"name"`
	Key   string `json:"key_hex"`
	Kid   string `json:"kid"` // the only kid the phone has a key for
	App   string `json:"app"`
	Now   int64  `json:"now"`
	Last  uint64 `json:"last"` // highest seq already accepted for kid
	CT    string `json:"ct"`
	Error string `json:"error"`
}

var errNames = map[error]string{
	ErrMalformed: "malformed", ErrUnknownKey: "unknown_key", ErrAuth: "auth",
	ErrExpired: "expired", ErrFuture: "future", ErrReplay: "replay", ErrTooLarge: "too_large",
}

func errName(err error) string {
	for e, n := range errNames {
		if errors.Is(err, e) {
			return n
		}
	}
	return "other"
}

func makeVectors(t *testing.T) vectorFile {
	t.Helper()
	nonce := func(b byte) []byte {
		n := make([]byte, 12)
		for i := range n {
			n[i] = b + byte(i)
		}
		return n
	}
	f := vectorFile{
		Comment: "Generated by go test ./connectpush -run TestVectors -update. Format in docs/PUSH.md. " +
			"An implementation must give ct from key, kid, app, nonce and plaintext_hex; json is what Go's encoder makes " +
			"from note, so a sealer that builds the same JSON gives the same ct. Every reject vector must fail with error.",
		Label: Label, Tiers: Tiers[:], MaxCiphertext: MaxCiphertext,
	}
	add := func(name, kid, app string, nb byte, n Note) {
		js, err := marshalNote(n)
		if err != nil {
			t.Fatal(err)
		}
		pt, err := pad(js)
		if err != nil {
			t.Fatal(err)
		}
		ct, err := SealRand(bytes.NewReader(nonce(nb)), testKey, kid, app, n)
		if err != nil {
			t.Fatal(err)
		}
		f.Seal = append(f.Seal, sealVector{
			Name: name, Key: hex.EncodeToString(testKey[:]), Kid: kid, App: app,
			Nonce: hex.EncodeToString(nonce(nb)), Note: n, JSON: string(js),
			AAD: hex.EncodeToString(AAD(app, kid)), Plaintext: hex.EncodeToString(pt),
			Ciphertext: ct, CiphertextLn: len(ct),
		})
	}
	sent := testNow.Unix()
	add("tier-256", "k1", "io.jingtao.herdr", 0x10,
		Note{Title: "Herdr", Body: "Agent finished", Thread: "session-1", Kind: "done", Sent: sent, Seq: 1})
	add("tier-1024-all-fields-unicode", "phone-7f3a", "io.jingtao.dsh", 0x20,
		Note{Title: "DSH ✓", Body: strings.Repeat("Résumé 🐑 <&> ", 30), Thread: "t/2", URL: "dsh://open?s=2&x=1", Kind: "agent", Sent: sent, Seq: 2})
	add("tier-2048", "k2", "io.jingtao.boop", 0x30,
		Note{Title: "Boop", Body: strings.Repeat("x", 1500), Sent: sent, Seq: 3})

	base := f.Seal[0]
	rej := func(name string, ct string, now int64, last uint64, app string) {
		if app == "" {
			app = base.App
		}
		_, _, err := Open(keyFor(base.Kid), app, ct, time.Unix(now, 0), func(string) uint64 { return last })
		if err == nil {
			t.Fatalf("reject vector %s opened", name)
		}
		f.Reject = append(f.Reject, rejectVector{Name: name, Key: base.Key, Kid: base.Kid, App: app, Now: now, Last: last, CT: ct, Error: errName(err)})
	}
	raw, _ := base64.RawURLEncoding.DecodeString(base.Ciphertext)
	flip := func(i int) string {
		b := bytes.Clone(raw)
		b[i] ^= 1
		return base64.RawURLEncoding.EncodeToString(b)
	}
	rej("wrong-app", base.Ciphertext, sent, 0, "io.jingtao.boop")
	rej("tag-changed", flip(len(raw)-1), sent, 0, "")
	rej("ciphertext-changed", flip(1+len(base.Kid)+12+5), sent, 0, "")
	rej("nonce-changed", flip(1+len(base.Kid)), sent, 0, "")
	rej("kid-changed", flip(1), sent, 0, "")
	rej("expired", base.Ciphertext, sent+int64(MaxAge/time.Second)+1, 0, "")
	rej("future", base.Ciphertext, sent-int64(MaxSkew/time.Second)-1, 0, "")
	rej("replay-equal-seq", base.Ciphertext, sent, 1, "")

	pt, _ := hex.DecodeString(base.Plaintext)
	sealN := func(b []byte, nb byte) string {
		ct, err := sealPadded(bytes.NewReader(nonce(nb)), testKey, base.Kid, base.App, b)
		if err != nil {
			t.Fatal(err)
		}
		return ct
	}
	p := bytes.Clone(pt)
	p[len(p)-1] = 1
	rej("padding-not-zero", sealN(p, 0x40), sent, 0, "")
	p = bytes.Clone(pt)
	binary.BigEndian.PutUint16(p, uint16(len(p)-1))
	rej("length-past-end", sealN(p, 0x50), sent, 0, "")
	p = append(bytes.Clone(pt), 0)
	rej("not-a-tier", sealN(p, 0x60), sent, 0, "")
	return f
}

func TestVectors(t *testing.T) {
	f := makeVectors(t)
	want, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, '\n')
	if *update {
		if err := os.WriteFile("testdata/vectors.json", want, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("testdata/vectors.json differs from what the code makes; if the change is meant, run go test -run TestVectors -update")
	}

	// Check the file on its own terms, as another implementation would.
	var file vectorFile
	if err := json.Unmarshal(got, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Seal) != 3 || len(file.Reject) < 10 {
		t.Fatalf("%d seal and %d reject vectors", len(file.Seal), len(file.Reject))
	}
	tiers := map[int]bool{}
	for _, v := range file.Seal {
		var key [32]byte
		kb, _ := hex.DecodeString(v.Key)
		copy(key[:], kb)
		nonce, _ := hex.DecodeString(v.Nonce)
		ct, err := SealRand(bytes.NewReader(nonce), key, v.Kid, v.App, v.Note)
		if err != nil || ct != v.Ciphertext {
			t.Fatalf("%s: Seal gave %q, %v", v.Name, ct, err)
		}
		pt, _ := hex.DecodeString(v.Plaintext)
		tiers[len(pt)] = true
		if js, _ := unpad(pt); string(js) != v.JSON {
			t.Fatalf("%s: plaintext does not unpad to json", v.Name)
		}
		n, kid, err := Open(func(k string) ([32]byte, bool) { return key, k == v.Kid }, v.App, v.Ciphertext, time.Unix(v.Note.Sent, 0), lastZero)
		if err != nil || n != v.Note || kid != v.Kid {
			t.Fatalf("%s: Open gave %+v %q %v", v.Name, n, kid, err)
		}
	}
	if len(tiers) != 3 {
		t.Fatalf("seal vectors cover tiers %v, want all three", tiers)
	}
	for _, v := range file.Reject {
		var key [32]byte
		kb, _ := hex.DecodeString(v.Key)
		copy(key[:], kb)
		_, _, err := Open(func(k string) ([32]byte, bool) { return key, k == v.Kid }, v.App, v.CT, time.Unix(v.Now, 0), func(string) uint64 { return v.Last })
		if err == nil || errName(err) != v.Error {
			t.Fatalf("%s: Open gave %v, want %s", v.Name, err, v.Error)
		}
	}
}
