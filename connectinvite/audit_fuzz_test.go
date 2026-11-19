package connectinvite

import "testing"

// Audit (fail closed): text from a QR code or a link. Decoding must not panic, and what it accepts
// must pass Validate and encode again.
func FuzzAuditDecodeInvite(f *testing.F) {
	f.Add("tailpocket2:eJyrVipTsjKqBQAGOgHk")
	f.Add("tailpocket1:AAAA")
	f.Add(`{"v":2,"exp":1,"via":[{"t":"lan","a":["127.0.0.1:1"]}]}`)
	f.Fuzz(func(t *testing.T, text string) {
		if in, err := DecodeV2(text, DefaultPrefix2); err == nil {
			if in.Validate() != nil {
				t.Fatalf("accepted an invite that does not validate: %+v", in)
			}
		}
		if in, err := Decode(text, DefaultPrefix); err == nil && in.Validate() != nil {
			t.Fatalf("accepted a v1 invite that does not validate: %+v", in)
		}
		if in, err := ParseJSON([]byte(text)); err == nil && in.Validate() != nil {
			t.Fatalf("accepted JSON that does not validate: %+v", in)
		}
	})
}
