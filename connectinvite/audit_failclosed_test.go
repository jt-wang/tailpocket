package connectinvite

import (
	"strings"
	"testing"
)

// Audit (fail closed), N1: the device name an unpaired peer sends reaches the computer's approval
// prompt (same-Wi-Fi "localCode", and "paired" after a Tailcat pairing) through CleanName, which
// drops control characters and keeps format characters. A right-to-left override or a line
// separator lets the sender reorder or split the text the user reads before approving.
// connectsecure.cleanName already drops them on relay and lan.
func TestAuditDeviceNameKeepsFormatCharacters(t *testing.T) {
	for name, r := range map[string]string{
		"right-to-left override U+202E": "\u202e",
		"line separator U+2028":         "\u2028",
		"zero width space U+200B":       "\u200b",
		"bidi isolate U+2066":           "\u2066",
	} {
		if got := CleanName("Pixel" + r + "9"); strings.Contains(got, r) {
			t.Errorf("CleanName keeps %s: %q", name, got)
		}
	}
}
