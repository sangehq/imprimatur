package cli

import (
	"strings"
	"testing"
)

// O-162, old bug 6: doctor's "not ok" is not the usage code. A host that is
// not ready exits 5 (unavailable), so a caller can tell it from a mistyped
// command, which still exits 1.
func TestDoctorNotOKIsNotUsage(t *testing.T) {
	h := newHarness(t)
	code, out, _ := h.impr("doctor", "--json")
	if code != 5 || !strings.Contains(out, `"ok":false`) {
		t.Fatalf("doctor with no default profile: exit %d, want 5\n%s", code, out)
	}
	if code, _, _ := h.impr("doctor", "extra"); code != 1 {
		t.Fatalf("doctor with a stray word: exit %d, want 1", code)
	}
}
