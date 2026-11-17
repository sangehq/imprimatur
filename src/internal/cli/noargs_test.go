package cli

import (
	"strings"
	"testing"
)

// O-17: commands that take no arguments refuse a stray word instead of
// ignoring it, as the PowerShell tool did.
func TestNoArgumentCommandsRefuseWords(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	for _, args := range [][]string{
		{"path", "extra"},
		{"uninstall", "--dir", dir, "extra"},
		{"install", "--dir", dir, "extra"},
		{"version", "extra"},
		{"--version", "extra"},
		{"menu", "extra"},
		{"doctor", "extra"},
	} {
		code, _, e := h.impr(args...)
		if code != 1 || !strings.Contains(e, "takes no arguments") {
			t.Errorf("impr %s: exit %d, want 1 naming the stray word\n%s", strings.Join(args, " "), code, e)
		}
	}
	// --help still works on each of them.
	for _, c := range []string{"path", "uninstall", "install", "version", "doctor"} {
		h.ok(c, "--help")
	}
}
