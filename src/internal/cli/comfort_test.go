package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ID-15, O-05: --no-color is accepted anywhere and changes nothing (impr
// prints no colour); NO_COLOR scripts keep working.
func TestNoColorIsAccepted(t *testing.T) {
	h := newHarness(t)
	h.ok("--no-color", "version")
	h.ok("version", "--no-color")
	h.ok("path", "--no-color", "--json")
}

// ID-15, O-07, O-12: a mistyped command or option gets the nearest name.
func TestDidYouMean(t *testing.T) {
	h := newHarness(t)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"relase"}, "did you mean: impr release"},
		{[]string{"verfy"}, "did you mean: impr verify"},
		{[]string{"rul"}, "did you mean: impr rules"},
		{[]string{"build", "--verison", "v1.0.0"}, "did you mean --version"},
		{[]string{"profile", "list", "--jsno"}, "did you mean --json"},
	} {
		code, _, e := h.impr(c.args...)
		if code != 1 || !strings.Contains(e, c.want) {
			t.Errorf("impr %s: exit %d, want %q\n%s", strings.Join(c.args, " "), code, c.want, e)
		}
	}
	if _, _, e := h.impr("zzzzzz"); strings.Contains(e, "did you mean") {
		t.Errorf("a word like no command got a suggestion: %s", e)
	}
}

// ID-15, O-15: impr CMD --help says what the command does and where its
// page is, and every command names a page that exists.
func TestHelpDescribesEachCommand(t *testing.T) {
	h := newHarness(t)
	_, _, e := h.impr("release", "--help")
	if !strings.Contains(e, "Builds, signs and verifies") || !strings.Contains(e, "docs/tools/release.md") {
		t.Fatalf("release --help: %s", e)
	}
	root := filepath.Join("..", "..", "..")
	n := 0
	for name, c := range commands {
		n++
		if c.about == "" || c.doc == "" {
			t.Errorf("%s has no description or docs page", name)
			continue
		}
		if _, err := os.Stat(filepath.Join(root, "docs", "tools", c.doc)); err != nil {
			t.Errorf("%s names docs/tools/%s, which does not exist", name, c.doc)
		}
	}
	if n < 20 {
		t.Fatalf("inspected %d commands, want at least 20", n)
	}
}
