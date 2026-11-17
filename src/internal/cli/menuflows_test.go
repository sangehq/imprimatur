package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ID-18, O-101, O-103, O-104: the menu builds (b), releases (r, only after
// a typed "yes") and installs (n), by running the same commands the CLI does.
func TestMenuBuildReleaseInstall(t *testing.T) {
	repo := goRepo(t)
	h := newHarness(t)
	internalSSHProfile(t, h, "p")
	h.ok("profile", "default", "p")

	code, _, e := h.menuRun("b\n" + repo + "\nv1.2.3\nq\n")
	if code != 0 || !strings.Contains(e, "menu      exit 0") {
		t.Fatalf("menu build: %d\n%s", code, e)
	}
	if b, err := os.ReadFile(filepath.Join(repo, "build", "build-manifest.json")); err != nil || !strings.Contains(string(b), `"v1.2.3"`) {
		t.Fatalf("the menu build wrote no v1.2.3 manifest: %v", err)
	}

	signed := filepath.Join(repo, "build", "impr-manifest.json")
	// Anything but "yes" releases nothing.
	_, _, e = h.menuRun("r\n" + repo + "\nv1.2.4\n\ninternal\nchecksums\nno\nq\n")
	if _, err := os.Stat(signed); err == nil || !strings.Contains(e, "nothing was released") {
		t.Fatalf("the menu released without a yes:\n%s", e)
	}
	code, _, e = h.menuRun("r\n" + repo + "\nv1.2.4\n\ninternal\nchecksums\nyes\nq\n")
	if code != 0 || !strings.Contains(e, "[p]") || !strings.Contains(e, "menu      exit 0") {
		t.Fatalf("menu release: %d\n%s", code, e)
	}
	if _, err := os.Stat(signed); err != nil {
		t.Fatal("the menu release signed nothing")
	}

	_, _, e = h.menuRun("n\nq\n")
	if !strings.Contains(e, "copied impr") {
		t.Fatalf("menu install: %s", e)
	}
}
