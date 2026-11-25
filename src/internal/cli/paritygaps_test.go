package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// O-62: profile add NAME --file FILE refuses a file whose profile is named
// something else, and adds nothing; a file with the same name is taken.
func TestProfileAddFileMustNameTheSameProfile(t *testing.T) {
	h := newHarness(t)
	h.ok("profile", "add", "other", "--scope", "personal", "--owner", "tester", "--purpose", "test",
		"--set", "platforms.checksums.kind=ssh", "--set", "platforms.checksums.keyRef=env://K",
		"--set", "platforms.checksums.fingerprint=SHA256:"+strings.Repeat("A", 43))
	f := filepath.Join(t.TempDir(), "other.json")
	h.ok("profile", "export", "other", "--out", f)
	code, _, errOut := h.impr("profile", "add", "mine", "--file", f)
	if code != 1 || !strings.Contains(errOut, "the file names profile other, not mine") {
		t.Fatalf("a file naming another profile: %d %s", code, errOut)
	}
	if strings.Contains(h.ok("profile", "list"), "mine") {
		t.Fatal("the refused profile was added")
	}
	h.ok("profile", "rm", "other", "--force")
	h.ok("profile", "add", "other", "--file", f)
}

// O-12: the PowerShell parser matched an option's value from a fixed set
// without regard to case (its Map options: --purpose and rules' --scope), so
// --purpose Release and --scope Product still work; other values keep their
// case.
func TestFixedSetValuesIgnoreCase(t *testing.T) {
	for name, spec := range map[string]flagSpec{"sign": signFlags, "build": buildFlags, "approve": approveFlags} {
		p, err := parse([]string{"--purpose", "Release", "--profile", "Acme"}, spec)
		if err != nil || p.str("purpose") != "release" || p.str("profile") != "Acme" {
			t.Errorf("%s: purpose %q profile %q (%v)", name, p.str("purpose"), p.str("profile"), err)
		}
	}
	p, err := parse([]string{"--scope=Product", "--product", "Tool"}, rulesFlags)
	if err != nil || p.str("scope") != "product" || p.str("product") != "Tool" {
		t.Errorf("rules: scope %q product %q (%v)", p.str("scope"), p.str("product"), err)
	}
}
