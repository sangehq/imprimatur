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

// O-74: config set trims the spaces and the quotes around a value, as the
// PowerShell line did (impr.ps1:474), so a value quoted twice is stored bare.
func TestConfigSetTrimsQuotes(t *testing.T) {
	h := newHarness(t)
	for _, v := range []string{`'127.0.0.1:8765'`, `"127.0.0.1:8765"`, ` "127.0.0.1:8765" `} {
		h.ok("config", "set", "server.listen", v)
		if got := strings.TrimSpace(h.ok("config", "get", "server.listen")); got != `"127.0.0.1:8765"` { // get prints JSON
			t.Errorf("set %q: got %q", v, got)
		}
	}
	h.ok("config", "set", "server.roots", `'["/srv/a", "/srv/b"]'`)
	if got := h.ok("config", "get", "server.roots"); !strings.Contains(got, "/srv/b") {
		t.Errorf("a quoted JSON list: %q", got)
	}
	if code, _, _ := h.impr("config", "set", "server.listen", `""`); code != 1 {
		t.Errorf("a value that is only quotes was accepted: %d", code)
	}
}
