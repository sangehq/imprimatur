package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ID-13: the PowerShell toolkit's spellings work as aliases of the Go names:
// profile add --file (--from-file), profile export --out (--out-file),
// install --yes (install never asks) and install --no-completion.
func TestOldOptionSpellingsWork(t *testing.T) {
	h := newHarness(t)
	h.home = t.TempDir()
	h.ok("profile", "add", "me", "--scope", "personal", "--owner", "me", "--purpose", "internal",
		"--set", "platforms.checksums.kind=ssh", "--set", "platforms.checksums.keyRef=env://K",
		"--set", "platforms.checksums.fingerprint=SHA256:"+strings.Repeat("A", 43))
	out := filepath.Join(t.TempDir(), "me.json")
	h.ok("profile", "export", "me", "--out", out)
	b, err := os.ReadFile(out)
	if err != nil || !strings.Contains(string(b), `"name": "me"`) {
		t.Fatalf("export --out: %s %v", b, err)
	}
	renamed := strings.Replace(string(b), `"name": "me"`, `"name": "me2"`, 1)
	f := filepath.Join(t.TempDir(), "me2.json")
	if err := os.WriteFile(f, []byte(renamed), 0o600); err != nil {
		t.Fatal(err)
	}
	h.ok("profile", "add", "me2", "--file", f)
	h.ok("profile", "show", "me2")
	// The old and new names together must agree.
	h.exits(1, "profile", "export", "me", "--out", out, "--out-file", out+".other")

	dir := t.TempDir()
	_, _, e := h.impr("install", "--dir", dir, "--yes", "--no-completion")
	if strings.Contains(e, "shell completion") || !strings.Contains(e, "copied impr") {
		t.Fatalf("install --yes --no-completion: %s", e)
	}
}
