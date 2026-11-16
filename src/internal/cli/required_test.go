package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestEventsRequiredFailsSigningClosed: with events.required, a run whose
// event log cannot be written signs nothing and exits 5; without it, the run
// signs and only warns.
func TestEventsRequiredFailsSigningClosed(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil || runtime.GOOS == "windows" {
		t.Skip("needs ssh-keygen")
	}
	h := newHarness(t)
	key := filepath.Join(t.TempDir(), "k")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	fpOut, _ := exec.Command("ssh-keygen", "-l", "-E", "sha256", "-f", key).Output()
	h.env["IMPR_K"] = key
	h.ok("profile", "add", "p", "--scope", "personal", "--owner", "me", "--purpose", "internal",
		"--set", "platforms.checksums.kind=ssh", "--set", "platforms.checksums.keyRef=env://IMPR_K",
		"--set", "platforms.checksums.fingerprint="+strings.Fields(string(fpOut))[1])
	h.ok("config", "set", "notify.desktop", "false")

	// Block the event log: a file where its folder should be.
	logDir := filepath.Join(h.env["IMPR_STATE_DIR"], "events")
	if err := os.RemoveAll(logDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logDir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	sign := func(want int) string {
		root, manifest, commit, tree := build(t)
		out := h.exits(want, "sign", "--json", "--strict", "--root", root, "--manifest", manifest, "--commit", commit, "--tree", tree,
			"--profile", "p", "--purpose", "internal", "--platforms", "checksums")
		_, err := os.Stat(filepath.Join(root, "build", "SHA256SUMS"))
		if (err == nil) != (want == 0) {
			t.Fatalf("exit %d, SHA256SUMS written: %v\n%s", want, err == nil, out)
		}
		return out
	}
	sign(0)
	h.ok("config", "set", "events.required", "true")
	if out := sign(5); !strings.Contains(out, "events.required") {
		t.Fatalf("the refusal does not say why: %s", out)
	}
}
