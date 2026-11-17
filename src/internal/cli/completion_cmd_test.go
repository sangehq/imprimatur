package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// O-89: impr completion prints a shell's script, takes pwsh for PowerShell
// as the PowerShell toolkit did, and refuses a second shell instead of
// ignoring it; install and uninstall write and remove the file.
func TestCompletionCommand(t *testing.T) {
	h := newHarness(t)
	h.home = t.TempDir()
	out := h.ok("completion", "bash")
	if !strings.Contains(out, "complete") || !strings.Contains(out, "impr") {
		t.Fatalf("bash script: %q", out)
	}
	// After an alias, the options of the command it stands for (the doc's
	// promise, completion.md).
	m := completionModel()
	for a, full := range aliases {
		if strings.Join(m[a], " ") != strings.Join(m[full], " ") || len(m[a]) == 0 && full != "help" {
			t.Errorf("alias %s does not complete like %s: %v", a, full, m[a])
		}
	}
	if bash, err := exec.LookPath("bash"); err == nil {
		f := filepath.Join(t.TempDir(), "impr.bash")
		if err := os.WriteFile(f, []byte(out), 0o600); err != nil {
			t.Fatal(err)
		}
		if b, err := exec.Command(bash, "-n", f).CombinedOutput(); err != nil {
			t.Fatalf("the bash script does not parse: %v %s", err, b)
		}
	}
	if ps, pwsh := h.ok("completion", "powershell"), h.ok("completion", "pwsh"); ps != pwsh || !strings.Contains(ps, "Register-ArgumentCompleter") {
		t.Fatalf("pwsh is not powershell's script")
	}
	h.exits(1, "completion")
	h.exits(1, "completion", "bash", "zsh")
	h.exits(1, "completion", "tcsh")
	h.exits(1, "completion", "install", "bash", "zsh")

	h.ok("completion", "install", "zsh")
	f := filepath.Join(h.home, ".zfunc", "_impr")
	if _, err := os.Stat(f); err != nil {
		t.Fatalf("install zsh wrote nothing: %v", err)
	}
	h.ok("completion", "uninstall", "zsh")
	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Fatalf("uninstall zsh left %s", f)
	}
	h.exits(1, "completion", "install", "powershell")
}
