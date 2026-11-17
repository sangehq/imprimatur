package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// ID-17, O-94, O-95: completion offers an option's values, read from the
// usage text, and every generated script still parses.
func TestCompletionOffersValues(t *testing.T) {
	v := completionValues()
	for _, c := range []struct{ cmd, opt, want string }{
		{"sign", "--purpose", "release"}, {"release", "--purpose", "internal"}, {"sign", "--platforms", "checksums"},
		{"rules", "--scope", "file"}, {"server", "--scopes", "verify"},
	} {
		if !slices.Contains(v[c.cmd][c.opt], c.want) {
			t.Errorf("%s %s does not offer %s: %v", c.cmd, c.opt, c.want, v[c.cmd][c.opt])
		}
	}
	for _, sh := range []string{"bash", "zsh", "fish", "powershell"} {
		script, err := CompletionScript(sh)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(script, "release") || !strings.Contains(script, "--purpose") {
			t.Errorf("%s script carries no values", sh)
		}
		bin := map[string]string{"bash": "bash", "zsh": "zsh", "fish": "fish"}[sh]
		if bin == "" {
			continue
		}
		if _, err := exec.LookPath(bin); err != nil {
			continue
		}
		f := filepath.Join(t.TempDir(), "impr."+sh)
		if err := os.WriteFile(f, []byte(script), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(bin, "-n", f).CombinedOutput(); err != nil {
			t.Errorf("%s script does not parse: %v %s", sh, err, out)
		}
	}
}

// ID-17, O-90, O-91, O-92: completion install and uninstall take several
// shells or all, and default to the shell in $SHELL.
func TestCompletionInstallSeveralShells(t *testing.T) {
	h := newHarness(t)
	h.home = t.TempDir()
	h.env["SHELL"] = "/bin/zsh"
	h.ok("completion", "install")
	zsh := filepath.Join(h.home, ".zfunc", "_impr")
	if _, err := os.Stat(zsh); err != nil {
		t.Fatalf("$SHELL zsh: %v", err)
	}
	h.ok("completion", "install", "all")
	bash := filepath.Join(h.home, ".local", "share", "bash-completion", "completions", "impr")
	fish := filepath.Join(h.home, ".config", "fish", "completions", "impr.fish")
	for _, f := range []string{bash, zsh, fish} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("all did not install %s", f)
		}
	}
	h.ok("completion", "uninstall", "bash", "fish")
	for _, f := range []string{bash, fish} {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Errorf("uninstall left %s", f)
		}
	}
	h.ok("completion", "uninstall", "all")
	if _, err := os.Stat(zsh); !os.IsNotExist(err) {
		t.Error("uninstall all left zsh")
	}
	h.env["SHELL"] = "/usr/bin/tcsh"
	h.exits(1, "completion", "install")
	// A bad shell in a list writes nothing.
	h.exits(1, "completion", "install", "bash", "tcsh")
	if _, err := os.Stat(bash); !os.IsNotExist(err) {
		t.Error("a list with an unknown shell still installed bash")
	}
}
