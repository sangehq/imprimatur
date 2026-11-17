package guardtest

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// makeRun runs one impr.mk target with IMPR=echo, so the output is the impr
// command line the target would run.
func makeRun(t *testing.T, target string, vars ...string) (string, error) {
	t.Helper()
	mk := filepath.Join(repoRoot(t), "make", "impr.mk")
	args := append([]string{"-s", "-f", mk, "IMPR=echo", "COMMIT=c", "TREE=t", "REPO=", target}, vars...)
	out, err := exec.Command("make", args...).CombinedOutput()
	return strings.Join(strings.Fields(string(out)), " "), err
}

// ID-21, O-187, O-188: impr.mk has the command targets the PowerShell impr.mk
// had (build, release, config, completion, install, path), with their
// variables.
func TestImprMakeTargets(t *testing.T) {
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("needs make")
	}
	for _, c := range []struct {
		target string
		vars   []string
		want   string
	}{
		{"impr-build", []string{"VERSION=v1.2.3", "TARGETS=linux/amd64", "ARCHIVES=1"}, "build --repo-root"},
		{"impr-b", []string{"VERSION=v1.2.3"}, "v1.2.3"},
		{"impr-release", []string{"PROFILE=p", "PURPOSE=internal", "VERSION=v2.0.0", "PLATFORMS=checksums"}, "release --repo-root"},
		{"impr-r", []string{"PROFILE=p", "PURPOSE=internal"}, "--profile p --purpose internal"},
		{"impr-config", nil, "config show"},
		{"impr-config-get", []string{"KEY=server.listen"}, "config get server.listen"},
		{"impr-config-set", []string{"KEY=server.listen", "VALUE=unix"}, "config set server.listen unix"},
		{"impr-completion", []string{"SHELLS=bash zsh"}, "completion install bash zsh"},
		{"impr-completion-uninstall", []string{"SHELLS=all"}, "completion uninstall all"},
		{"impr-install", []string{"DIR=/opt/bin", "FORCE=1"}, "install --dir /opt/bin --force"},
		{"impr-uninstall", nil, "uninstall"},
		{"impr-path", nil, "path"},
	} {
		out, err := makeRun(t, c.target, c.vars...)
		if err != nil || !strings.Contains(out, c.want) {
			t.Errorf("make %s %v: %q (%v), want %q", c.target, c.vars, out, err, c.want)
		}
	}
	if out, err := makeRun(t, "impr-build", "VERSION=v1.2.3", "TARGETS=linux/amd64", "ARCHIVES=1"); err != nil ||
		!strings.Contains(out, "v1.2.3") || !strings.Contains(out, "--targets linux/amd64") || !strings.Contains(out, "--archives") {
		t.Errorf("impr-build variables: %q", out)
	}
	if _, err := makeRun(t, "impr-release", "PURPOSE=internal"); err == nil {
		t.Error("impr-release without PROFILE ran")
	}
	if _, err := makeRun(t, "impr-config-set", "KEY=server.listen"); err == nil {
		t.Error("impr-config-set without VALUE ran")
	}
}

// Every impr.mk recipe runs an impr command that exists.
func TestImprMakeRunsRealCommands(t *testing.T) {
	root := repoRoot(t)
	mk := readFile(t, filepath.Join(root, "make", "impr.mk"))
	cli := readFile(t, filepath.Join(root, "src", "internal", "cli", "cli.go"))
	known := map[string]bool{"help": true, "version": true}
	for _, m := range regexp.MustCompile(`\n\t\t"([a-z]+)":\s+\{`).FindAllStringSubmatch(cli, -1) {
		known[m[1]] = true
	}
	atLeast(t, "impr commands in the dispatch table", len(known), 20)
	calls := regexp.MustCompile(`\$\(IMPR\) ([a-z]+)`).FindAllStringSubmatch(mk, -1)
	for _, m := range calls {
		if !known[m[1]] {
			t.Errorf("impr.mk runs impr %s, which is not a command", m[1])
		}
	}
	atLeast(t, "impr calls in impr.mk", len(calls), 18)
}
