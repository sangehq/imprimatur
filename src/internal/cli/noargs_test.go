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

// Old bug 8: profile edit and export with no NAME use the default profile,
// and now say so on stderr instead of acting silently. stdout stays the
// profile alone, so `impr profile export > f.json` still works.
func TestProfileEditExportNameTheDefault(t *testing.T) {
	h := newHarness(t)
	h.home = t.TempDir()
	h.ok("profile", "add", "me", "--scope", "personal", "--owner", "me", "--purpose", "internal",
		"--set", "platforms.checksums.kind=ssh", "--set", "platforms.checksums.keyRef=env://K",
		"--set", "platforms.checksums.fingerprint=SHA256:"+strings.Repeat("A", 43))
	h.ok("profile", "default", "me")
	for _, args := range [][]string{{"profile", "export"}, {"profile", "edit", "--notes", "x"}} {
		code, out, e := h.impr(args...)
		if code != 0 || !strings.Contains(e, "no NAME given: using the default profile me") {
			t.Errorf("impr %s: exit %d, no note naming the default\n%s", strings.Join(args, " "), code, e)
		}
		if args[1] == "export" && !strings.HasPrefix(strings.TrimSpace(out), "{") {
			t.Errorf("export stdout is not the profile: %q", out)
		}
	}
	// A named profile prints no such note.
	if _, _, e := h.impr("profile", "export", "me"); strings.Contains(e, "no NAME given") {
		t.Errorf("a named export printed the default note: %s", e)
	}
}

// Old security finding 14: the PATH command impr prints on Windows reads and
// writes the user PATH only, unexpanded, so it neither copies the machine
// PATH into the user's nor turns %VAR% entries into fixed text.
func TestInstallPrintsAUserOnlyPathCommand(t *testing.T) {
	h := newHarness(t)
	h.os = "windows"
	dir := t.TempDir()
	_, _, e := h.impr("install", "--dir", dir)
	if strings.Contains(e, "$env:Path") || !strings.Contains(e, "DoNotExpandEnvironmentNames") || !strings.Contains(e, "ExpandString") {
		t.Fatalf("the PATH command is not user-only and unexpanded:\n%s", e)
	}
}
