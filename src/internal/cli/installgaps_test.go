package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeUserPath stands in for the user PATH in the Windows registry.
type fakeUserPath struct {
	value string
	sets  int
}

func (f *fakeUserPath) Get() (string, error) { return f.value, nil }
func (f *fakeUserPath) Set(v string) error   { f.value, f.sets = v, f.sets+1; return nil }

// withUserPath swaps the user PATH store for the test.
func withUserPath(t *testing.T, f userPathStore) {
	t.Helper()
	old := userPath
	userPath = f
	t.Cleanup(func() { userPath = old })
}

// runAt runs impr as a person at a terminal who answers with input.
func runAt(t *testing.T, h *harness, input string, args ...string) (int, string) {
	t.Helper()
	var o, e bytes.Buffer
	home := h.home
	if home == "" {
		home = t.TempDir()
	}
	a := &App{Stdout: &o, Stderr: &e, Getenv: func(k string) string { return h.env[k] }, GOOS: h.os, Home: home, User: "tester",
		Runner: h.run, Now: time.Now, Notifier: h.notifier, Stdin: strings.NewReader(input), Interactive: func() bool { return true }}
	return a.Run(context.Background(), args), e.String()
}

// O-78: on Windows, impr install puts its folder on the user PATH, as the
// PowerShell line did: with --yes, or when the person at the terminal says
// yes. --no-path, a no, or nobody at a terminal leaves PATH alone and prints
// the line to add instead.
func TestInstallPutsItsFolderOnTheUserPathOnWindows(t *testing.T) {
	h := newHarness(t)
	h.os = "windows"
	h.env["PATH"] = `C:\Windows`
	for name, tc := range map[string]struct {
		args  []string
		input string
		want  bool
	}{
		"--yes":                 {[]string{"--yes"}, "", true},
		"a yes at the terminal": {nil, "y\n", true},
		"a no at the terminal":  {nil, "n\n", false},
		"--yes --no-path":       {[]string{"--yes", "--no-path"}, "", false},
		"nobody at a terminal":  {nil, "", false},
	} {
		up := &fakeUserPath{value: `C:\Tools;C:\Go\bin`}
		withUserPath(t, up)
		dir := t.TempDir()
		args := append([]string{"install", "--dir", dir, "--no-completion"}, tc.args...)
		var code int
		var errOut string
		if name == "nobody at a terminal" || name == "--yes" || name == "--yes --no-path" {
			code, _, errOut = h.impr(args...)
		} else {
			code, errOut = runAt(t, h, tc.input, args...)
		}
		added := up.value == `C:\Tools;C:\Go\bin;`+dir
		if code != 0 || added != tc.want {
			t.Errorf("%s: exit %d, user PATH %q (want added %v)\n%s", name, code, up.value, tc.want, errOut)
		}
		if !tc.want && !strings.Contains(errOut, "is not on PATH") {
			t.Errorf("%s: no hint: %s", name, errOut)
		}
	}
	// Already there: nothing is written.
	dir := t.TempDir()
	up := &fakeUserPath{value: `C:\Tools;` + dir}
	withUserPath(t, up)
	h.ok("install", "--dir", dir, "--yes", "--no-completion")
	if up.sets != 0 {
		t.Fatal("the user PATH was written although the folder was on it")
	}
}

// O-80: after an install, impr sets up completion for the shell in use, as
// the PowerShell line did: with --yes or a yes at the terminal; --no-completion
// or nobody at a terminal prints the hint instead.
func TestInstallOffersCompletion(t *testing.T) {
	for name, tc := range map[string]struct {
		args     []string
		input    string
		terminal bool
		want     bool
	}{
		"--yes":                 {[]string{"--yes"}, "", false, true},
		"a yes at the terminal": {nil, "\n", true, true},
		"a no at the terminal":  {nil, "n\n", true, false},
		"--yes --no-completion": {[]string{"--yes", "--no-completion"}, "", false, false},
		"nobody at a terminal":  {nil, "", false, false},
	} {
		h := newHarness(t)
		h.home = t.TempDir()
		h.env["SHELL"] = "/bin/bash"
		h.env["PATH"] = "/usr/bin"
		args := append([]string{"install", "--dir", t.TempDir()}, tc.args...)
		var code int
		if tc.terminal {
			code, _ = runAt(t, h, tc.input, args...)
		} else {
			code, _, _ = h.impr(args...)
		}
		f, _ := (&App{Home: h.home, Getenv: func(k string) string { return h.env[k] }}).completionFile("bash")
		_, owned := completionOwned(f, "bash")
		if code != 0 || owned != tc.want {
			t.Errorf("%s: exit %d, completion installed %v, want %v", name, code, owned, tc.want)
		}
	}
}

// O-97: a completion script impr installed is rewritten on the next run after
// an upgrade, quietly, as the PowerShell line's cache was; a file impr did not
// write is never touched.
func TestInstalledCompletionFollowsAnUpgrade(t *testing.T) {
	h := newHarness(t)
	h.home = t.TempDir()
	h.ok("completion", "install", "bash")
	a := &App{Home: h.home, Getenv: func(k string) string { return h.env[k] }}
	f, _ := a.completionFile("bash")
	cur, _ := os.ReadFile(f)
	old := strings.Replace(string(cur), "release", "an-old-value", -1)
	if err := os.WriteFile(f, []byte(old), 0o644); err != nil { //nolint:gosec // a completion script
		t.Fatal(err)
	}
	h.ok("path")
	if now, _ := os.ReadFile(f); string(now) != string(cur) {
		t.Fatal("the installed script was not brought up to date")
	}
	zsh, _ := a.completionFile("zsh")
	if err := os.MkdirAll(filepath.Dir(zsh), 0o755); err != nil { //nolint:gosec // a test folder
		t.Fatal(err)
	}
	mine := "# my own zsh completion\n"
	if err := os.WriteFile(zsh, []byte(mine), 0o644); err != nil { //nolint:gosec // a completion script
		t.Fatal(err)
	}
	h.ok("path")
	if now, _ := os.ReadFile(zsh); string(now) != mine {
		t.Fatal("a file impr did not write was changed")
	}
}
