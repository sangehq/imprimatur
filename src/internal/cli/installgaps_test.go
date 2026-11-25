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

// withVersion runs the rest of a test as impr version v.
func withVersion(t *testing.T, v string) {
	t.Helper()
	old := version
	version = v
	t.Cleanup(func() { version = old })
}

// stampedBash installs the bash completion as impr version stamp, then
// changes its body so a rewrite shows, and returns the path and the body.
func stampedBash(t *testing.T, h *harness, stamp string) (path, body string) {
	t.Helper()
	withVersion(t, stamp)
	h.ok("completion", "install", "bash")
	a := &App{Home: h.home, Getenv: func(k string) string { return h.env[k] }}
	f, _ := a.completionFile("bash")
	cur, _ := os.ReadFile(f)
	if !strings.Contains(string(cur), "# impr-version: "+stamp+"\n") {
		t.Fatalf("the generated header does not carry the version stamp:\n%.300s", cur)
	}
	body = strings.ReplaceAll(string(cur), "release", "an-old-value")
	if err := os.WriteFile(f, []byte(body), 0o644); err != nil { //nolint:gosec // a completion script
		t.Fatal(err)
	}
	return f, body
}

// O-97: a completion script impr installed is rewritten after an upgrade,
// once, quietly, as the PowerShell line's cache was: only when its version
// stamp is older than the running impr. A file impr did not write is never
// touched.
func TestInstalledCompletionFollowsAnUpgrade(t *testing.T) {
	h := newHarness(t)
	h.home = t.TempDir()
	f, _ := stampedBash(t, h, "1.4.0")
	withVersion(t, "1.5.0")
	h.ok("path")
	now, _ := os.ReadFile(f)
	want, _ := CompletionScript("bash")
	if string(now) != want || !strings.Contains(want, "# impr-version: 1.5.0\n") {
		t.Fatal("the installed script was not brought up to date")
	}
	// Exactly one write: once stamped 1.5.0, a 1.5.0 impr leaves it alone.
	edited := strings.ReplaceAll(want, "release", "edited-after")
	if err := os.WriteFile(f, []byte(edited), 0o644); err != nil { //nolint:gosec // a completion script
		t.Fatal(err)
	}
	h.ok("path")
	if again, _ := os.ReadFile(f); string(again) != edited {
		t.Fatal("the script was written a second time by the same version")
	}
	a := &App{Home: h.home, Getenv: func(k string) string { return h.env[k] }}
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

// The same version, an older impr and a dev build never write the home
// folder's completion script.
func TestCompletionRefreshNeverDowngradesOrRewritesTheSameVersion(t *testing.T) {
	for _, c := range []struct{ name, stamp, running string }{
		{"same version", "1.5.0", "1.5.0"},
		{"older impr", "1.5.0", "1.4.9"},
		{"older pre-release", "1.5.0", "1.5.0-rc.2"},
		{"dev build", "1.4.0", "dev"},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			h.home = t.TempDir()
			f, body := stampedBash(t, h, c.stamp)
			withVersion(t, c.running)
			h.ok("path")
			if now, _ := os.ReadFile(f); string(now) != body {
				t.Fatalf("impr %s rewrote a script stamped %s", c.running, c.stamp)
			}
		})
	}
}

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.5.0", "1.4.0", 1}, {"v1.5.0", "1.5.0", 0}, {"1.10.0", "1.9.9", 1}, {"1.5.0", "1.5.0-rc.1", 1},
		{"1.5.0-rc.10", "1.5.0-rc.2", 1}, {"1.5.0-beta.1", "1.5.0-alpha.9", 1}, {"1.5.0-rc.1", "1.5.0-rc", 1},
		{"2.0.0+build.1", "2.0.0", 0},
	} {
		got, ok := compareVersions(c.a, c.b)
		if !ok || got != c.want {
			t.Errorf("compareVersions(%s, %s) = %d %v, want %d", c.a, c.b, got, ok, c.want)
		}
		if back, _ := compareVersions(c.b, c.a); back != -c.want {
			t.Errorf("compareVersions(%s, %s) = %d, want %d", c.b, c.a, back, -c.want)
		}
	}
	for _, bad := range []string{"dev", "", "1.2", "1.2.x", "01.2.3"} {
		if _, ok := compareVersions(bad, "1.0.0"); ok {
			t.Errorf("%q read as a version", bad)
		}
	}
}

// The user PATH is written back with the user's own entries byte for byte
// (spaces and empty entries kept), and a folder already there under a %VAR%
// reference, in another case or with a trailing backslash is not added again.
func TestInstallKeepsTheUserPathAsItWas(t *testing.T) {
	h := newHarness(t)
	h.os = "windows"
	h.env["PATH"] = `C:\Windows`
	h.env["USERPROFILE"] = `C:\Users\Pat`
	for name, tc := range map[string]struct{ cur, dir, want string }{
		"spaces and empty entries kept": {`C:\Tools;; C:\Go\bin ;`, `D:\impr`, `C:\Tools;; C:\Go\bin ;D:\impr`},
		"no trailing separator":         {` C:\Tools`, `D:\impr`, ` C:\Tools;D:\impr`},
		"empty":                         {``, `D:\impr`, `D:\impr`},
		"a %VAR% reference":             {`C:\Tools;%USERPROFILE%\.local\bin`, `C:\Users\Pat\.local\bin`, `C:\Tools;%USERPROFILE%\.local\bin`},
		"case and a trailing backslash": {`c:\users\pat\.LOCAL\bin\;C:\Tools`, `C:\Users\Pat\.local\bin`, `c:\users\pat\.LOCAL\bin\;C:\Tools`},
		"a %var% in another case":       {`%userprofile%\.local\bin`, `C:\Users\Pat\.local\bin`, `%userprofile%\.local\bin`},
	} {
		up := &fakeUserPath{value: tc.cur}
		withUserPath(t, up)
		a := &App{Stderr: &bytes.Buffer{}, Stdout: &bytes.Buffer{}, GOOS: "windows", Getenv: func(k string) string { return h.env[k] }}
		if !a.addToUserPath(tc.dir, true) {
			t.Errorf("%s: not on the user PATH", name)
		}
		if up.value != tc.want {
			t.Errorf("%s: user PATH %q, want %q", name, up.value, tc.want)
		}
		if tc.want == tc.cur && up.sets != 0 {
			t.Errorf("%s: written although the folder was there", name)
		}
	}
}

// Both install questions read one input: the second answer is not lost to
// the first question's buffer.
func TestInstallQuestionsShareTheInput(t *testing.T) {
	h := newHarness(t)
	h.os = "windows"
	h.home = t.TempDir()
	h.env["PATH"] = `C:\Windows`
	h.env["SHELL"] = "/bin/bash"
	up := &fakeUserPath{value: `C:\Tools`}
	withUserPath(t, up)
	dir := t.TempDir()
	if code, errOut := runAt(t, h, "y\nn\n", "install", "--dir", dir); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if up.value != `C:\Tools;`+dir {
		t.Fatalf("the first yes was not taken: %q", up.value)
	}
	f, _ := (&App{Home: h.home, Getenv: func(k string) string { return h.env[k] }}).completionFile("bash")
	if _, owned := completionOwned(f, "bash"); owned {
		t.Fatal("the second answer, no, was lost: completion was installed")
	}
}
