package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sangehq/imprimatur/src/internal/execx"
)

func TestRulesTestAsksWindowsAndFailsOnADenial(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	policy := filepath.Join(dir, "applocker.xml")
	if err := os.WriteFile(policy, []byte("<AppLockerPolicy/>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := h.impr("rules", "test", "--policy", policy, filepath.Join(dir, "tool.exe")); code != 5 || !strings.Contains(errOut, "Windows only") {
		if h.os != "windows" {
			t.Fatalf("off Windows: %d %s", code, errOut)
		}
	}
	answer := `[{"path":"C:\\b\\tool.exe","decision":"Allowed","rule":"imprimatur: TOOL.EXE"}]`
	f := execx.NewFake("powershell")
	f.Handle = func(c execx.Cmd) execx.Result { return execx.Result{Stdout: []byte(answer)} }
	h.os, h.run = "windows", f
	out := h.ok("rules", "test", "--json", "--policy", policy, filepath.Join(dir, "tool.exe"))
	if !strings.Contains(out, `"ok":true`) || !strings.Contains(out, `"decision":"Allowed"`) {
		t.Fatalf("allowed: %s", out)
	}
	// S-16: the one inline form, with the inputs in the environment only.
	if len(f.Calls) != 1 || !slices.Equal(f.Calls[0].Args, execx.PowerShellArgs()) ||
		!slices.Contains(f.Calls[0].Env, "IMPR_TAL_POLICY="+policy) {
		t.Fatalf("calls: %+v", f.Calls)
	}
	answer = `[{"path":"C:\\b\\tool.exe","decision":"DeniedByDefault","rule":""}]`
	h.exits(4, "rules", "test", "--json", "--policy", policy, filepath.Join(dir, "tool.exe"))
}

// Found on the Windows devbox: an answer that does not cover every file (an
// empty array) is not "allowed". impr rules test fails instead of passing
// what was never tested.
func TestRulesTestFailsWhenAFileHasNoAnswer(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	policy := filepath.Join(dir, "applocker.xml")
	if err := os.WriteFile(policy, []byte("<AppLockerPolicy/>"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, answer := range []string{`[]`, `[{"path":"C:\\b\\a.exe","decision":"Allowed","rule":"r"}]`} {
		f := execx.NewFake("powershell")
		f.Handle = func(execx.Cmd) execx.Result { return execx.Result{Stdout: []byte(answer)} }
		h.os, h.run = "windows", f
		code, out, _ := h.impr("rules", "test", "--json", "--policy", policy, filepath.Join(dir, "a.exe"), filepath.Join(dir, "b.exe"))
		if code == 0 || strings.Contains(out, `"ok":true`) {
			t.Errorf("answer %s for two files passed: %d %s", answer, code, out)
		}
	}
}
