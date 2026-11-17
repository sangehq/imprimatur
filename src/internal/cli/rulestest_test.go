package cli

import (
	"os"
	"path/filepath"
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
	if len(f.Calls) != 1 || f.Calls[0].Args[6] != "-PolicyPath" {
		t.Fatalf("calls: %+v", f.Calls)
	}
	answer = `[{"path":"C:\\b\\tool.exe","decision":"DeniedByDefault","rule":""}]`
	h.exits(4, "rules", "test", "--json", "--policy", policy, filepath.Join(dir, "tool.exe"))
}
