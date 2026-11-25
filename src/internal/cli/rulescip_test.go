package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sangehq/imprimatur/src/internal/execx"
)

func rulesRequest(t *testing.T) string {
	t.Helper()
	req := map[string]any{"contract": 1, "manifestDigest": "sha256:" + randHex(t, 32), "commit": randHex(t, 20), "version": "v1.8.0", "fileVersion": "1.8.0.0",
		"publisher": map[string]any{"subject": "O=ACME LTD, L=LONDON, C=GB", "leafCn": "Acme Ltd", "issuerName": "Acme CA", "issuerTbs": strings.ToUpper(randHex(t, 32)), "product": "tool"},
		"files":     []map[string]any{{"path": "build/windows/tool.exe", "sha256": randHex(t, 32), "collection": "Exe", "binaryName": "tool.exe"}},
		"options":   map[string]any{"name": "tool", "basePolicyId": "{A244370E-44C9-4C06-B551-F6016E563076}", "appLocker": true, "wdac": true}}
	b, _ := json.Marshal(req)
	f := filepath.Join(t.TempDir(), "req.json")
	if err := os.WriteFile(f, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

// O-183: on Windows, impr rules compiles the WDAC policy it writes into a .cip
// with ConvertFrom-CIPolicy, through impr's own embedded script, which proves
// the XML is a policy Windows accepts, as the PowerShell line did. A policy
// that does not compile fails the run; a Windows without ConfigCI is skipped
// with a note; other hosts never run it.
func TestRulesCompilesTheWDACPolicyOnWindows(t *testing.T) {
	for name, tc := range map[string]struct {
		goos, answer string
		exit         int
		cip          bool
	}{
		"windows, compiled":    {"windows", "compiled", 0, true},
		"windows, no ConfigCI": {"windows", "skipped", 0, false},
		"windows, refused":     {"windows", "fail", 5, false},
		"linux":                {"linux", "compiled", 0, false},
	} {
		h := newHarness(t)
		h.os = tc.goos
		f := execx.NewFake("powershell")
		ran := 0
		f.Handle = func(c execx.Cmd) execx.Result {
			ran++
			if !strings.Contains(strings.Join(c.Args, " "), execx.CompileCIPolicyArgs()[3]) {
				t.Errorf("%s: powershell ran something else: %v", name, c.Args)
			}
			var out string
			for _, e := range c.Env {
				if v, ok := strings.CutPrefix(e, "IMPR_CIP_OUT="); ok {
					out = v
				}
			}
			switch tc.answer {
			case "compiled":
				_ = os.WriteFile(out, []byte("cip"), 0o600)
				return execx.Result{Stdout: []byte("compiled\n")}
			case "skipped":
				return execx.Result{Stdout: []byte("skipped\n")}
			}
			return execx.Result{ExitCode: 1, Stderr: []byte("ConvertFrom-CIPolicy: the policy is not valid")}
		}
		h.run = f
		dir := t.TempDir()
		code, _, errOut := h.impr("rules", "--request", rulesRequest(t), "--out-dir", dir)
		_, err := os.Stat(filepath.Join(dir, "wdac-supplemental.cip"))
		if code != tc.exit || (err == nil) != tc.cip {
			t.Errorf("%s: exit %d, .cip %v\n%s", name, code, err == nil, errOut)
		}
		if tc.goos != "windows" && ran != 0 {
			t.Errorf("%s: powershell ran off Windows", name)
		}
	}
}
