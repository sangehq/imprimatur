package rules

import (
	"strings"
	"testing"
)

// O-174, ID-11: the four scopes render what the PowerShell toolkit rendered
// (src/commands/rules.ps1:290-292 for AppLocker, :365-370 for WDAC).
func TestRuleScopesMatchPowerShell(t *testing.T) {
	cases := []struct {
		scope, fv     string
		product       string
		alProd, alBin string
		alLow         string
		wdac          []string // attributes the WDAC policy must carry
		wdacNot       []string
	}{
		{"publisher", "", "", "*", "*", "*", nil, []string{"FileAttrib "}},
		{"product", "", "tool", "TOOL", "*", "*", []string{`ProductName="tool"`, `MinimumFileVersion="0.0.0.0"`}, []string{`FileName=`}},
		{"file", "", "tool", "TOOL", "TOOL.EXE", "0.0.0.0", []string{`FileName="tool.exe"`, `MinimumFileVersion="0.0.0.0"`}, []string{`ProductName=`}},
		{"version", "1.8.0.0", "tool", "TOOL", "TOOL.EXE", "1.8.0.0", []string{`FileName="tool.exe"`, `MinimumFileVersion="1.8.0.0"`}, []string{`ProductName=`}},
	}
	for _, c := range cases {
		t.Run(c.scope, func(t *testing.T) {
			req := request(t)
			req.Scope, req.FileVersion, req.Publisher.Product = c.scope, c.fv, c.product
			res, err := Render(req, "test")
			if err != nil {
				t.Fatal(err)
			}
			want := `ProductName="` + c.alProd + `" BinaryName="` + c.alBin + `"`
			if !strings.Contains(res.AppLocker, want) || !strings.Contains(res.AppLocker, `LowSection="`+c.alLow+`"`) {
				t.Fatalf("AppLocker for %s: want %s, low %s\n%s", c.scope, want, c.alLow, res.AppLocker)
			}
			for _, w := range c.wdac {
				if !strings.Contains(res.WDAC, w) {
					t.Errorf("WDAC for %s lacks %s\n%s", c.scope, w, res.WDAC)
				}
			}
			for _, w := range c.wdacNot {
				if strings.Contains(res.WDAC, w) {
					t.Errorf("WDAC for %s carries %s\n%s", c.scope, w, res.WDAC)
				}
			}
		})
	}
	// Mismatched inputs are refused, not silently widened or narrowed.
	for _, bad := range []struct{ scope, fv, product string }{
		{"publisher", "", "tool"}, {"product", "", ""}, {"product", "1.0.0.0", "tool"},
		{"file", "1.0.0.0", "tool"}, {"version", "", "tool"}, {"hash", "", "tool"},
	} {
		req := request(t)
		req.Scope, req.FileVersion, req.Publisher.Product = bad.scope, bad.fv, bad.product
		if _, err := Render(req, "test"); err == nil {
			t.Errorf("scope %q fv %q product %q was accepted", bad.scope, bad.fv, bad.product)
		}
	}
}

// A request pinned to the generic Artifact Signing EKU still renders (sange
// passes the EKU its user set), but the result says how wide that is.
func TestRenderNotesTheGenericArtifactSigningEKU(t *testing.T) {
	res, err := Render(request(t), "test")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(res.Notes, "\n"), "every Artifact Signing customer") {
		t.Fatalf("no note about the generic EKU: %v", res.Notes)
	}
	req := request(t)
	req.Publisher.EKU = "1.3.6.1.4.1.311.97.990309390.766961637"
	if res, _ := Render(req, "test"); strings.Contains(strings.Join(res.Notes, "\n"), "every Artifact Signing customer") {
		t.Fatalf("a profile EKU drew the generic note: %v", res.Notes)
	}
}
