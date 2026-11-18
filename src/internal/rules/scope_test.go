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

// Old bug 12: the WDAC PolicyID is the same for every build of one product
// against one base policy, so redeploying replaces the supplemental policy
// instead of adding another; and --enforce, which a supplemental policy
// cannot take, says so instead of passing silently.
func TestWDACPolicyIDStableAndEnforceNoted(t *testing.T) {
	id := func(req Request) string {
		res, err := Render(req, "test")
		if err != nil {
			t.Fatal(err)
		}
		i := strings.Index(res.WDAC, "<PolicyID>")
		return res.WDAC[i : i+60]
	}
	a, b := request(t), request(t) // two builds: new digests, new file hashes
	b.FileVersion = "1.9.0.0"
	if id(a) != id(b) {
		t.Fatalf("two builds of one product got different PolicyIDs: %s %s", id(a), id(b))
	}
	c := request(t)
	c.Publisher.Product = "other"
	if id(a) == id(c) {
		t.Fatalf("two products share a PolicyID")
	}
	e := request(t)
	e.Options.Enforce = true
	res, err := Render(e, "test")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(res.Notes, "\n"), "--enforce does not apply to the WDAC supplemental policy") {
		t.Fatalf("no note that --enforce does not reach WDAC: %v", res.Notes)
	}
}

// Old security finding 15 (ID-25): impr's allow rules apply to BUILTIN\Users
// by default, not Everyone (which also covers anonymous and service
// identities); an explicit SID is kept, and the result names the user.
func TestAllowRulesDefaultToBuiltinUsers(t *testing.T) {
	allowSIDs := func(xml string) []string {
		var sids []string
		for _, line := range strings.Split(xml, "\n") {
			if strings.Contains(line, "<FilePublisherRule") {
				i := strings.Index(line, `UserOrGroupSid="`)
				sids = append(sids, strings.SplitN(line[i+16:], `"`, 2)[0])
			}
		}
		return sids
	}
	req := request(t)
	req.Options.UserOrGroupSID = ""
	res, err := Render(req, "test")
	if err != nil {
		t.Fatal(err)
	}
	sids := allowSIDs(res.AppLocker)
	if len(sids) == 0 {
		t.Fatalf("no allow rules found:\n%s", res.AppLocker)
	}
	for _, s := range sids {
		if s != "S-1-5-32-545" {
			t.Fatalf("an allow rule is for %s, want S-1-5-32-545", s)
		}
	}
	if !strings.Contains(strings.Join(res.Notes, "\n"), `BUILTIN\Users`) {
		t.Fatalf("no note naming the user: %v", res.Notes)
	}
	req.Options.UserOrGroupSID = "S-1-5-21-1-2-3-1001"
	res, _ = Render(req, "test")
	for _, s := range allowSIDs(res.AppLocker) {
		if s != "S-1-5-21-1-2-3-1001" {
			t.Fatalf("an explicit SID was not kept: %s", s)
		}
	}
}
