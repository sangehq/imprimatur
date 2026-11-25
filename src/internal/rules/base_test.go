package rules

import (
	"strings"
	"testing"
)

// O-182: a WDAC base policy, as the PowerShell line rendered without --base,
// only when asked for (basePolicy, impr rules --wdac-base): its own PolicyID
// as BasePolicyID, UMCI, and Audit Mode unless enforce. Without it, impr
// still renders supplemental policies only (threat I-15), and the two are
// exclusive.
func TestWDACBasePolicyOnlyByRequest(t *testing.T) {
	req := request(t)
	req.Options.BasePolicyID = ""
	if _, err := Render(req, "test"); err == nil {
		t.Fatal("a WDAC policy with no base policy id and no basePolicy was rendered")
	}
	req.Options.BasePolicy = true
	res, err := Render(req, "test")
	if err != nil {
		t.Fatal(err)
	}
	w := res.WDAC
	i, j := strings.Index(w, "<PolicyID>"), strings.Index(w, "<BasePolicyID>")
	if !strings.Contains(w, `PolicyType="Base Policy"`) || i < 0 || j < 0 || w[i+len("<PolicyID>"):i+len("<PolicyID>")+38] != w[j+len("<BasePolicyID>"):j+len("<BasePolicyID>")+38] {
		t.Fatalf("not a base policy naming itself:\n%s", w)
	}
	for _, want := range []string{"Enabled:Unsigned System Integrity Policy", "Enabled:UMCI", "Enabled:Audit Mode"} {
		if !strings.Contains(w, want) {
			t.Errorf("the base policy lacks %s", want)
		}
	}
	if !strings.Contains(strings.Join(res.Notes, "\n"), "block Windows itself") {
		t.Errorf("no warning against deploying it alone: %v", res.Notes)
	}
	req.Options.Enforce = true
	if res, _ := Render(req, "test"); strings.Contains(res.WDAC, "Enabled:Audit Mode") {
		t.Error("an enforced base policy is still in audit mode")
	}
	req.Options.BasePolicyID = "{A244370E-44C9-4C06-B551-F6016E563076}"
	if _, err := Render(req, "test"); err == nil {
		t.Fatal("basePolicy and basePolicyId together were rendered")
	}
}
