package rules

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestFuzzSeedRenders proves FuzzRender's seed is a request Render accepts,
// so the fuzzer starts from the accepting path, not only from refusals.
func TestFuzzSeedRenders(t *testing.T) {
	var req Request
	seed := `{"contract":1,"manifestDigest":"sha256:` + strings.Repeat("a", 64) + `","version":"v1.8.0","fileVersion":"1.8.0.0",` +
		`"publisher":{"subject":"O=ACME LTD, L=LONDON, C=GB","leafCn":"Acme Ltd","issuerName":"Acme CA","issuerTbs":"` + strings.Repeat("B", 64) +
		`","eku":"1.3.6.1.4.1.311.97.1.0","product":"tool"},"files":[{"path":"build/windows/tool.exe","sha256":"` + strings.Repeat("c", 64) +
		`","collection":"Exe","binaryName":"tool.exe"}],"options":{"name":"tool","basePolicyId":"{A244370E-44C9-4C06-B551-F6016E563076}","appLocker":true,"wdac":true}}`
	if err := json.Unmarshal([]byte(seed), &req); err != nil {
		t.Fatal(err)
	}
	res, err := Render(req, "imprimatur")
	if err != nil || res.AppLocker == "" || res.WDAC == "" {
		t.Fatalf("the fuzz seed does not render: %v", err)
	}
	if err := wellFormed(res.AppLocker); err != nil {
		t.Fatal(err)
	}
}
