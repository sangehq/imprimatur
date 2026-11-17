package rules

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"strings"
	"testing"
)

func wellFormed(doc string) error {
	d := xml.NewDecoder(strings.NewReader(doc))
	for {
		if _, err := d.Token(); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// FuzzRender: no request panics the renderer, and every policy it accepts is
// well-formed XML, so no field can inject markup into a policy.
func FuzzRender(f *testing.F) {
	seed := []byte(`{"contract":1,"manifestDigest":"sha256:` + strings.Repeat("a", 64) + `","version":"v1.8.0","fileVersion":"1.8.0.0",` +
		`"publisher":{"subject":"O=ACME LTD, L=LONDON, C=GB","leafCn":"Acme Ltd","issuerName":"Acme CA","issuerTbs":"` + strings.Repeat("B", 64) +
		`","eku":"1.3.6.1.4.1.311.97.1.0","product":"tool"},"files":[{"path":"build/windows/tool.exe","sha256":"` + strings.Repeat("c", 64) +
		`","collection":"Exe","binaryName":"tool.exe"}],"options":{"name":"tool","basePolicyId":"{A244370E-44C9-4C06-B551-F6016E563076}","appLocker":true,"wdac":true}}`)
	f.Add(seed)
	f.Add([]byte(strings.Replace(string(seed), "Acme Ltd", `Acme"/><Deny Id="x`, 1)))
	f.Add([]byte(strings.Replace(string(seed), "tool.exe", "<tool>&amp;.exe", 1)))
	f.Fuzz(func(t *testing.T, b []byte) {
		var req Request
		if json.Unmarshal(b, &req) != nil {
			return
		}
		res, err := Render(req, "imprimatur")
		if err != nil {
			return
		}
		for name, doc := range map[string]string{"AppLocker": res.AppLocker, "WDAC": res.WDAC} {
			if doc == "" {
				continue
			}
			if err := wellFormed(doc); err != nil {
				t.Fatalf("%s policy is not well-formed XML: %v", name, err)
			}
		}
	})
}
