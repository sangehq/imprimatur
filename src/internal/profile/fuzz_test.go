package profile

import (
	"encoding/json"
	"testing"
)

// FuzzCheck: no profile document panics the strict decoder, and a valid one
// has a stable pinned-identity digest across a re-encode.
func FuzzCheck(f *testing.F) {
	f.Add([]byte(`{"name":"me-test","scope":"personal","owner":"me","purpose":["test"],"platforms":{"checksums":{"kind":"ssh","keyRef":"env://K","fingerprint":"SHA256:abc"}}}`))
	f.Add([]byte(`{"name":"x","scope":"client:acme","owner":"acme","purpose":["release"],"allowedRepos":["github.com/acme/*"],"platforms":{"windows":{"kind":"authenticode","signers":[{"id":"a","backend":"certum","thumbprint":"AB"}]}}}`))
	f.Add([]byte(`{"name":"x","privateKey":"-----BEGIN"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		p, ps, err := Check(b)
		if err != nil || len(ps) > 0 {
			return
		}
		d := p.Pinned().Digest()
		raw, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		q, ps, err := Check(raw)
		if err != nil || len(ps) > 0 || q.Pinned().Digest() != d {
			t.Fatalf("a valid profile changed on re-encode: %v %v", err, ps)
		}
	})
}
