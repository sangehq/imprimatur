package webhook

import (
	"net/http"
	"testing"
	"time"
)

// FuzzVerify: no headers or body panic the verifier, and nothing verifies
// against a key that did not sign it.
func FuzzVerify(f *testing.F) {
	f.Add("msg_1", "1700000000", "v1,K5oZfzN95Z9UVu1EsfQmfVNQhnkZ2pj9o9NDN/H/pI4=", []byte(`{"a":1}`))
	f.Add("", "", "", []byte{})
	f.Add("id", "-1", "v1a,AAAA v1,", []byte("x"))
	key := []byte("an unguessable fuzz key, 32 bytes")
	f.Fuzz(func(t *testing.T, id, ts, sig string, body []byte) {
		h := http.Header{}
		h.Set("webhook-id", id)
		h.Set("webhook-timestamp", ts)
		h.Set("webhook-signature", sig)
		if _, err := Verify(h, body, [][]byte{key}, time.Unix(1700000000, 0), 5*time.Minute); err == nil {
			t.Fatalf("an unsigned delivery verified: %q %q %q", id, ts, sig)
		}
	})
}
