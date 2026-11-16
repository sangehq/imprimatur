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

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	for in, want := range map[string]time.Duration{
		"":                              0,
		"120":                           2 * time.Minute,
		"-5":                            0,
		"999999":                        24 * time.Hour,
		"Mon, 16 Nov 2026 12:05:00 GMT": 5 * time.Minute,
		"Mon, 16 Nov 2026 11:00:00 GMT": 0,
		"soon":                          0,
	} {
		if got := parseRetryAfter(in, now); got != want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", in, got, want)
		}
	}
}
