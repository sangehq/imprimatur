package webhook

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// The reference vector from the Standard Webhooks libraries' own tests: the
// same secret, id, timestamp and body must give the same v1 signature, or a
// receiver using those libraries would refuse every delivery.
func TestStandardWebhooksReferenceVector(t *testing.T) {
	// @credential-literal-exempt: the published Standard Webhooks library test vector; the exact bytes are the point
	referenceVector := "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
	key, err := DecodeSecret(referenceVector)
	if err != nil {
		t.Fatal(err)
	}
	got := Signature([][]byte{key}, "msg_p5jXN8AQM9LWM0D4loKWxJek", 1614265330, []byte(`{"test": 2432232314}`))
	if want := "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="; got != want {
		t.Fatalf("signature %s, want %s", got, want)
	}
}

func TestVerifyRoundTripRotationAndRefusals(t *testing.T) {
	s1, _ := NewSecret()
	s2, _ := NewSecret()
	k1, _ := DecodeSecret(s1)
	k2, _ := DecodeSecret(s2)
	now := time.Unix(1_800_000_000, 0)
	body := []byte(`{"specversion":"1.0"}`)
	h := http.Header{}
	SetHeaders(h, [][]byte{k1, k2}, "id-1", now, body) // rotation: two signatures
	if strings.Count(h.Get(HeaderSignature), "v1,") != 2 {
		t.Fatalf("rotation header: %s", h.Get(HeaderSignature))
	}
	if kid, err := Verify(h, body, [][]byte{k2}, now, 0); err != nil || kid != KeyID(k2) {
		t.Fatalf("new key: %s %v", kid, err)
	}
	other, _ := NewSecret()
	ko, _ := DecodeSecret(other)
	cases := map[string]func() (http.Header, []byte, [][]byte, time.Time){
		"wrong key":    func() (http.Header, []byte, [][]byte, time.Time) { return h, body, [][]byte{ko}, now },
		"changed body": func() (http.Header, []byte, [][]byte, time.Time) { return h, []byte(`{}`), [][]byte{k1}, now },
		"stale": func() (http.Header, []byte, [][]byte, time.Time) {
			return h, body, [][]byte{k1}, now.Add(6 * time.Minute)
		},
		"future": func() (http.Header, []byte, [][]byte, time.Time) {
			return h, body, [][]byte{k1}, now.Add(-6 * time.Minute)
		},
		"missing header": func() (http.Header, []byte, [][]byte, time.Time) { return http.Header{}, body, [][]byte{k1}, now },
		"other scheme only": func() (http.Header, []byte, [][]byte, time.Time) {
			x := h.Clone()
			x.Set(HeaderSignature, strings.ReplaceAll(x.Get(HeaderSignature), "v1,", "v0,"))
			return x, body, [][]byte{k1}, now
		},
	}
	for name, c := range cases {
		hh, b, keys, at := c()
		if _, err := Verify(hh, b, keys, at, 0); err == nil {
			t.Errorf("%s verified", name)
		}
	}
	for _, bad := range []string{"secret", "whsec_!!", "whsec_" + strings.Repeat("A", 8)} {
		if _, err := DecodeSecret(bad); err == nil {
			t.Errorf("%q decoded", bad)
		}
	}
}
