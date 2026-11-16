package redact

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func rnd(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func TestRedactsEverySecretShape(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte(rnd(t, 24)))
	cases := map[string]string{
		"webhook secret": "secret whsec_" + b64 + " in a message",
		"api token":      "token impr_" + rnd(t, 20) + " here",
		"pem key":        "-----BEGIN EC PRIVATE KEY-----\n" + b64 + "\n-----END EC PRIVATE KEY-----",
		"pem cut short":  "-----BEGIN PRIVATE KEY-----\n" + b64,
		"key=value":      "connect with password=" + rnd(t, 6) + " now",
		"bearer":         "Authorization: Bearer " + rnd(t, 16),
		"url userinfo":   "https://alice:" + rnd(t, 6) + "@example.com/repo.git",
		"github token":   "ghp_" + rnd(t, 18),
		"github pat":     "github_pat_" + rnd(t, 12),
		"slack":          "xoxb-" + rnd(t, 8),
		"aws key id":     "AKIA" + strings.ToUpper(rnd(t, 8)),
	}
	for name, in := range cases {
		out := String(in)
		if !strings.Contains(out, Mask) || !Found(in) {
			t.Errorf("%s: not redacted: %q", name, out)
		}
	}
	if got := String("https://alice:" + "x9" + "@example.com/r"); got != "https://"+Mask+"@example.com/r" {
		t.Errorf("url keeps scheme and host: %q", got)
	}
}

func TestLeavesOrdinaryTextAlone(t *testing.T) {
	for _, s := range []string{
		"sha256:" + rnd(t, 32),
		"SHA256:" + base64.RawStdEncoding.EncodeToString([]byte(rnd(t, 16))),
		"impr server token add --scopes read,verify",
		"curl -H \"Authorization: Bearer $IMPR_TOKEN\" http://impr/v1/profiles",
		"secretRef must be a secret:// or env:// reference",
		"git@github.com:acme/tool.git",
		"https://github.com/acme/tool",
		"impr_short",
	} {
		if Found(s) {
			t.Errorf("redacted ordinary text: %q -> %q", s, String(s))
		}
	}
}
