package cli

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sangehq/imprimatur/src/internal/config"
	"github.com/sangehq/imprimatur/src/internal/webhook"
)

func TestEd25519WebhookKeys(t *testing.T) {
	h := newHarness(t)
	code, out, errOut := h.impr("webhooks", "secret", "--ed25519")
	sk := strings.TrimSpace(out)
	if code != 0 || !strings.HasPrefix(sk, webhook.SigningKeyPrefix) || strings.Count(out, "\n") != 1 {
		t.Fatalf("exit %d, stdout %q", code, out)
	}
	pk := regexp.MustCompile(`whpk_[A-Za-z0-9+/=]+`).FindString(errOut)
	priv, err := webhook.DecodeSigningKey(sk)
	if err != nil || pk == "" || webhook.PublicKeyOf(priv) != pk || strings.Contains(errOut, sk) {
		t.Fatalf("public key %q (%v); stderr %s", pk, err, errOut)
	}

	h.env["WH_SK"] = sk
	a := &App{Stdout: &lockedBuffer{}, Stderr: &lockedBuffer{}, Getenv: func(k string) string { return h.env[k] }, GOOS: h.os,
		Home: t.TempDir(), User: "tester", Runner: h.run, Now: time.Now}
	cfg := config.Config{Webhooks: config.Webhooks{Outbound: []config.Outbound{{Name: "bus", URL: "https://bus.example.com/h", SecretRef: "env://WH_SK"}}}}
	subs, err := a.subscriptions(context.Background(), cfg)
	if err != nil || len(subs) != 1 || len(subs[0].SigningKeys) != 1 || len(subs[0].Keys) != 0 || !subs[0].SigningKeys[0].Equal(priv) {
		t.Fatalf("subscriptions %+v %v", subs, err)
	}
}
