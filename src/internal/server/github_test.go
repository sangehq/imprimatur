package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sangehq/imprimatur/src/internal/config"
)

func ghSign(secret string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	_, _ = m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

func TestGitHubInboundRecordsOrRuns(t *testing.T) {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	secret := hex.EncodeToString(b)
	cfg := config.Config{Schema: config.Schema, Server: config.Server{Roots: []string{filepath.ToSlash(t.TempDir())},
		Inbound: []config.Inbound{
			{Name: "gh-log", Kind: config.InboundGitHub, SecretRef: "env://GH", Allow: []string{"doctor"}, GitHubEvents: []string{"push"}},
			{Name: "gh-run", Kind: config.InboundGitHub, SecretRef: "env://GH", Allow: []string{"doctor"}, Run: "doctor"},
			{Name: "gh-weak", Kind: config.InboundGitHub, SecretRef: "env://WEAK", Allow: []string{"doctor"}},
		}}}
	if ps := cfg.Validate(); len(ps) > 0 {
		t.Fatal(ps)
	}
	var mu sync.Mutex
	var emitted []map[string]any
	f := &fakeRun{}
	h := Handler(Options{Config: cfg, Run: f.run, StateDir: t.TempDir(), Now: time.Now,
		Secret: func(_ context.Context, ref string) (string, error) {
			if ref == "env://WEAK" {
				return "short", nil
			}
			return secret, nil
		},
		Emit: func(short, _ string, data map[string]any) {
			mu.Lock()
			defer mu.Unlock()
			if short == "webhook.inbound.received" {
				emitted = append(emitted, data)
			}
		}})
	push := []byte(`{"ref":"refs/heads/main","repository":{"full_name":"acme/tool"}}`)
	send := func(endpoint, event, delivery string, body []byte, sig string) (int, string) {
		hdr := http.Header{}
		if sig != "" {
			hdr.Set("X-Hub-Signature-256", sig)
		}
		if event != "" {
			hdr.Set("X-GitHub-Event", event)
		}
		if delivery != "" {
			hdr.Set("X-GitHub-Delivery", delivery)
		}
		r := do(h, "POST", "/v1/hooks/"+endpoint, "", string(body), hdr)
		return r.Code, r.Body.String()
	}
	count := func() int { mu.Lock(); defer mu.Unlock(); return len(emitted) }

	for name, c := range map[string]struct {
		sig, event, delivery string
		want                 int
	}{
		"unsigned":    {"", "push", "d0", 401},
		"wrong key":   {ghSign("not the secret at all", push), "push", "d0", 401},
		"not sha256":  {strings.Replace(ghSign(secret, push), "sha256=", "sha1=", 1), "push", "d0", 401},
		"no delivery": {ghSign(secret, push), "push", "", 401},
	} {
		if code, body := send("gh-log", c.event, c.delivery, push, c.sig); code != c.want {
			t.Errorf("%s: %d, want %d: %s", name, code, c.want, body)
		}
	}
	ping := []byte(`{"zen":"Keep it logically awesome."}`)
	if code, body := send("gh-log", "ping", "p1", ping, ghSign(secret, ping)); code != 200 || !strings.Contains(body, `"pong"`) || count() != 0 {
		t.Fatalf("ping: %d %s, %d events", code, body, count())
	}
	if code, body := send("gh-log", "push", "d1", push, ghSign(secret, push)); code != 200 || !strings.Contains(body, `"recorded"`) {
		t.Fatalf("push: %d %s", code, body)
	}
	if count() != 1 || emitted[0]["repository"] != "acme/tool" || emitted[0]["event"] != "push" || f.last() != "" {
		t.Fatalf("recorded %v, ran %q", emitted, f.last())
	}
	if code, _ := send("gh-log", "push", "d1", push, ghSign(secret, push)); code != 409 {
		t.Fatalf("replay: %d", code)
	}
	if code, body := send("gh-log", "release", "d2", push, ghSign(secret, push)); code != 200 || !strings.Contains(body, `"ignored"`) || count() != 1 {
		t.Fatalf("a filtered event: %d %s, %d events", code, body, count())
	}
	if code, _ := send("gh-run", "push", "d3", push, ghSign(secret, push)); code != 200 || !strings.Contains(f.last(), "doctor") || count() != 2 {
		t.Fatalf("run: %d, ran %q, %d events", code, f.last(), count())
	}
	if code, _ := send("gh-weak", "push", "d4", push, ghSign("short", push)); code != 503 {
		t.Fatalf("a short secret: %d", code)
	}
}

func TestGitHubInboundConfig(t *testing.T) {
	for name, in := range map[string]config.Inbound{
		"public key":         {Name: "x", Kind: "github", SecretRef: "env://G", PublicKey: "whpk_" + strings.Repeat("A", 43) + "=", Allow: []string{"doctor"}},
		"no secret":          {Name: "x", Kind: "github", Allow: []string{"doctor"}},
		"run verify":         {Name: "x", Kind: "github", SecretRef: "env://G", Allow: []string{"verify"}, Run: "verify"},
		"run not allowed":    {Name: "x", Kind: "github", SecretRef: "env://G", Allow: []string{"doctor"}, Run: "cert.list"},
		"bad event name":     {Name: "x", Kind: "github", SecretRef: "env://G", Allow: []string{"doctor"}, GitHubEvents: []string{"Push!"}},
		"run on standard":    {Name: "x", SecretRef: "env://G", Allow: []string{"doctor"}, Run: "doctor"},
		"events on standard": {Name: "x", SecretRef: "env://G", Allow: []string{"doctor"}, GitHubEvents: []string{"push"}},
		"unknown kind":       {Name: "x", Kind: "gitlab", SecretRef: "env://G", Allow: []string{"doctor"}},
	} {
		c := config.Config{Schema: config.Schema, Server: config.Server{Inbound: []config.Inbound{in}}}
		if len(c.Validate()) == 0 {
			t.Errorf("%s was accepted", name)
		}
	}
}
