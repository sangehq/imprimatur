package cli

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func replayDoc(t *testing.T, out string) ReplayResult {
	t.Helper()
	var r ReplayResult
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	return r
}

func TestEventsReplay(t *testing.T) {
	h := newHarness(t)
	secret := strings.TrimSpace(h.ok("webhooks", "secret"))
	h.env["IMPR_WH"] = secret

	// A receiver on loopback, when this host lets tests listen.
	var mu sync.Mutex
	var got []string
	url := "https://receiver.example.com/hooks/impr"
	allowPrivate := false
	if ln, err := net.Listen("tcp", "127.0.0.1:0"); err == nil {
		_ = ln.Close()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			got = append(got, r.Header.Get("webhook-id")+" "+string(b))
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		}))
		defer srv.Close()
		url, allowPrivate = srv.URL, true
	}
	sub := map[string]any{"name": "recv", "url": url, "secretRef": "env://IMPR_WH", "allowPrivate": allowPrivate, "types": []string{"profile.*"}}
	b, _ := json.Marshal([]any{sub})
	h.ok("config", "set", "webhooks.outbound", string(b))

	// Events that happened before anything was delivered.
	for _, n := range []string{"a1", "a2", "a3"} {
		h.ok("profile", "add", n, "--scope", "personal", "--owner", "me", "--purpose", "test",
			"--set", "platforms.checksums.kind=ssh", "--set", "platforms.checksums.keyRef=env://K",
			"--set", "platforms.checksums.fingerprint=SHA256:"+strings.Repeat("A", 43))
	}

	r := replayDoc(t, h.ok("events", "replay", "--to", "recv", "--dry-run", "--json"))
	if !r.DryRun || r.Matched < 3 || r.Sent != r.Matched-r.Delivered {
		t.Fatalf("dry run: %+v", r)
	}
	if r := replayDoc(t, h.ok("events", "replay", "--to", "recv", "--dry-run", "--limit", "1", "--json")); r.Sent != 1 {
		t.Fatalf("--limit 1 sent %d", r.Sent)
	}
	if r := replayDoc(t, h.ok("events", "replay", "--to", "recv", "--dry-run", "--type", "config.*", "--json")); r.Matched != 0 {
		t.Fatalf("a type the subscription does not want matched: %+v", r)
	}
	h.exits(1, "events", "replay", "--to", "nobody")
	h.exits(1, "events", "replay")
	h.exits(1, "events", "replay", "--to", "recv", "--since", "yesterday")

	if !allowPrivate {
		t.Log("no loopback listener here (sandbox); the delivery half runs in CI")
		return
	}
	first := replayDoc(t, h.ok("events", "replay", "--to", "recv", "--json"))
	if first.Sent < 3 || first.Pending != 0 {
		t.Fatalf("replay: %+v", first)
	}
	mu.Lock()
	n := len(got)
	mu.Unlock()
	if n < 3 || !strings.Contains(got[0], "profile.created") {
		t.Fatalf("the receiver got %d deliveries: %v", n, got)
	}
	// Delivered events are not sent again, unless --force.
	if again := replayDoc(t, h.ok("events", "replay", "--to", "recv", "--json")); again.Sent != 0 || again.Delivered < 3 {
		t.Fatalf("second replay resent delivered events: %+v", again)
	}
	if forced := replayDoc(t, h.ok("events", "replay", "--to", "recv", "--force", "--json")); forced.Sent < 3 {
		t.Fatalf("--force: %+v", forced)
	}
	done, _ := filepath.Glob(filepath.Join(h.env["IMPR_STATE_DIR"], "outbox", "done", "recv--*.json"))
	if len(done) < 3 {
		t.Fatalf("outbox done: %v", done)
	}
	_ = os.Remove
}

func TestWebhooksAddRotateRemove(t *testing.T) {
	h := newHarness(t)
	list := func() []map[string]any {
		t.Helper()
		var r struct {
			Subscriptions []map[string]any `json:"subscriptions"`
		}
		if err := json.Unmarshal([]byte(h.ok("webhooks", "list", "--json")), &r); err != nil {
			t.Fatal(err)
		}
		return r.Subscriptions
	}
	h.exits(1, "webhooks", "add", "bus") // no --url / --secret-ref
	h.ok("webhooks", "add", "bus", "--url", "https://bus.example.com/hooks/impr", "--secret-ref", "env://WH_A", "--types", "signing.*,cert.*")
	if l := list(); len(l) != 1 || l[0]["name"] != "bus" || l[0]["secretRef"] != "env://WH_A" {
		t.Fatalf("after add: %v", l)
	}
	h.exits(1, "webhooks", "add", "bus", "--url", "https://bus.example.com/x", "--secret-ref", "env://WH_A")   // duplicate
	h.exits(1, "webhooks", "add", "evil", "--url", "http://169.254.169.254/", "--secret-ref", "env://WH_A")    // SSRF target
	h.exits(1, "webhooks", "add", "bad", "--url", "https://bus.example.com/x", "--secret-ref", "whsec_inline") // not a reference

	h.ok("webhooks", "rotate", "bus", "--secret-ref", "env://WH_B")
	if l := list(); l[0]["secretRef"] != "env://WH_B" || l[0]["previousSecretRef"] != "env://WH_A" {
		t.Fatalf("after rotate: %v", l)
	}
	h.ok("webhooks", "rotate", "bus", "--finish")
	if l := list(); l[0]["previousSecretRef"] != nil {
		t.Fatalf("after finish: %v", l)
	}
	h.exits(1, "webhooks", "rotate", "bus", "--finish") // nothing to finish
	h.ok("webhooks", "rm", "bus")
	if l := list(); len(l) != 0 {
		t.Fatalf("after rm: %v", l)
	}
	h.exits(1, "webhooks", "rm", "bus")
}

func TestRotationIsAnEvent(t *testing.T) {
	h := newHarness(t)
	h.ok("webhooks", "add", "bus", "--url", "https://bus.example.com/hooks/impr", "--secret-ref", "env://WH_A")
	h.ok("webhooks", "rotate", "bus", "--secret-ref", "env://WH_B")
	h.ok("webhooks", "rotate", "bus", "--finish")
	out := h.ok("events", "tail", "--json", "--type", "webhook.*")
	if strings.Count(out, `"type":"com.simtabi.sange.imprimatur.webhook.secret.rotated"`) != 2 || !strings.Contains(out, `"step":"started"`) || !strings.Contains(out, `"step":"finished"`) {
		t.Fatalf("rotation events: %s", out)
	}
}
