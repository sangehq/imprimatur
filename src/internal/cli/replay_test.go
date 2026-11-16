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
