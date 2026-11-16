package server

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sangehq/imprimatur/src/internal/config"
)

// adminFixture is a server with read and admin tokens, and allowAdmin as given.
func adminFixture(t *testing.T, allowAdmin bool) (http.Handler, *fakeRun, string, string, string) {
	t.Helper()
	read, rt := token(t, "read")
	admin, at := token(t, "admin")
	cfg := config.Config{Schema: config.Schema, Server: config.Server{AllowAdmin: allowAdmin, Tokens: []config.Token{rt, at}}}
	if ps := cfg.Validate(); len(ps) > 0 {
		t.Fatal(ps)
	}
	f := &fakeRun{}
	state := t.TempDir()
	return Handler(Options{Config: cfg, Run: f.run, StateDir: state, Now: time.Now}), f, read, admin, state
}

func TestAdminEndpointsNeedTheScopeAndTheSwitch(t *testing.T) {
	h, f, read, admin, _ := adminFixture(t, false)
	body := `{"name":"bus","url":"https://bus.example.com/hooks/impr","secretRef":"env://WH","types":["signing.*"]}`
	if r := do(h, "GET", "/v1/webhooks", read, "", nil); r.Code != 403 {
		t.Fatalf("read token listed webhooks: %d", r.Code)
	}
	if r := do(h, "GET", "/v1/webhooks", admin, "", nil); r.Code != 200 || f.last() != "webhooks list --json" {
		t.Fatalf("admin list: %d %s", r.Code, f.last())
	}
	if r := do(h, "POST", "/v1/webhooks", admin, body, nil); r.Code != 403 || !strings.Contains(r.Body.String(), "allowAdmin") {
		t.Fatalf("add without allowAdmin: %d %s", r.Code, r.Body)
	}
	if r := do(h, "DELETE", "/v1/webhooks/bus", admin, "", nil); r.Code != 403 {
		t.Fatalf("rm without allowAdmin: %d", r.Code)
	}

	h, f, read, admin, _ = adminFixture(t, true)
	if r := do(h, "POST", "/v1/webhooks", read, body, nil); r.Code != 403 {
		t.Fatalf("read token added a webhook: %d", r.Code)
	}
	if r := do(h, "POST", "/v1/webhooks", admin, body, nil); r.Code != 200 ||
		f.last() != "webhooks add bus --url=https://bus.example.com/hooks/impr --secret-ref=env://WH --types=signing.* --json" {
		t.Fatalf("add: %d %s", r.Code, f.last())
	}
	for name, b := range map[string]string{
		"inline secret":  strings.Replace(body, "env://WH", "whsec_abc", 1),
		"option as name": strings.Replace(body, `"bus"`, `"--force"`, 1),
		"bad url":        strings.Replace(body, "https://bus.example.com/hooks/impr", "file:///etc/passwd", 1),
		"bad type":       strings.Replace(body, "signing.*", "--json", 1),
		"unknown field":  strings.Replace(body, `"name"`, `"exec":"x","name"`, 1),
	} {
		if r := do(h, "POST", "/v1/webhooks", admin, b, nil); r.Code != 400 {
			t.Errorf("%s: %d, want 400", name, r.Code)
		}
	}
	if r := do(h, "DELETE", "/v1/webhooks/bus", admin, "", nil); r.Code != 200 || f.last() != "webhooks rm bus --json" {
		t.Fatalf("rm: %d %s", r.Code, f.last())
	}
	if r := do(h, "POST", "/v1/webhooks/bus/test", admin, "", nil); r.Code != 200 || f.last() != "webhooks test bus --json" {
		t.Fatalf("test: %d %s", r.Code, f.last())
	}
}

func TestRulesAndCapabilitiesEndpoints(t *testing.T) {
	h, f, read, _, state := adminFixture(t, false)
	if r := do(h, "GET", "/v1/profiles/acme-release/capabilities", read, "", nil); r.Code != 200 || f.last() != "profile capabilities acme-release --json" {
		t.Fatalf("capabilities: %d %s", r.Code, f.last())
	}
	// The rules request reaches impr rules as a private file, removed afterwards.
	var seen string
	var mu sync.Mutex
	f2 := &fakeRun{}
	cfgRun := func(ctx context.Context, args []string) (int, []byte) {
		for _, a := range args {
			if p, ok := strings.CutPrefix(a, "--request="); ok {
				b, _ := os.ReadFile(p)
				st, _ := os.Stat(p)
				mu.Lock()
				seen = string(b) + " " + st.Mode().Perm().String() + " " + p
				mu.Unlock()
			}
		}
		return f2.run(ctx, args)
	}
	read2, rt2 := token(t, "read")
	h2 := Handler(Options{Config: config.Config{Schema: config.Schema, Server: config.Server{Tokens: []config.Token{rt2}}},
		Run: cfgRun, StateDir: state, Now: time.Now})
	if r := do(h2, "POST", "/v1/rules", read2, `{"contract":1}`, nil); r.Code != 200 || !strings.HasPrefix(f2.last(), "rules --strict --request=") {
		t.Fatalf("rules: %d %s", r.Code, f2.last())
	}
	if !strings.HasPrefix(seen, `{"contract":1} -rw-------`) {
		t.Fatalf("the request file: %q", seen)
	}
	if left, _ := filepath.Glob(filepath.Join(state, "server", "rules-*")); len(left) != 0 {
		t.Fatalf("the request file was left behind: %v", left)
	}
	if r := do(h2, "POST", "/v1/rules", read2, `not json`, nil); r.Code != 400 {
		t.Fatalf("a non-JSON request: %d", r.Code)
	}
	if r := do(h, "GET", "/v1/profiles/--json/capabilities", read, "", nil); r.Code != 400 {
		t.Fatalf("an option as a profile name: %d", r.Code)
	}
}
