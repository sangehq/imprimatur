package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sangehq/imprimatur/src/internal/config"
	"github.com/sangehq/imprimatur/src/internal/events"
	"github.com/sangehq/imprimatur/src/internal/webhook"
)

type fakeRun struct {
	mu    sync.Mutex
	calls [][]string
	code  int
}

func (f *fakeRun) run(_ context.Context, args []string) (int, []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, args)
	return f.code, []byte(`{"contract":1,"ok":true}`)
}

func (f *fakeRun) last() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		return ""
	}
	return strings.Join(f.calls[len(f.calls)-1], " ")
}

// token makes a generated API token and its config entry.
func token(t *testing.T, scopes ...string) (string, config.Token) {
	t.Helper()
	raw := "impr_" + base64.RawURLEncoding.EncodeToString([]byte(events.NewID() + events.NewID())[:32])
	sum := sha256.Sum256([]byte(raw))
	return raw, config.Token{ID: "tok_" + events.NewID()[:12], SHA256: hex.EncodeToString(sum[:]), Scopes: scopes}
}

type fixture struct {
	h     http.Handler
	run   *fakeRun
	root  string
	read  string
	ver   string
	signT string
	key   []byte
}

func setup(t *testing.T, allowSign bool) fixture {
	t.Helper()
	root := t.TempDir()
	read, rt := token(t, "read", "events")
	ver, vt := token(t, "verify")
	sig, st := token(t, "sign")
	sec, _ := webhook.NewSecret()
	key, _ := webhook.DecodeSecret(sec)
	cfg := config.Config{Schema: config.Schema, Server: config.Server{Roots: []string{root}, AllowSign: allowSign,
		Tokens:  []config.Token{rt, vt, st},
		Inbound: []config.Inbound{{Name: "sange", SecretRef: "env://K", Allow: []string{"verify"}}}}}
	if ps := cfg.Validate(); len(ps) > 0 {
		t.Fatal(ps)
	}
	f := &fakeRun{}
	h := Handler(Options{Config: cfg, Run: f.run, StateDir: t.TempDir(), Now: time.Now,
		Secret: func(context.Context, string) (string, error) { return sec, nil }})
	return fixture{h: h, run: f, root: root, read: read, ver: ver, signT: sig, key: key}
}

func do(h http.Handler, method, path, tok, body string, hdr http.Header) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range hdr {
		req.Header[k] = v
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAuthMatrix(t *testing.T) {
	f := setup(t, false)
	if r := do(f.h, "GET", "/v1/health", "", "", nil); r.Code != 200 {
		t.Fatalf("health %d", r.Code)
	}
	cases := []struct {
		name, method, path, tok, body string
		want                          int
	}{
		{"no token", "GET", "/v1/profiles", "", "", 401},
		{"malformed token", "GET", "/v1/profiles", "nope", "", 401},
		{"unknown token", "GET", "/v1/profiles", "impr_" + strings.Repeat("A", 43), "", 401},
		{"read token reads", "GET", "/v1/profiles", f.read, "", 200},
		{"read token cannot verify", "POST", "/v1/verify", f.read, `{}`, 403},
		{"verify token cannot read", "GET", "/v1/certs", f.ver, "", 403},
		{"sign is off by default", "POST", "/v1/sign", f.signT, `{}`, 403},
		{"bad profile name", "GET", "/v1/profiles/..%2Fx", f.read, "", 400},
	}
	for _, c := range cases {
		if r := do(f.h, c.method, c.path, c.tok, c.body, nil); r.Code != c.want {
			t.Errorf("%s: %d, want %d (%s)", c.name, r.Code, c.want, r.Body)
		}
	}
	// Every 401 carries the same body, so a caller learns nothing from it.
	a, b := do(f.h, "GET", "/v1/profiles", "", "", nil).Body.String(), do(f.h, "GET", "/v1/profiles", "impr_"+strings.Repeat("A", 43), "", nil).Body.String()
	if a != b {
		t.Errorf("401 bodies differ:\n%s\n%s", a, b)
	}
}

func TestVerifyStaysInsideRoots(t *testing.T) {
	f := setup(t, false)
	good := `{"root":"` + f.root + `","profile":"acme","signed":"build/impr-manifest.json","manifest":"build/m.json","strict":true}`
	if r := do(f.h, "POST", "/v1/verify", f.ver, good, nil); r.Code != 200 {
		t.Fatalf("verify %d %s", r.Code, r.Body)
	}
	want := "verify --root=" + f.root + " --profile=acme --strict --signed=" + filepath.Join(f.root, "build/impr-manifest.json") +
		" --manifest=" + filepath.Join(f.root, "build/m.json") + " --json"
	if got := f.run.last(); got != want {
		t.Fatalf("args\n got %s\nwant %s", got, want)
	}
	files := `{"root":"` + f.root + `","profile":"acme","files":["--json","a.exe"]}`
	if r := do(f.h, "POST", "/v1/verify", f.ver, files, nil); r.Code != 200 || !strings.HasSuffix(f.run.last(), "--json -- --json a.exe") {
		t.Fatalf("files are passed after --, never as options: %s", f.run.last())
	}
	for name, body := range map[string]string{
		"root outside roots":  `{"root":"/etc","profile":"acme","files":["passwd"]}`,
		"relative root":       `{"root":"build","profile":"acme","files":["x"]}`,
		"escaping file":       `{"root":"` + f.root + `","profile":"acme","files":["../outside"]}`,
		"absolute signed":     `{"root":"` + f.root + `","profile":"acme","signed":"/etc/impr-manifest.json"}`,
		"unknown field":       `{"root":"` + f.root + `","profile":"acme","exec":"x"}`,
		"two objects":         `{"root":"` + f.root + `","profile":"acme"}{}`,
		"option as a profile": `{"root":"` + f.root + `","profile":"--strict"}`,
	} {
		if r := do(f.h, "POST", "/v1/verify", f.ver, body, nil); r.Code != 400 {
			t.Errorf("%s: %d, want 400", name, r.Code)
		}
	}
}

func TestSignNeedsTheSwitchTheScopeAndABoundManifest(t *testing.T) {
	f := setup(t, true)
	body := `{"root":"` + f.root + `","manifest":"build/m.json","commit":"0123456789abcdef0123456789abcdef01234567","tree":"89abcdef0123456789abcdef0123456789abcdef","profile":"acme","purpose":"release","repo":"git@github.com:acme/tool.git"}`
	if r := do(f.h, "POST", "/v1/sign", f.ver, body, nil); r.Code != 403 {
		t.Fatalf("verify scope signed: %d", r.Code)
	}
	if r := do(f.h, "POST", "/v1/sign", f.signT, body, nil); r.Code != 200 || !strings.Contains(f.run.last(), "--commit=0123456789abcdef") {
		t.Fatalf("sign: %d %s", r.Code, f.run.last())
	}
	for name, b := range map[string]string{
		"no commit":     strings.Replace(body, `"commit":"0123456789abcdef0123456789abcdef01234567",`, "", 1),
		"no purpose":    strings.Replace(body, `"purpose":"release",`, "", 1),
		"option repo":   strings.Replace(body, `git@github.com:acme/tool.git`, `--root=/`, 1),
		"outside roots": strings.Replace(body, f.root, "/tmp", 1),
	} {
		if r := do(f.h, "POST", "/v1/sign", f.signT, b, nil); r.Code != 400 {
			t.Errorf("%s: %d, want 400", name, r.Code)
		}
	}
}

func TestExitCodesMapToHTTP(t *testing.T) {
	for code, want := range map[int]int{0: 200, 1: 400, 2: 200, 3: 422, 4: 422, 5: 503} {
		if got := status(code); got != want {
			t.Errorf("exit %d -> %d, want %d", code, got, want)
		}
	}
}

func TestInboundWebhook(t *testing.T) {
	f := setup(t, false)
	body := []byte(`{"action":"verify","verify":{"root":"` + f.root + `","profile":"acme","files":["a.exe"]}}`)
	signed := func(id string, b []byte, key []byte) http.Header {
		h := http.Header{}
		webhook.SetHeaders(h, [][]byte{key}, id, time.Now(), b)
		return h
	}
	if r := do(f.h, "POST", "/v1/hooks/sange", "", string(body), nil); r.Code != 401 {
		t.Fatalf("unsigned: %d", r.Code)
	}
	other, _ := webhook.NewSecret()
	ok, _ := webhook.DecodeSecret(other)
	if r := do(f.h, "POST", "/v1/hooks/sange", "", string(body), signed("d1", body, ok)); r.Code != 401 {
		t.Fatalf("wrong key: %d", r.Code)
	}
	if r := do(f.h, "POST", "/v1/hooks/nobody", "", string(body), signed("d1", body, f.key)); r.Code != 401 {
		t.Fatalf("unknown endpoint: %d", r.Code)
	}
	if r := do(f.h, "POST", "/v1/hooks/sange", "", string(body), signed("d2", body, f.key)); r.Code != 200 || !strings.Contains(f.run.last(), "verify --root=") {
		t.Fatalf("signed verify: %d %s %s", r.Code, r.Body, f.run.last())
	}
	if r := do(f.h, "POST", "/v1/hooks/sange", "", string(body), signed("d2", body, f.key)); r.Code != 409 {
		t.Fatalf("replay: %d", r.Code)
	}
	doctor := []byte(`{"action":"doctor"}`)
	if r := do(f.h, "POST", "/v1/hooks/sange", "", string(doctor), signed("d3", doctor, f.key)); r.Code != 403 {
		t.Fatalf("an action the endpoint does not allow: %d", r.Code)
	}
	sign := []byte(`{"action":"sign"}`)
	if r := do(f.h, "POST", "/v1/hooks/sange", "", string(sign), signed("d4", sign, f.key)); r.Code != 403 {
		t.Fatalf("sign over an inbound webhook: %d", r.Code)
	}
	if !bytes.Contains([]byte(f.run.last()), []byte("verify")) {
		t.Fatal("a refused action ran a command")
	}
}

func TestRateLimit(t *testing.T) {
	f := setup(t, false)
	var last int
	for i := 0; i <= RatePerMinute; i++ {
		last = do(f.h, "GET", "/v1/profiles", f.read, "", nil).Code
	}
	if last != 429 {
		t.Fatalf("request %d: %d, want 429", RatePerMinute+1, last)
	}
}
