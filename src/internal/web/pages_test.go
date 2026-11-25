package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sangehq/imprimatur/src/internal/events"
	"github.com/sangehq/imprimatur/src/internal/server"
)

// fakeImpr stands in for the command layer: it answers each command line
// with a document, records every line it ran, and holds what the writes
// changed, so a page shows the result of a write.
type fakeImpr struct {
	mu      sync.Mutex
	ran     [][]string
	empty   bool
	secrets map[string]string
	token   string
}

func (f *fakeImpr) run(_ context.Context, args []string) (int, []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ran = append(f.ran, slices.Clone(args))
	line := strings.Join(slices.DeleteFunc(slices.Clone(args), func(a string) bool { return a == "--json" }), " ")
	doc := func(v any) (int, []byte) { b, _ := json.Marshal(v); return 0, b }
	if f.empty {
		switch {
		case line == "doctor":
			return doc(map[string]any{"contract": 1, "ok": true, "version": "test", "profiles": []any{}, "problems": []any{}, "notes": []any{}, "tools": []any{}})
		case line == "profile list":
			return doc(map[string]any{"contract": 1, "profiles": []any{}})
		case line == "profile default":
			return doc(map[string]any{"contract": 1, "default": ""})
		case line == "cert list":
			return doc(map[string]any{"contract": 1, "certificates": []any{}})
		case line == "server token list":
			return doc(map[string]any{"contract": 1, "tokens": []any{}})
		case line == "webhooks list":
			return doc(map[string]any{"contract": 1, "subscriptions": []any{}, "pending": 0, "dead": 0})
		case line == "webhooks deliveries":
			return doc(map[string]any{"contract": 1, "pending": []any{}, "dead": []any{}, "done": []any{}})
		case strings.HasPrefix(line, "events tail"), strings.HasPrefix(line, "audit tail"):
			return doc(map[string]any{"contract": 1, "events": []any{}, "records": []any{}})
		}
	}
	when := "2026-12-25T00:00:00Z"
	switch {
	case line == "doctor":
		return 5, mustJSON(map[string]any{"contract": 1, "ok": false, "version": "test", "defaultProfile": "",
			"profiles": []any{map[string]any{"name": "rel", "valid": true, "ready": []any{"checksums"}}},
			"problems": []any{"no default signing profile (impr profile default <name>)"}, "notes": []any{"a note"},
			"tools": []any{map[string]any{"name": "ssh-keygen", "why": "SSH checksum signatures", "path": "/usr/bin/ssh-keygen", "pinned": false}}})
	case line == "profile list":
		return doc(map[string]any{"contract": 1, "profiles": []any{map[string]any{"name": "rel", "scope": "personal", "owner": "tester",
			"purpose": []any{"release"}, "platforms": map[string]any{"checksums": map[string]any{"kind": "ssh", "backend": "ssh"}}}}})
	case strings.HasPrefix(line, "profile show "):
		return doc(map[string]any{"contract": 1, "name": args[2], "scope": "personal", "owner": "tester", "purpose": []any{"release"},
			"platforms": map[string]any{"checksums": map[string]any{"kind": "ssh", "keyRef": "env://K"}}})
	case strings.HasPrefix(line, "profile capabilities "):
		return doc(map[string]any{"contract": 1, "host": "macos", "profiles": []any{map[string]any{"name": args[2], "valid": true,
			"platforms": map[string]any{"checksums": map[string]any{"platform": "checksums", "kind": "ssh", "backend": "ssh", "sign": true, "verify": true}}, "ready": []any{"checksums"}}}})
	case strings.HasPrefix(line, "profile validate "):
		return doc(map[string]any{"contract": 1, "ok": true, "profiles": []any{map[string]any{"name": args[2], "identityDigest": "sha256:ab", "problems": []any{}}}})
	case line == "profile default":
		return doc(map[string]any{"contract": 1, "default": "rel"})
	case strings.HasPrefix(line, "profile default "), strings.HasPrefix(line, "profile rm "):
		return 0, []byte("default   x\n")
	case line == "cert list":
		return doc(map[string]any{"contract": 1, "certificates": []any{map[string]any{"profile": "t1", "platform": "windows", "subject": "CN=Test",
			"thumbprint": "5492CAFA", "notAfter": when, "present": true, "source": "file"}}})
	case strings.HasPrefix(line, "cert create "):
		return doc(map[string]any{"contract": 1, "profile": "t1", "subject": "CN=Test", "thumbprint": "5492CAFA"})
	case line == "server token list":
		return doc(map[string]any{"contract": 1, "tokens": []any{map[string]any{"id": "tok_0123456789ab", "scopes": []any{"read"}}}})
	case strings.HasPrefix(line, "server token add "):
		return 0, []byte(f.token + "\n")
	case strings.HasPrefix(line, "server token revoke "):
		return 0, nil
	case line == "webhooks list":
		return doc(map[string]any{"contract": 1, "subscriptions": []any{map[string]any{"name": "ci", "url": "https://ci.example/hook", "secretRef": "env://WH"}}, "pending": 1, "dead": 1})
	case line == "webhooks deliveries":
		d := map[string]any{"subscription": "ci", "eventId": "e1", "eventType": "com.simtabi.sange.imprimatur.webhook.test", "attempts": 2, "lastStatus": 500}
		return doc(map[string]any{"contract": 1, "pending": []any{d}, "dead": []any{d}, "done": []any{}})
	case strings.HasPrefix(line, "webhooks add "), strings.HasPrefix(line, "webhooks rm "), strings.HasPrefix(line, "webhooks test "):
		return doc(map[string]any{"contract": 1, "ok": true})
	case strings.HasPrefix(line, "webhooks retry"):
		return doc(map[string]any{"contract": 1, "tried": 1, "delivered": 1})
	case strings.HasPrefix(line, "events tail"):
		return doc(map[string]any{"contract": 1, "events": []any{map[string]any{"id": "e1", "type": "com.simtabi.sange.imprimatur.profile.changed", "subject": "rel", "time": when}}})
	case strings.HasPrefix(line, "audit tail"):
		return doc(map[string]any{"contract": 1, "records": []any{map[string]any{"id": "a1", "type": "com.simtabi.sange.imprimatur.audit.command.completed", "subject": "doctor", "time": when,
			"data": map[string]any{"command": "doctor", "exitCode": 0, "user": "tester"}}}})
	case line == "audit verify":
		return doc(map[string]any{"contract": 1, "ok": true, "checked": 3})
	case line == "path":
		return doc(map[string]any{"contract": 1, "config": "/c", "state": "/s", "installDir": "/b", "installed": true, "onPath": true})
	case line == "companion info":
		return doc(map[string]any{"contract": 1, "version": "test", "host": "macos", "capabilityList": []any{"macos", "checksums"}, "commands": []any{"sign", "verify"}})
	}
	return 1, mustJSON(map[string]any{"contract": 1, "ok": false, "exitCode": 1, "error": map[string]any{"message": "the fake knows no " + line}})
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

// ran reports whether a command line starting with prefix was run.
func (f *fakeImpr) ranLine(prefix string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range f.ran {
		if strings.HasPrefix(strings.Join(a, " "), prefix) {
			return true
		}
	}
	return false
}

func (f *fakeImpr) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.ran) }

// pagesFixture is a signed-in web UI over the fake command layer.
type pagesFixture struct {
	*fixture
	impr   *fakeImpr
	cookie string
	csrf   string
	evlog  events.Log
}

func newPages(t *testing.T, empty bool) *pagesFixture {
	t.Helper()
	fi := &fakeImpr{empty: empty, secrets: map[string]string{}}
	var err error
	fi.token, _, _, err = newAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	evlog := events.Log{Dir: filepath.Join(t.TempDir(), "events")}
	f := newFixture(t, func(o *Options) {
		o.Run = fi.run
		o.Events = evlog
		o.Poll = 20 * time.Millisecond
		o.PutSecret = func(_ context.Context, name, value string) (string, error) {
			fi.mu.Lock()
			defer fi.mu.Unlock()
			fi.secrets[name] = value
			return "secret://" + name, nil
		}
		o.ListSecrets = func() ([]server.UISecret, error) {
			fi.mu.Lock()
			defer fi.mu.Unlock()
			var out []server.UISecret
			for k := range fi.secrets {
				out = append(out, server.UISecret{Name: k, Ref: "secret://" + k})
			}
			return out, nil
		}
	})
	p := &pagesFixture{fixture: f, impr: fi, evlog: evlog}
	p.cookie, p.csrf = f.signIn(t)
	return p
}

func (p *pagesFixture) get(path string) (int, string, http.Header) {
	r := do(p.s.Handler(), "GET", path, nil, map[string]string{"Cookie": p.cookie})
	return r.Code, r.Body.String(), r.Header()
}

// post sends a form from the UI's own page; csrf adds the session's token.
func (p *pagesFixture) post(path string, v url.Values, csrf bool) (int, string, http.Header) {
	if v == nil {
		v = url.Values{}
	}
	if csrf {
		v.Set("csrf", p.csrf)
	}
	body, hdr := form(v)
	hdr["Cookie"] = p.cookie
	r := do(p.s.Handler(), "POST", path, body, hdr)
	return r.Code, r.Body.String(), r.Header()
}

// htmlPages is every GET route that answers with a page, wildcards filled.
func htmlPages(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, r := range registeredRoutes(t) {
		switch {
		case r.Method != "GET", strings.HasPrefix(r.Pattern, "/assets/"), r.Pattern == "/healthz", r.Pattern == "/events/stream":
			continue
		}
		p := strings.TrimSuffix(r.Pattern, "{$}")
		p = strings.NewReplacer("{name}", "rel", "{id}", "tok_0123456789ab").Replace(p)
		out = append(out, p)
	}
	return out
}

// Every page renders in the layout, signed in, from the command layer's
// documents.
func TestEveryPageRenders(t *testing.T) {
	p := newPages(t, false)
	pages := htmlPages(t)
	atLeast(t, "pages", len(pages), 16)
	for _, path := range pages {
		code, body, _ := p.get(path)
		if code != http.StatusOK && (path != "/tokens/created" || code != http.StatusSeeOther) {
			t.Errorf("GET %s: %d %s", path, code, body)
			continue
		}
		if code == http.StatusOK {
			if miss := styled(t, p.s, body); len(miss) > 0 {
				t.Errorf("GET %s lacks %v", path, miss)
			}
		}
	}
	for path, want := range map[string]string{"/": "no default signing profile", "/doctor": "ssh-keygen", "/profiles": "rel", "/profiles/rel": "env://K",
		"/certs": "CN=Test", "/tokens": "tok_0123456789ab", "/webhooks": "https://ci.example/hook", "/events": "profile.changed",
		"/audit": "3 records", "/about": "Open Font License"} {
		if _, body, _ := p.get(path); !strings.Contains(body, want) {
			t.Errorf("GET %s does not show %q", path, want)
		}
	}
}

// A list with nothing in it shows Tabler's empty state, not an empty table.
func TestEmptyStatesAreShown(t *testing.T) {
	p := newPages(t, true)
	for _, path := range []string{"/profiles", "/certs", "/secrets", "/tokens", "/webhooks", "/events", "/audit"} {
		if _, body, _ := p.get(path); !strings.Contains(body, `class="empty`) {
			t.Errorf("GET %s with nothing to list shows no empty state", path)
		}
	}
}

// write is one change the UI makes: its form, the command line it runs, and
// the page it lands on.
type write struct {
	path    string
	form    url.Values
	command string
	back    string
}

var writes = []write{
	{"/profiles/rel/default", nil, "profile default rel", "/profiles"},
	{"/profiles/rel/remove", url.Values{"confirm": {"yes"}}, "profile rm rel", "/profiles"},
	{"/certs", url.Values{"name": {"t2"}, "subject": {"Test Two"}, "days": {"30"}}, "cert create --name=t2 --subject=Test Two --days=30", "/certs"},
	{"/tokens", url.Values{"scopes": {"read", "verify"}}, "server token add --scopes=read,verify", "/tokens/created"},
	{"/tokens/tok_0123456789ab/revoke", url.Values{"confirm": {"yes"}}, "server token revoke tok_0123456789ab", "/tokens"},
	{"/webhooks", url.Values{"name": {"ci2"}, "url": {"https://ci.example/h"}, "secretRef": {"env://WH"}, "types": {"profile.*"}}, "webhooks add ci2 --url=https://ci.example/h --secret-ref=env://WH --types=profile.*", "/webhooks"},
	{"/webhooks/ci/remove", url.Values{"confirm": {"yes"}}, "webhooks rm ci", "/webhooks"},
	{"/webhooks/ci/test", nil, "webhooks test ci", "/webhooks"},
	{"/webhooks/retry", nil, "webhooks retry", "/webhooks"},
	{"/webhooks/retry", url.Values{"all": {"1"}}, "webhooks retry --all", "/webhooks"},
}

// Every write runs its command, then redirects (303) to a page that shows
// what happened: POST, redirect, GET.
func TestEveryWriteRoundTrips(t *testing.T) {
	p := newPages(t, false)
	for _, w := range writes {
		code, body, hdr := p.post(w.path, w.form, true)
		if code != http.StatusSeeOther || hdr.Get("Location") != w.back {
			t.Errorf("POST %s: %d %q %s", w.path, code, hdr.Get("Location"), body)
			continue
		}
		if !p.impr.ranLine(w.command) {
			t.Errorf("POST %s did not run %q (ran %v)", w.path, w.command, p.impr.ran)
		}
		if w.back != "/tokens/created" {
			if _, page, _ := p.get(w.back); !strings.Contains(page, `class="toast show"`) {
				t.Errorf("after POST %s, %s shows no message", w.path, w.back)
			}
		}
	}
	// A secret goes through PutSecret, never Run, and is never shown back.
	val := "-----BEGIN PRIVATE KEY-----\n" + NewToken() + "\n-----END PRIVATE KEY-----"
	before := p.impr.count()
	code, _, hdr := p.post("/secrets", url.Values{"name": {"IMPR_NOTARY_KEY"}, "value": {val}}, true)
	if code != http.StatusSeeOther || hdr.Get("Location") != "/secrets" || p.impr.secrets["IMPR_NOTARY_KEY"] != val || p.impr.count() != before {
		t.Fatalf("store a secret: %d %q", code, hdr.Get("Location"))
	}
	if _, page, _ := p.get("/secrets"); strings.Contains(page, "PRIVATE KEY") || !strings.Contains(page, "secret://IMPR_NOTARY_KEY") {
		t.Fatal("the secrets page echoes the value or omits the reference")
	}
	// A new API token is shown once, then never again.
	p.post("/tokens", url.Values{"scopes": {"read"}}, true)
	if _, page, _ := p.get("/tokens/created"); !strings.Contains(page, p.impr.token) {
		t.Fatal("the new token is not shown")
	}
	if code, page, _ := p.get("/tokens/created"); strings.Contains(page, p.impr.token) || code != http.StatusSeeOther {
		t.Fatalf("the token was shown twice: %d", code)
	}
}

// A write's fields are checked before they reach a command line.
func TestAWriteWithABadFieldRunsNothing(t *testing.T) {
	p := newPages(t, false)
	for path, v := range map[string]url.Values{
		"/certs":                {"name": {"--root=/"}, "subject": {"x"}, "days": {"30"}},
		"/certs#days":           {"name": {"ok"}, "subject": {"x"}, "days": {"0"}},
		"/certs#subject":        {"name": {"ok"}, "subject": {"a\nb"}, "days": {"30"}},
		"/tokens":               {"scopes": {"root"}},
		"/webhooks":             {"name": {"x"}, "url": {"ftp://x"}, "secretRef": {"env://WH"}},
		"/webhooks#secret":      {"name": {"x"}, "url": {"https://x"}, "secretRef": {"whsec_plain"}},
		"/secrets":              {"name": {"impr-x"}, "value": {"v"}},
		"/profiles/-rf/default": {},
		"/tokens/tok_zz/revoke": {"confirm": {"yes"}},
		"/webhooks/-x/remove":   {"confirm": {"yes"}},
	} {
		before := p.impr.count()
		code, _, _ := p.post(strings.SplitN(path, "#", 2)[0], v, true)
		if code < 400 || p.impr.count() != before {
			t.Errorf("POST %s %v: %d, ran %d command(s)", path, v, code, p.impr.count()-before)
		}
	}
}

// Every POST route refuses a form without the session's CSRF token, and runs
// nothing.
func TestEveryWriteRefusesWithoutCSRF(t *testing.T) {
	p := newPages(t, false)
	n := 0
	for _, r := range registeredRoutes(t) {
		if r.Method != "POST" || r.Pattern == "/signin" {
			continue
		}
		n++
		path := strings.NewReplacer("{name}", "rel", "{id}", "tok_0123456789ab").Replace(r.Pattern)
		before := p.impr.count()
		if code, _, _ := p.post(path, url.Values{"confirm": {"yes"}}, false); code != http.StatusForbidden || p.impr.count() != before {
			t.Errorf("POST %s without CSRF: %d", path, code)
		}
	}
	atLeast(t, "POST routes", n, 10)
}

// destructiveRe is a POST route that removes or revokes something.
var destructiveRe = regexp.MustCompile(`/(remove|revoke)$`)

// Every destructive action asks first: its button opens a danger modal, and
// without confirm=yes the server answers with a confirmation page and changes
// nothing.
func TestEveryDestructiveActionConfirms(t *testing.T) {
	p := newPages(t, false)
	n := 0
	for _, r := range registeredRoutes(t) {
		if r.Method != "POST" || !destructiveRe.MatchString(r.Pattern) {
			continue
		}
		n++
		path := strings.NewReplacer("{name}", "rel", "{id}", "tok_0123456789ab").Replace(r.Pattern)
		before := p.impr.count()
		code, body, _ := p.post(path, nil, true)
		if code != http.StatusOK || p.impr.count() != before || !strings.Contains(body, `name="confirm" value="yes"`) {
			t.Errorf("POST %s without confirm=yes: %d, ran %d", path, code, p.impr.count()-before)
		}
	}
	atLeast(t, "destructive routes", n, 3)
	// Every form that posts to one has a data-confirm button and its modal.
	formRe := regexp.MustCompile(`(?s)<form[^>]*action="([^"]+/(?:remove|revoke))"[^>]*id="([^"]+)"[^>]*>(.*?)</form>`)
	forms := 0
	for _, path := range []string{"/profiles", "/profiles/rel", "/tokens", "/webhooks"} {
		_, body, _ := p.get(path)
		for _, m := range formRe.FindAllStringSubmatch(body, -1) {
			forms++
			btn := regexp.MustCompile(`data-confirm="([^"]+)"`).FindStringSubmatch(m[3])
			if btn == nil {
				t.Errorf("%s: the form for %s has no data-confirm button", path, m[1])
				continue
			}
			if !strings.Contains(body, `id="`+btn[1]+`"`) || !strings.Contains(body, `form="`+m[2]+`" name="confirm" value="yes"`) {
				t.Errorf("%s: the form for %s has no confirm modal submitting it", path, m[1])
			}
		}
	}
	atLeast(t, "destructive forms", forms, 3)
}

var hrefRe = regexp.MustCompile(`href="(/[^"#]*)`)

// Every link on every page opens: nothing points at a page that is not there.
func TestEveryLinkOnEveryPageOpens(t *testing.T) {
	p := newPages(t, false)
	seen := map[string]bool{}
	for _, path := range htmlPages(t) {
		_, body, _ := p.get(path)
		for _, m := range hrefRe.FindAllStringSubmatch(body, -1) {
			seen[strings.ReplaceAll(m[1], "&amp;", "&")] = true
		}
	}
	atLeast(t, "distinct links", len(seen), 20)
	for link := range seen {
		code, _, _ := p.get(link)
		if code >= 400 {
			t.Errorf("a page links %s, which answers %d", link, code)
		}
	}
}

// The palette offers every page and every form that opens in the panel.
func TestPaletteCoversEveryPage(t *testing.T) {
	p := newPages(t, false)
	_, body, _ := p.get("/")
	palette := body[strings.Index(body, "data-command-palette"):]
	n := 0
	for _, r := range registeredRoutes(t) {
		switch {
		case r.Method != "GET", strings.Contains(strings.TrimSuffix(r.Pattern, "{$}"), "{"), r.Pattern == "/healthz", r.Pattern == "/signin",
			r.Pattern == "/events/stream", r.Pattern == "/tokens/created":
			continue
		}
		n++
		href := strings.TrimSuffix(r.Pattern, "{$}")
		if href == "" {
			href = "/"
		}
		if !strings.Contains(palette, `href="`+href+`"`) {
			t.Errorf("the palette has no entry for %s", href)
		}
	}
	atLeast(t, "palette pages", n, 14)
}

var (
	tagRe      = regexp.MustCompile(`(?is)<(input|select|textarea)\b([^>]*)>`)
	buttonRe   = regexp.MustCompile(`(?is)<(button|a)\b([^>]*)>(.*?)</(?:button|a)>`)
	attrRe     = func(name string) *regexp.Regexp { return regexp.MustCompile(`\b` + name + `="([^"]*)"`) }
	tagStripRe = regexp.MustCompile(`(?s)<[^>]*>`)
)

// labelProblems lists the controls on a page with no name a screen reader
// can read, and icon-only controls with no tooltip.
func labelProblems(page, body string) []string {
	var out []string
	for _, m := range tagRe.FindAllStringSubmatch(body, -1) {
		attrs := m[2]
		if typ := attrRe("type").FindStringSubmatch(attrs); typ != nil && (typ[1] == "hidden" || typ[1] == "submit") {
			continue
		}
		if attrRe("aria-label").MatchString(attrs) {
			continue
		}
		id := attrRe("id").FindStringSubmatch(attrs)
		if id == nil || !strings.Contains(body, `for="`+id[1]+`"`) {
			out = append(out, page+": a <"+m[1]+"> with no label: "+strings.TrimSpace(attrs))
		}
	}
	for _, m := range buttonRe.FindAllStringSubmatch(body, -1) {
		attrs, text := m[2], strings.TrimSpace(tagStripRe.ReplaceAllString(m[3], ""))
		if m[1] == "a" && !strings.Contains(attrs, "btn") {
			continue
		}
		if text == "" {
			if !attrRe("aria-label").MatchString(attrs) {
				out = append(out, page+": an icon-only <"+m[1]+"> with no aria-label: "+strings.TrimSpace(attrs))
			}
			if !attrRe("title").MatchString(attrs) {
				out = append(out, page+": an icon-only <"+m[1]+"> with no tooltip: "+strings.TrimSpace(attrs))
			}
		}
	}
	return out
}

// Every control has a label or an aria-label, and an icon-only one a
// tooltip as well.
func TestEveryControlHasALabel(t *testing.T) {
	p := newPages(t, false)
	pages := 0
	for _, path := range htmlPages(t) {
		code, body, _ := p.get(path)
		if code != http.StatusOK {
			continue
		}
		pages++
		for _, x := range labelProblems(path, body) {
			t.Error(x)
		}
	}
	atLeast(t, "pages", pages, 14)
	if len(labelProblems("x", `<input id="a" name="a"><button type="button"><svg></svg></button>`)) != 3 {
		t.Error("the label guard missed an unlabelled input or an unnamed icon button")
	}
}

// The events page streams each new event, as data with no markup, and only
// the types asked for.
func TestEventsStreamLive(t *testing.T) {
	p := newPages(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptestRequest(ctx, "/events/stream?type=profile.*", p.cookie)
	rec := newStreamRecorder()
	done := make(chan struct{})
	go func() { p.s.Handler().ServeHTTP(rec, req); close(done) }()
	time.Sleep(100 * time.Millisecond)
	env := events.Env{Now: time.Now, NewID: events.NewID, InstallID: "0123456789abcdef"}
	for _, short := range []string{"cert.expiring", "profile.changed"} {
		ev, err := env.New(short, "<b>rel</b>", map[string]any{"profile": "rel"})
		if err != nil {
			t.Fatal(err)
		}
		if err := p.evlog.Write(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(rec.String(), "profile.changed") {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	out := rec.String()
	if !strings.Contains(out, "profile.changed") || strings.Contains(out, "cert.expiring") || !strings.Contains(out, `\u003cb\u003erel`) || strings.Contains(out, "<b>") {
		t.Fatalf("the stream: %q", out)
	}
	if rec.Header().Get("Content-Type") != "text/event-stream" {
		t.Fatalf("content type %q", rec.Header().Get("Content-Type"))
	}
}
