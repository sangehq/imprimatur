package web

import (
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/sangehq/imprimatur/src/internal/config"
)

// tokenSession signs in at /signin with a new API token holding scopes, and
// returns a pagesFixture acting as that session.
func tokenSession(t *testing.T, base *pagesFixture, raw string) *pagesFixture {
	t.Helper()
	body, hdr := form(url.Values{"token": {raw}})
	r := do(base.s.Handler(), "POST", "/signin", body, hdr)
	if r.Code != http.StatusSeeOther {
		t.Fatalf("token sign-in: %d %s", r.Code, r.Body)
	}
	p := *base
	p.cookie = strings.SplitN(r.Header().Get("Set-Cookie"), ";", 2)[0]
	p.csrf = base.csrfOfPath(t, p.cookie, r.Header().Get("Location"))
	return &p
}

// csrfOfPath reads the CSRF token from a page the session can open.
func (p *pagesFixture) csrfOfPath(t *testing.T, cookie, path string) string {
	t.Helper()
	r := do(p.s.Handler(), "GET", path, nil, map[string]string{"Cookie": cookie})
	m := metaCSRF.FindStringSubmatch(r.Body.String())
	if m == nil {
		t.Fatalf("no CSRF token on %s: %d", path, r.Code)
	}
	return m[1]
}

// scopedPages is a fixture with server.web.tokenAccess scopes and three API
// tokens: read, secrets, and admin with read.
func scopedPages(t *testing.T, access string) (base *pagesFixture, read, secret, admin string) {
	t.Helper()
	var rt, st, at config.Token
	read, rt = apiToken(t, "read")
	secret, st = apiToken(t, "secrets")
	admin, at = apiToken(t, "read", "admin")
	base = newPagesWith(t, false, func(o *Options) {
		o.Web.TokenAccess = access
		o.AllowAdmin = true
		o.Tokens = append(o.Tokens, rt, st, at)
	})
	return base, read, secret, admin
}

// With server.web.tokenAccess scopes, a token sign-in reaches what its scopes
// allow: read the read-only pages, secrets the Secrets page, admin the
// writes. What it cannot reach is not linked, and answers the styled 403.
func TestTokenScopesDecideWhatASessionReaches(t *testing.T) {
	base, read, secret, admin := scopedPages(t, config.TokenAccessScopes)
	r := tokenSession(t, base, read)
	for path, want := range map[string]int{"/": 200, "/doctor": 200, "/profiles": 200, "/certs": 200, "/audit": 200, "/about": 200,
		"/secrets": 403, "/secrets/new": 403, "/tokens": 403, "/webhooks": 403, "/certs/new": 403, "/events": 403} {
		code, body, _ := r.get(path)
		if code != want {
			t.Errorf("read token, GET %s: %d, want %d", path, code, want)
		}
		if code == 403 && len(styled(t, r.s, body)) > 0 {
			t.Errorf("read token, GET %s: the 403 is not styled", path)
		}
	}
	before := r.impr.count()
	if code, _, _ := r.post("/certs", url.Values{"name": {"x"}, "subject": {"X"}, "days": {"2"}}, true); code != 403 || r.impr.count() != before {
		t.Errorf("read token, POST /certs: %d, ran %d", code, r.impr.count()-before)
	}
	// Nothing on a page it reaches links where it cannot go, and no write
	// form shows.
	for _, path := range []string{"/", "/doctor", "/profiles", "/profiles/rel", "/certs", "/audit", "/about"} {
		_, body, _ := r.get(path)
		for _, m := range hrefRe.FindAllStringSubmatch(body, -1) {
			if code, _, _ := r.get(strings.ReplaceAll(m[1], "&amp;", "&")); code >= 400 {
				t.Errorf("read token: %s links %s, which answers %d", path, m[1], code)
			}
		}
		if strings.Contains(body, `method="post" action="/profiles/`) || strings.Contains(body, `action="/certs"`) {
			t.Errorf("read token: %s shows a write form", path)
		}
	}
	s := tokenSession(t, base, secret)
	if code, _, _ := s.get("/secrets"); code != 200 {
		t.Errorf("secrets token, /secrets: %d", code)
	}
	if code, _, _ := s.get("/doctor"); code != 403 {
		t.Errorf("secrets token, /doctor: %d", code)
	}
	a := tokenSession(t, base, admin)
	if code, _, hdr := a.post("/certs", url.Values{"name": {"x2"}, "subject": {"X"}, "days": {"2"}}, true); code != 303 || hdr.Get("Location") != "/certs" {
		t.Errorf("admin token, POST /certs: %d", code)
	}
	if code, _, _ := a.get("/tokens"); code != 200 {
		t.Errorf("admin token, /tokens: %d", code)
	}
}

// The default (secrets) keeps a token sign-in to the Secrets page, whatever
// else the token may do over the API; the one-time link keeps full access.
func TestTokenAccessDefaultsToSecretsOnly(t *testing.T) {
	base, read, _, admin := scopedPages(t, "")
	body, hdr := form(url.Values{"token": {read}})
	if r := do(base.s.Handler(), "POST", "/signin", body, hdr); r.Code != http.StatusForbidden {
		t.Errorf("a read token signed in under the default: %d", r.Code)
	}
	_ = admin
	s := tokenSession(t, base, base.secrets)
	for path, want := range map[string]int{"/secrets": 200, "/doctor": 403, "/": 403, "/tokens": 403} {
		if code, _, _ := s.get(path); code != want {
			t.Errorf("secrets token, GET %s: %d, want %d", path, code, want)
		}
	}
	if code, _, _ := base.get("/tokens"); code != 200 {
		t.Errorf("the link session lost a page: %d", code)
	}
}

// Every route but the few that need no session names the scope a token
// session needs for it, on its own line in routes.go.
func TestEveryRouteNamesItsScope(t *testing.T) {
	b, err := os.ReadFile("routes.go")
	if err != nil {
		t.Fatal(err)
	}
	open := map[string]bool{"GET /assets/{hash}/{path...}": true, "GET /healthz": true, "GET /signin": true, "POST /signin": true,
		"POST /signout": true, "/": true}
	// Every registration, whatever its method (or none), so a route added
	// without one cannot slip past.
	lineRe := regexp.MustCompile(`mux\.HandleFunc\("([^"]+)", (.*)\)`)
	n := 0
	for _, m := range lineRe.FindAllStringSubmatch(string(b), -1) {
		n++
		if open[m[1]] {
			continue
		}
		if !regexp.MustCompile(`^s\.need\("(read|secrets|admin|events)", s\.[a-zA-Z]+\)$`).MatchString(m[2]) {
			t.Errorf("%s does not name its scope: %s", m[1], m[2])
		}
	}
	if total := strings.Count(string(b), "mux.HandleFunc("); total != n {
		t.Errorf("matched %d of %d registrations in routes.go", n, total)
	}
	atLeast(t, "routes", n, 30)
}
