package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// styled reports what an HTML page lacks of the layout: the stylesheet, the
// favicon logo mark, the skip link and main#main.
func styled(t *testing.T, s *Server, body string) []string {
	t.Helper()
	css, _ := s.assets.url("vendor/tabler/tabler.min.css")
	fav, _ := s.assets.url("favicon.svg")
	var miss []string
	for _, want := range []string{`<link rel="stylesheet" href="` + css + `">`, `<link rel="icon" type="image/svg+xml" href="` + fav + `">`,
		`href="#main"`, `<main id="main"`, `tabindex="-1"`} {
		if !strings.Contains(body, want) {
			miss = append(miss, want)
		}
	}
	return miss
}

// Every error answers with a page in the layout, not a plain-text line.
func TestErrorPagesAreStyled(t *testing.T) {
	s := newTestServer(t, nil, nil)
	for _, code := range []int{401, 403, 404, 421, 429, 500} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/x", nil)
		req.Host = testHost
		s.renderError(rec, req, code, "Heading", "Message")
		if rec.Code != code || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") || rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%d: %d %q %q", code, rec.Code, rec.Header().Get("Content-Type"), rec.Header().Get("Cache-Control"))
		}
		if miss := styled(t, s, rec.Body.String()); len(miss) > 0 {
			t.Errorf("the %d page lacks %v", code, miss)
		}
	}
	f := newFixture(t, nil)
	cookie, _ := f.signIn(t)
	for host, code := range map[string]int{testHost: http.StatusNotFound, "evil.example:7823": http.StatusMisdirectedRequest} {
		r := do(f.s.Handler(), "GET", "/no-such-page", nil, map[string]string{"Host": host, "Cookie": cookie})
		if r.Code != code || len(styled(t, f.s, r.Body.String())) > 0 {
			t.Errorf("GET /no-such-page on %s: %d, lacks %v", host, r.Code, styled(t, f.s, r.Body.String()))
		}
	}
}

// The favicon is the header's logo mark, linked from every page, served as
// image/svg+xml.
func TestEveryPageNamesTheLogoMarkFavicon(t *testing.T) {
	s := newTestServer(t, nil, nil)
	fav, _ := s.assets.url("favicon.svg")
	pages := 0
	for _, r := range registeredRoutes(t) {
		if r.Method != "GET" {
			continue
		}
		rec := do(s.Handler(), "GET", concrete(r.Pattern), nil, nil)
		if !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
			continue
		}
		pages++
		body := rec.Body.String()
		if !strings.Contains(body, `<link rel="icon" type="image/svg+xml" href="`+fav+`">`) || !strings.Contains(body, `class="navbar-brand-mark" src="`+fav+`"`) {
			t.Errorf("GET %s does not link the logo mark favicon", r.Pattern)
		}
	}
	rec := do(s.Handler(), "GET", "/no-such-page", nil, nil)
	if !strings.Contains(rec.Body.String(), fav) {
		t.Error("the 404 page does not link the favicon")
	}
	atLeast(t, "HTML pages without a session", pages, 16)
	// Signed in, every page names it too.
	p := newPages(t, false)
	signed := 0
	for _, path := range htmlPages(t) {
		code, body, _ := p.get(path)
		if code != http.StatusOK {
			continue
		}
		signed++
		if !strings.Contains(body, `<link rel="icon" type="image/svg+xml" href="`+fav+`">`) || !strings.Contains(body, `class="navbar-brand-mark" src="`+fav+`"`) {
			t.Errorf("signed in, GET %s does not link the logo mark favicon", path)
		}
	}
	atLeast(t, "HTML pages signed in", signed, 16)
	r := do(s.Handler(), "GET", fav, nil, nil)
	svg := r.Body.String()
	if r.Code != 200 || r.Header().Get("Content-Type") != "image/svg+xml" || !strings.Contains(svg, `viewBox="0 0 32 32"`) ||
		!strings.Contains(svg, `rx="7"`) || !strings.Contains(svg, `fill="#066fd1"`) {
		t.Fatalf("the favicon: %d %q %s", r.Code, r.Header().Get("Content-Type"), svg)
	}
}
