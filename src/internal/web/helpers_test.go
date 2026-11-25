package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
)

// testHost is the Host every test request carries: the bound address.
const testHost = "127.0.0.1:7823"

func atLeast(t *testing.T, what string, got, floor int) {
	t.Helper()
	if got < floor {
		t.Fatalf("inspected %d %s, want at least %d: the search no longer matches what it inspects", got, what, floor)
	}
}

// routeRe is how routes.go registers a route: one mux.HandleFunc per line.
var routeRe = regexp.MustCompile(`mux\.HandleFunc\("(GET|POST) (/[^"]*)"`)

// route is one registered pattern.
type route struct{ Method, Pattern string }

// registeredRoutes reads routes.go: every route the mux serves, as written.
func registeredRoutes(t *testing.T) []route {
	t.Helper()
	b, err := os.ReadFile("routes.go")
	if err != nil {
		t.Fatal(err)
	}
	var out []route
	for _, m := range routeRe.FindAllStringSubmatch(string(b), -1) {
		out = append(out, route{m[1], m[2]})
	}
	return out
}

// concrete fills a pattern's wildcards with a value each kind of name accepts.
func concrete(pattern string) string {
	p := strings.TrimSuffix(pattern, "{$}")
	p = regexp.MustCompile(`\{hash\}`).ReplaceAllString(p, "0")
	p = regexp.MustCompile(`\{path\.\.\.\}`).ReplaceAllString(p, "favicon.svg")
	p = regexp.MustCompile(`\{[a-z]+\}`).ReplaceAllString(p, "example")
	return p
}

// do sends one request to h and returns the recorder.
func do(h http.Handler, method, target string, body io.Reader, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, body)
	req.Host = testHost
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// form encodes v as a POST body.
func form(v url.Values) (io.Reader, map[string]string) {
	return strings.NewReader(v.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Origin": "http://" + testHost}
}
