package web

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func newTestServer(t *testing.T, log, debug *bytes.Buffer) *Server {
	t.Helper()
	o := Options{AllowedHosts: AllowedHosts(7823), Version: "test", Token: NewToken()}
	if log != nil {
		o.Log = func(f string, a ...any) { fmt.Fprintf(log, f+"\n", a...) }
	}
	if debug != nil {
		o.Debug = func(f string, a ...any) { fmt.Fprintf(debug, f+"\n", a...) }
	}
	s, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// wantHeaders is the header set every response carries (design ID-34).
var wantHeaders = map[string]string{
	"Content-Security-Policy":      ContentSecurityPolicy,
	"X-Content-Type-Options":       "nosniff",
	"X-Frame-Options":              "DENY",
	"Referrer-Policy":              "same-origin",
	"Cross-Origin-Opener-Policy":   "same-origin",
	"Cross-Origin-Resource-Policy": "same-origin",
	"Permissions-Policy":           PermissionsPolicy,
}

// Every route, an unknown path and a refused host answer with the same
// security headers: they are set before anything else can answer.
func TestEveryResponseCarriesTheSecurityHeaders(t *testing.T) {
	s := newTestServer(t, nil, nil)
	routes := registeredRoutes(t)
	atLeast(t, "routes in routes.go", len(routes), 1)
	type probe struct{ method, target, host string }
	probes := []probe{{"GET", "/no-such-page", testHost}, {"GET", "/", "evil.example:7823"}}
	for _, r := range routes {
		probes = append(probes, probe{r.Method, concrete(r.Pattern), testHost})
	}
	for _, p := range probes {
		rec := do(s.Handler(), p.method, p.target, nil, map[string]string{"Host": p.host})
		for k, v := range wantHeaders {
			if got := rec.Header().Get(k); got != v {
				t.Errorf("%s %s (Host %s): %s = %q, want %q", p.method, p.target, p.host, k, got, v)
			}
		}
	}
	for _, d := range []string{"unsafe-inline", "unsafe-eval"} {
		if strings.Contains(ContentSecurityPolicy, d) {
			t.Errorf("the CSP allows %s", d)
		}
	}
}

// A page that rebinds its own name to 127.0.0.1 still sends its own Host:
// only this machine's three spellings at the bound port are answered.
func TestHostCheckRefusesARebindingHost(t *testing.T) {
	s := newTestServer(t, nil, nil)
	for _, h := range []string{"127.0.0.1:7823", "localhost:7823", "[::1]:7823"} {
		if r := do(s.Handler(), "GET", "/healthz", nil, map[string]string{"Host": h}); r.Code != http.StatusOK {
			t.Errorf("Host %s: %d, want 200", h, r.Code)
		}
	}
	for _, h := range []string{"evil.example:7823", "evil.example", "127.0.0.1:7824", "127.0.0.1", "10.0.0.5:7823", ""} {
		if r := do(s.Handler(), "GET", "/healthz", nil, map[string]string{"Host": h}); r.Code != http.StatusMisdirectedRequest {
			t.Errorf("Host %q: %d, want 421", h, r.Code)
		}
	}
}

// A body over MaxBodyBytes is refused before it is parsed.
func TestAnOversizedBodyIsRefused(t *testing.T) {
	s := newTestServer(t, nil, nil)
	big := strings.NewReader("csrf=x&v=" + strings.Repeat("a", MaxBodyBytes+1))
	r := do(s.Handler(), "POST", "/signin", big, map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Origin": "http://" + testHost})
	if r.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("an oversized body: %d, want 413", r.Code)
	}
}

// A change must come from this server's own pages: an Origin naming this
// host, or, with none, Sec-Fetch-Site: same-origin.
func TestUnsafeMethodsNeedTheSameOrigin(t *testing.T) {
	s := newTestServer(t, nil, nil)
	for name, hdr := range map[string]map[string]string{
		"another origin":             {"Origin": "http://evil.example"},
		"the right host, wrong port": {"Origin": "http://127.0.0.1:9999"},
		"Origin: null":               {"Origin": "null"},
		"no Origin, cross-site":      {"Sec-Fetch-Site": "cross-site"},
		"no Origin, no fetch site":   {},
	} {
		hdr["Content-Type"] = "application/x-www-form-urlencoded"
		if r := do(s.Handler(), "POST", "/signin", strings.NewReader("token=x"), hdr); r.Code != http.StatusForbidden {
			t.Errorf("%s: %d, want 403", name, r.Code)
		}
	}
}

// The access log writes a change at info and a page view at debug, by path
// only: a sign-in link's token never reaches it.
func TestAccessLogNeverHasTheQuery(t *testing.T) {
	var info, debug bytes.Buffer
	s := newTestServer(t, &info, &debug)
	linkToken := NewToken()
	do(s.Handler(), "GET", "/healthz?token="+linkToken, nil, nil)
	body, hdr := form(nil)
	do(s.Handler(), "POST", "/signout?token="+linkToken, body, hdr)
	if !strings.Contains(debug.String(), "GET /healthz") {
		t.Errorf("the page view is not in the debug log: %q", debug.String())
	}
	if !strings.Contains(info.String(), "POST /signout") {
		t.Errorf("the change is not in the log: %q", info.String())
	}
	if strings.Contains(info.String(), "GET /healthz") {
		t.Errorf("a page view was logged at info: %q", info.String())
	}
	for _, l := range []string{info.String(), debug.String()} {
		if strings.Contains(l, linkToken) || strings.Contains(l, "token=") {
			t.Errorf("the log has the query: %q", l)
		}
	}
}
