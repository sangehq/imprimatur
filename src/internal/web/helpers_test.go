package web

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
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

// newAPIToken makes an API token as impr server token add does, at run time.
func newAPIToken() (raw, id, sum string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return
	}
	raw = "impr_" + base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(raw))
	idb := make([]byte, 6)
	if _, err = rand.Read(idb); err != nil {
		return
	}
	return raw, "tok_" + hex.EncodeToString(idb), hex.EncodeToString(h[:]), nil
}

// httptestRequest is a signed-in GET on ctx.
func httptestRequest(ctx context.Context, target, cookie string) *http.Request {
	req := httptest.NewRequest("GET", target, nil).WithContext(ctx)
	req.Host = testHost
	req.Header.Set("Cookie", cookie)
	return req
}

// streamRecorder is a ResponseRecorder safe to read while a stream writes.
type streamRecorder struct {
	mu  sync.Mutex
	hdr http.Header
	buf strings.Builder
}

func newStreamRecorder() *streamRecorder { return &streamRecorder{hdr: http.Header{}} }

func (s *streamRecorder) Header() http.Header { return s.hdr }
func (s *streamRecorder) WriteHeader(int)     {}
func (s *streamRecorder) Flush()              {}
func (s *streamRecorder) Write(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(b)
}
func (s *streamRecorder) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.buf.String() }
