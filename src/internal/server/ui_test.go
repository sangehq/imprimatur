package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sangehq/imprimatur/src/internal/config"
)

type uiFixture struct {
	h      http.Handler
	secret string // a token with the secrets scope
	reader string // a token without it
	stored map[string]string
}

func newUI(t *testing.T, listen string) uiFixture {
	t.Helper()
	sec, st := token(t, "secrets")
	rd, rt := token(t, "read")
	cfg := config.Config{Schema: config.Schema, Server: config.Server{Listen: listen, Tokens: []config.Token{st, rt}}}
	f := uiFixture{secret: sec, reader: rd, stored: map[string]string{}}
	f.h = Handler(Options{Config: cfg, Run: (&fakeRun{}).run, StateDir: t.TempDir(), Now: time.Now,
		PutSecret: func(_ context.Context, name, value string) (string, error) {
			f.stored[name] = value
			return "secret://" + name, nil
		},
		ListSecrets: func() ([]UISecret, error) {
			var out []UISecret
			for k := range f.stored {
				out = append(out, UISecret{Name: k, Ref: "secret://" + k})
			}
			return out, nil
		}})
	return f
}

func uiDo(h http.Handler, method, target, host, cookie string, form url.Values, hdr map[string]string) *httptest.ResponseRecorder {
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequest(method, target, body)
	req.Host = host
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([0-9a-f]{64})"`)

// Owner decision ID-31, threat I-23: the page that takes a signing secret
// answers only on loopback, signs in with a secrets-scoped token into a
// strict, HttpOnly session, checks a CSRF token and the Origin on every
// write, and never shows a value back.
func TestSecretsPage(t *testing.T) {
	f := newUI(t, "127.0.0.1:8765")
	const host = "127.0.0.1:8765"
	// A name that resolves to loopback but is not one (DNS rebinding).
	if r := uiDo(f.h, "GET", "/ui/", "attacker.example:8765", "", nil, nil); r.Code != http.StatusMisdirectedRequest {
		t.Fatalf("a foreign Host: %d", r.Code)
	}
	r := uiDo(f.h, "GET", "/ui/", host, "", nil, nil)
	if r.Code != 200 || !strings.Contains(r.Body.String(), `name="token"`) {
		t.Fatalf("the sign-in page: %d %s", r.Code, r.Body)
	}
	for k, want := range map[string]string{"Content-Security-Policy": "default-src 'none'", "X-Frame-Options": "DENY", "Cache-Control": "no-store", "Referrer-Policy": "no-referrer"} {
		if !strings.Contains(r.Header().Get(k), want) {
			t.Errorf("%s: %q", k, r.Header().Get(k))
		}
	}
	login := func(tok string) *httptest.ResponseRecorder {
		return uiDo(f.h, "POST", "/ui/login", host, "", url.Values{"token": {tok}}, map[string]string{"Origin": "http://" + host})
	}
	if r := login("impr_" + strings.Repeat("A", 43)); r.Code != http.StatusUnauthorized {
		t.Fatalf("an unknown token signed in: %d", r.Code)
	}
	if r := login(f.reader); r.Code != http.StatusForbidden {
		t.Fatalf("a token without the secrets scope signed in: %d", r.Code)
	}
	r = login(f.secret)
	if r.Code != http.StatusSeeOther {
		t.Fatalf("sign in: %d %s", r.Code, r.Body)
	}
	c := r.Header().Get("Set-Cookie")
	if !strings.Contains(c, "HttpOnly") || !strings.Contains(c, "SameSite=Strict") || !strings.Contains(c, "Path=/ui") {
		t.Fatalf("session cookie: %q", c)
	}
	cookie := strings.SplitN(c, ";", 2)[0]
	page := uiDo(f.h, "GET", "/ui/", host, cookie, nil, nil)
	m := csrfRe.FindStringSubmatch(page.Body.String())
	if page.Code != 200 || m == nil {
		t.Fatalf("the secrets page: %d %s", page.Code, page.Body)
	}
	val := "-----BEGIN PRIVATE KEY-----\n" + randHex(t, 24) + "\n-----END PRIVATE KEY-----"
	form := url.Values{"csrf": {m[1]}, "name": {"IMPR_NOTARY_KEY"}, "value": {val}}
	origin := map[string]string{"Origin": "http://" + host}
	for name, tc := range map[string]struct {
		cookie string
		form   url.Values
		hdr    map[string]string
	}{
		"no session":     {"", form, origin},
		"no csrf":        {cookie, url.Values{"name": {"IMPR_X"}, "value": {val}}, origin},
		"a wrong csrf":   {cookie, url.Values{"csrf": {strings.Repeat("0", 64)}, "name": {"IMPR_X"}, "value": {val}}, origin},
		"another origin": {cookie, form, map[string]string{"Origin": "http://attacker.example"}},
		"cross-site":     {cookie, form, map[string]string{"Origin": "http://" + host, "Sec-Fetch-Site": "cross-site"}},
	} {
		if r := uiDo(f.h, "POST", "/ui/secrets", host, tc.cookie, tc.form, tc.hdr); r.Code < 400 {
			t.Errorf("%s: %d", name, r.Code)
		}
	}
	if len(f.stored) != 0 {
		t.Fatalf("a refused write stored a secret: %v", f.stored)
	}
	r = uiDo(f.h, "POST", "/ui/secrets", host, cookie, form, origin)
	if r.Code != 200 || f.stored["IMPR_NOTARY_KEY"] != val {
		t.Fatalf("store: %d %v", r.Code, f.stored)
	}
	if strings.Contains(r.Body.String(), "PRIVATE KEY") || !strings.Contains(r.Body.String(), "secret://IMPR_NOTARY_KEY") {
		t.Fatalf("the answer echoes the value or omits the reference: %s", r.Body)
	}
	if r := uiDo(f.h, "POST", "/ui/secrets", host, cookie, url.Values{"csrf": {m[1]}, "name": {"impr-x"}, "value": {val}}, origin); r.Code != http.StatusBadRequest {
		t.Fatalf("a bad name: %d", r.Code)
	}
	// Signing out ends the session.
	uiDo(f.h, "POST", "/ui/logout", host, cookie, url.Values{"csrf": {m[1]}}, origin)
	if r := uiDo(f.h, "POST", "/ui/secrets", host, cookie, form, origin); r.Code < 400 {
		t.Fatalf("a session survived sign-out: %d", r.Code)
	}
}

// The page does not exist on a server reachable from other machines.
func TestSecretsPageIsLoopbackOnly(t *testing.T) {
	f := newUI(t, "0.0.0.0:8765")
	if r := uiDo(f.h, "GET", "/ui/", "10.0.0.5:8765", "", nil, nil); r.Code != http.StatusNotFound {
		t.Fatalf("a remote server shows the page: %d", r.Code)
	}
}

func randHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}
