package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sangehq/imprimatur/src/internal/config"
)

// clock is a settable test clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// fixture is a web UI with a first link, a control key and two API tokens.
type fixture struct {
	s         *Server
	clk       *clock
	link      string // the first sign-in link's token
	control   string
	secrets   string // an API token with the secrets scope
	secretsID string
	reader    string // one without it
}

func apiToken(t *testing.T, scopes ...string) (string, config.Token) {
	t.Helper()
	raw, id, sum, err := newAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	return raw, config.Token{ID: id, SHA256: sum, Scopes: scopes}
}

func newFixture(t *testing.T, edit func(*Options)) *fixture {
	t.Helper()
	f := &fixture{clk: &clock{t: time.Date(2026, 11, 25, 9, 0, 0, 0, time.UTC)}, link: NewToken(), control: NewToken()}
	var st, rt config.Token
	f.secrets, st = apiToken(t, "secrets")
	f.secretsID = st.ID
	f.reader, rt = apiToken(t, "read")
	o := Options{AllowedHosts: AllowedHosts(7823), Version: "test", Now: f.clk.now, Token: f.link, Control: f.control,
		Instance: "inst-1", Tokens: []config.Token{st, rt}, User: "tester", Host: "box"}
	if edit != nil {
		edit(&o)
	}
	s, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	f.s = s
	return f
}

// signIn uses a fresh link and returns the session cookie and the page's
// CSRF token.
func (f *fixture) signIn(t *testing.T) (cookie, csrf string) {
	t.Helper()
	st := NewLink(f.s)
	r := do(f.s.Handler(), "GET", "/?token="+st.Token, nil, nil)
	if r.Code != http.StatusSeeOther {
		t.Fatalf("sign in: %d %s", r.Code, r.Body)
	}
	cookie = strings.SplitN(r.Header().Get("Set-Cookie"), ";", 2)[0]
	page := do(f.s.Handler(), "GET", "/healthz", nil, map[string]string{"Cookie": cookie})
	_ = page
	return cookie, f.csrfOf(t, cookie)
}

var metaCSRF = regexp.MustCompile(`<meta name="csrf-token" content="([A-Za-z0-9_-]{43})">`)

// csrfOf reads the CSRF token a signed-in page carries.
func (f *fixture) csrfOf(t *testing.T, cookie string) string {
	t.Helper()
	r := do(f.s.Handler(), "GET", "/no-such-page", nil, map[string]string{"Cookie": cookie})
	m := metaCSRF.FindStringSubmatch(r.Body.String())
	if m == nil {
		t.Fatalf("no CSRF token on a signed-in page: %d", r.Code)
	}
	return m[1]
}

// A sign-in link signs one browser in, once, within ten minutes; a HEAD (a
// link preview) does not spend it.
func TestASignInLinkWorksOnceAndExpires(t *testing.T) {
	f := newFixture(t, nil)
	if r := do(f.s.Handler(), "HEAD", "/?token="+f.link, nil, nil); r.Code == http.StatusSeeOther {
		t.Fatal("a HEAD signed in")
	}
	r := do(f.s.Handler(), "GET", "/?token="+f.link, nil, nil)
	if r.Code != http.StatusSeeOther || r.Header().Get("Set-Cookie") == "" {
		t.Fatalf("the link: %d", r.Code)
	}
	if r := do(f.s.Handler(), "GET", "/?token="+f.link, nil, nil); r.Code != http.StatusUnauthorized {
		t.Fatalf("a used link signed in again: %d", r.Code)
	}
	late := NewLink(f.s)
	f.clk.add(LinkLifetime + time.Second)
	if r := do(f.s.Handler(), "GET", "/?token="+late.Token, nil, nil); r.Code != http.StatusUnauthorized {
		t.Fatalf("an expired link signed in: %d", r.Code)
	}
	if r := do(f.s.Handler(), "GET", "/?token="+NewToken(), nil, nil); r.Code != http.StatusUnauthorized {
		t.Fatalf("a made-up link signed in: %d", r.Code)
	}
	if r := do(f.s.Handler(), "GET", "/", nil, nil); r.Code != http.StatusUnauthorized || !strings.Contains(r.Body.String(), "impr serve") {
		t.Fatalf("no session: %d", r.Code)
	}
}

// The token leaves the address at once: a 303 to the same page without it,
// into an HttpOnly, SameSite=Strict session cookie for the whole UI.
func TestTheLinkIsStrippedFromTheAddress(t *testing.T) {
	f := newFixture(t, nil)
	r := do(f.s.Handler(), "GET", "/doctor?token="+f.link+"&type=x", nil, nil)
	if r.Code != http.StatusSeeOther || r.Header().Get("Location") != "/doctor?type=x" {
		t.Fatalf("redirect: %d %q", r.Code, r.Header().Get("Location"))
	}
	c := r.Header().Get("Set-Cookie")
	for _, want := range []string{SessionCookie + "=", "HttpOnly", "SameSite=Strict", "Path=/"} {
		if !strings.Contains(c, want) {
			t.Errorf("session cookie %q lacks %s", c, want)
		}
	}
	// A path a browser reads as another host never becomes the target.
	st := NewLink(f.s)
	if r := do(f.s.Handler(), "GET", "//evil.example/?token="+st.Token, nil, nil); r.Code == http.StatusSeeOther && r.Header().Get("Location") != "/" {
		t.Fatalf("redirected off the server: %q", r.Header().Get("Location"))
	}
}

// A session ends after 8 hours without a request, or 24 hours after it began.
func TestASessionEndsWhenIdleAndAtItsLimit(t *testing.T) {
	f := newFixture(t, nil)
	cookie, _ := f.signIn(t)
	hdr := map[string]string{"Cookie": cookie}
	f.clk.add(SessionIdle - time.Minute)
	if r := do(f.s.Handler(), "GET", "/no-such-page", nil, hdr); r.Code != http.StatusNotFound {
		t.Fatalf("a session in use ended: %d", r.Code)
	}
	f.clk.add(SessionIdle)
	if r := do(f.s.Handler(), "GET", "/no-such-page", nil, hdr); r.Code != http.StatusUnauthorized {
		t.Fatalf("an idle session lived on: %d", r.Code)
	}
	cookie, _ = f.signIn(t)
	hdr = map[string]string{"Cookie": cookie}
	for i := 0; i < 23; i++ {
		f.clk.add(time.Hour)
		if r := do(f.s.Handler(), "GET", "/no-such-page", nil, hdr); r.Code != http.StatusNotFound {
			t.Fatalf("hour %d: %d", i+1, r.Code)
		}
	}
	f.clk.add(time.Hour)
	if r := do(f.s.Handler(), "GET", "/no-such-page", nil, hdr); r.Code != http.StatusUnauthorized {
		t.Fatalf("a session lived past its limit: %d", r.Code)
	}
}

// Token sign-in is kept (owner, 2026-11-25): an API token with the secrets
// scope signs in on the sign-in page, into a session that reaches the
// secrets page only.
func TestTokenSignInStillWorks(t *testing.T) {
	f := newFixture(t, nil)
	login := func(tok string) *httptest.ResponseRecorder {
		body, hdr := form(url.Values{"token": {tok}})
		return do(f.s.Handler(), "POST", "/signin", body, hdr)
	}
	if r := do(f.s.Handler(), "GET", "/signin", nil, nil); r.Code != 200 || !strings.Contains(r.Body.String(), `name="token"`) {
		t.Fatalf("the sign-in page: %d", r.Code)
	}
	if r := login(f.reader); r.Code != http.StatusForbidden {
		t.Fatalf("a token without the secrets scope: %d", r.Code)
	}
	r := login(f.secrets)
	if r.Code != http.StatusSeeOther || r.Header().Get("Location") != "/secrets" {
		t.Fatalf("token sign-in: %d %q", r.Code, r.Header().Get("Location"))
	}
	hdr := map[string]string{"Cookie": strings.SplitN(r.Header().Get("Set-Cookie"), ";", 2)[0]}
	if r := do(f.s.Handler(), "GET", "/doctor", nil, hdr); r.Code != http.StatusForbidden {
		t.Fatalf("a token session reached /doctor: %d", r.Code)
	}
	// Five failed sign-ins a minute, then 429 until the minute is over.
	for i := 0; i < 5; i++ {
		if r := login("impr_" + strings.Repeat("A", 43)); r.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d: %d", i+1, r.Code)
		}
	}
	if r := login(f.secrets); r.Code != http.StatusTooManyRequests {
		t.Fatalf("after five failures: %d", r.Code)
	}
	f.clk.add(time.Minute + time.Second)
	if r := login(f.secrets); r.Code != http.StatusSeeOther {
		t.Fatalf("a minute later: %d", r.Code)
	}
}

// Every change carries the session's CSRF token; sign-out is one.
func TestEveryChangeNeedsTheCSRFToken(t *testing.T) {
	f := newFixture(t, nil)
	cookie, csrf := f.signIn(t)
	body, hdr := form(url.Values{})
	hdr["Cookie"] = cookie
	if r := do(f.s.Handler(), "POST", "/signout", body, hdr); r.Code != http.StatusForbidden {
		t.Fatalf("no CSRF token: %d", r.Code)
	}
	body, _ = form(url.Values{"csrf": {NewToken()}})
	if r := do(f.s.Handler(), "POST", "/signout", body, hdr); r.Code != http.StatusForbidden {
		t.Fatalf("a wrong CSRF token: %d", r.Code)
	}
	body, _ = form(url.Values{"csrf": {csrf}})
	if r := do(f.s.Handler(), "POST", "/signout", body, hdr); r.Code != http.StatusOK || !strings.Contains(r.Header().Get("Set-Cookie"), "Max-Age=0") {
		t.Fatalf("sign out: %d %q", r.Code, r.Header().Get("Set-Cookie"))
	}
	if r := do(f.s.Handler(), "GET", "/no-such-page", nil, map[string]string{"Cookie": cookie}); r.Code != http.StatusUnauthorized {
		t.Fatalf("the session outlived sign-out: %d", r.Code)
	}
}

// A second impr serve gets a fresh link from the running one with the control
// key from serve.json; nothing else does.
func TestALinkNeedsTheControlKey(t *testing.T) {
	f := newFixture(t, nil)
	ask := func(key string, extra map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", LinkPath, nil)
		req.Host = testHost
		req.RemoteAddr = "127.0.0.1:50000"
		req.Header.Set(ControlHeader, key)
		for k, v := range extra {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		f.s.Handler().ServeHTTP(rec, req)
		return rec
	}
	if r := ask(NewToken(), nil); r.Code != http.StatusForbidden {
		t.Fatalf("a wrong key: %d", r.Code)
	}
	if r := ask(f.control, map[string]string{"X-Forwarded-For": "10.0.0.5"}); r.Code != http.StatusForbidden {
		t.Fatalf("a forwarded request: %d", r.Code)
	}
	r := ask(f.control, nil)
	var reply struct {
		SignIn string `json:"sign_in"`
	}
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &reply) != nil || !strings.HasPrefix(reply.SignIn, "?token=") {
		t.Fatalf("the right key: %d %s", r.Code, r.Body)
	}
	if r := do(f.s.Handler(), "GET", "/"+reply.SignIn, nil, nil); r.Code != http.StatusSeeOther {
		t.Fatalf("the new link: %d", r.Code)
	}
	h := do(f.s.Handler(), "GET", "/healthz", nil, nil)
	if !strings.Contains(h.Body.String(), `"instance":"inst-1"`) {
		t.Fatalf("healthz: %s", h.Body)
	}
}

// A browser signed in with an API token that opens the owner's one-time link
// becomes the owner: a new session, the token one ended. A browser already
// signed in with a link only drops a new link from the address.
func TestALinkReplacesATokenSession(t *testing.T) {
	f := newFixture(t, nil)
	body, hdr := form(url.Values{"token": {f.secrets}})
	r := do(f.s.Handler(), "POST", "/signin", body, hdr)
	tokCookie := strings.SplitN(r.Header().Get("Set-Cookie"), ";", 2)[0]
	link := NewLink(f.s)
	r = do(f.s.Handler(), "GET", "/doctor?token="+link.Token, nil, map[string]string{"Cookie": tokCookie})
	owner := strings.SplitN(r.Header().Get("Set-Cookie"), ";", 2)[0]
	if r.Code != http.StatusSeeOther || owner == "" || owner == tokCookie {
		t.Fatalf("the link did not replace the token session: %d %q", r.Code, owner)
	}
	if r := do(f.s.Handler(), "GET", "/no-such-page", nil, map[string]string{"Cookie": tokCookie}); r.Code != http.StatusUnauthorized {
		t.Fatalf("the token session lived on: %d", r.Code)
	}
	if r := do(f.s.Handler(), "GET", "/no-such-page", nil, map[string]string{"Cookie": owner}); r.Code != http.StatusNotFound {
		t.Fatalf("the owner session: %d", r.Code)
	}
	// An owner session opening another link keeps its session; the link is spent.
	again := NewLink(f.s)
	r = do(f.s.Handler(), "GET", "/?token="+again.Token, nil, map[string]string{"Cookie": owner})
	if r.Code != http.StatusSeeOther || r.Header().Get("Set-Cookie") != "" {
		t.Fatalf("an owner session opening a link: %d %q", r.Code, r.Header().Get("Set-Cookie"))
	}
	if r := do(f.s.Handler(), "GET", "/?token="+again.Token, nil, nil); r.Code != http.StatusUnauthorized {
		t.Fatalf("the spent link signed another browser in: %d", r.Code)
	}
}

// Failed token sign-ins are counted and checked in one locked step: twenty
// at once still allow no more than five through to a token check.
func TestFailedSignInsAreCountedAtomically(t *testing.T) {
	f := newFixture(t, nil)
	codes := make(chan int, 20)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			body, hdr := form(url.Values{"token": {"impr_" + strings.Repeat("B", 43)}})
			codes <- do(f.s.Handler(), "POST", "/signin", body, hdr).Code
		}()
	}
	close(start)
	wg.Wait()
	close(codes)
	refused := 0
	for c := range codes {
		if c == http.StatusUnauthorized {
			refused++
		}
	}
	if refused > loginsPerMinute {
		t.Fatalf("%d sign-ins were checked in a minute, want at most %d", refused, loginsPerMinute)
	}
}

// A full session table makes room by ending the oldest token session, never
// an owner's link session; with nothing but link sessions, a token sign-in
// is refused.
func TestATokenSignInNeverEvictsTheOwner(t *testing.T) {
	f := newFixture(t, nil)
	var owners []string
	for i := 0; i < maxSessions; i++ {
		c, _ := f.signIn(t)
		owners = append(owners, c)
		f.clk.add(time.Second)
	}
	body, hdr := form(url.Values{"token": {f.secrets}})
	r := do(f.s.Handler(), "POST", "/signin", body, hdr)
	if r.Code != http.StatusTooManyRequests || len(styled(t, f.s, r.Body.String())) > 0 {
		t.Fatalf("a token sign-in into a table of owners: %d", r.Code)
	}
	for i, c := range owners {
		if r := do(f.s.Handler(), "GET", "/no-such-page", nil, map[string]string{"Cookie": c}); r.Code != http.StatusNotFound {
			t.Fatalf("owner session %d was evicted: %d", i, r.Code)
		}
	}
}
