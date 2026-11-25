package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sangehq/imprimatur/src/internal/paths"
)

// syncBuf is a buffer a running server and the test can share.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// serving is an impr serve running in the background of a test.
type serving struct {
	cancel context.CancelFunc
	done   chan int
	errOut *syncBuf
	out    *syncBuf
}

// startServe runs impr serve with args until stop, with no terminal.
func startServe(t *testing.T, h *harness, args ...string) *serving {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	sv := &serving{cancel: cancel, done: make(chan int, 1), errOut: &syncBuf{}, out: &syncBuf{}}
	a := &App{Stdout: sv.out, Stderr: sv.errOut, Getenv: func(k string) string { return h.env[k] }, GOOS: h.os, Home: t.TempDir(), User: "tester",
		Runner: h.run, Now: time.Now, Notifier: h.notifier}
	go func() { sv.done <- a.Run(ctx, append([]string{"serve"}, args...)) }()
	t.Cleanup(func() { sv.stop(t) })
	return sv
}

func (sv *serving) stop(t *testing.T) int {
	t.Helper()
	sv.cancel()
	select {
	case code := <-sv.done:
		sv.done <- code
		return code
	case <-time.After(20 * time.Second):
		t.Fatal("impr serve did not stop")
	}
	return -1
}

// webDirOf is the harness's web state directory.
func webDirOf(t *testing.T, h *harness) string {
	t.Helper()
	d, err := paths.Resolve(paths.Env{GOOS: h.os, Getenv: func(k string) string { return h.env[k] }})
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(d.State, "web")
}

// waitLink waits for the owner-only sign-in link file to name a link other
// than old, and returns it.
func waitLink(t *testing.T, dir, old string, sv *serving) string {
	t.Helper()
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		b, err := os.ReadFile(filepath.Join(dir, "signin-link"))
		if l := strings.TrimSpace(string(b)); err == nil && l != "" && l != old {
			return l
		}
		select {
		case code := <-sv.done:
			sv.done <- code
			t.Fatalf("impr serve ended (%d) before writing a link: %s", code, sv.errOut)
		default:
		}
	}
	t.Fatalf("no sign-in link was written: %s", sv.errOut)
	return ""
}

func signInWith(t *testing.T, link string) (*http.Client, *http.Response) {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	resp, err := c.Get(link)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return c, resp
}

// Owner decision 2026-11-25: bare impr serve starts the web UI too, with no
// API token configured; the link goes to an owner-only file when nobody is at
// a terminal, and the log names the file, never the token.
func TestServeStartsTheUIWithoutAnAPIToken(t *testing.T) {
	h := newHarness(t)
	sv := startServe(t, h, "--listen", "127.0.0.1:0", "--port", "0", "--no-open")
	dir := webDirOf(t, h)
	link := waitLink(t, dir, "", sv)
	if !strings.HasPrefix(link, "http://127.0.0.1:") || !strings.Contains(link, "/?token=") {
		t.Fatalf("link %q", link)
	}
	if runtime.GOOS != "windows" {
		for _, p := range []string{filepath.Join(dir, "signin-link"), filepath.Join(dir, "serve.json")} {
			if st, err := os.Stat(p); err != nil || st.Mode().Perm() != 0o600 {
				t.Errorf("%s: %v %v, want 0600", p, st.Mode(), err)
			}
		}
		if st, err := os.Stat(dir); err != nil || st.Mode().Perm() != 0o700 {
			t.Errorf("%s: %v, want 0700", dir, err)
		}
	}
	c, resp := signInWith(t, link)
	if resp.StatusCode != 200 || resp.Request.URL.RawQuery != "" {
		t.Fatalf("sign in: %d at %s", resp.StatusCode, resp.Request.URL)
	}
	if r, err := c.Get(link); err != nil || r.Request.URL.RawQuery != "" {
		t.Fatalf("the used link: %v", err)
	}
	token := strings.SplitN(link, "token=", 2)[1]
	if strings.Contains(sv.errOut.String(), token) || strings.Contains(sv.out.String(), token) {
		t.Fatal("the sign-in token reached the log")
	}
	if !strings.Contains(sv.errOut.String(), filepath.Join(dir, "signin-link")) {
		t.Fatalf("the log does not name the link file: %s", sv.errOut)
	}
	if code := sv.stop(t); code != 0 {
		t.Fatalf("stop: %d %s", code, sv.errOut)
	}
	if _, err := os.Stat(filepath.Join(dir, "serve.json")); !os.IsNotExist(err) {
		t.Fatalf("serve.json outlived the server: %v", err)
	}
	// --no-web keeps today's API-only behaviour: no token, no server.
	if code, _, errOut := h.impr("serve", "--no-web", "--check-config"); code != 1 || !strings.Contains(errOut, "no API token") {
		t.Fatalf("--no-web without a token: %d %s", code, errOut)
	}
}

// atTerminal runs impr as a person at a terminal would, and returns when it
// ends.
func atTerminal(t *testing.T, h *harness, args ...string) (int, string, string) {
	t.Helper()
	var o, e bytes.Buffer
	a := &App{Stdout: &o, Stderr: &e, Getenv: func(k string) string { return h.env[k] }, GOOS: h.os, Home: t.TempDir(), User: "tester",
		Runner: h.run, Now: time.Now, Notifier: h.notifier, Stdin: strings.NewReader(""), Interactive: func() bool { return true }}
	done := make(chan int, 1)
	go func() { done <- a.Run(context.Background(), args) }()
	select {
	case code := <-done:
		return code, o.String(), e.String()
	case <-time.After(15 * time.Second):
		t.Fatal("impr did not return")
	}
	return -1, "", ""
}

var linkLineRe = regexp.MustCompile(`web UI    (http://\S+)`)

// A second impr serve at a terminal, for the same API address, opens the
// running one with a fresh link instead of starting another.
func TestServeReusesTheRunningInstance(t *testing.T) {
	h := newHarness(t)
	sv := startServe(t, h, "--listen", "127.0.0.1:0", "--port", "0", "--no-open")
	dir := webDirOf(t, h)
	first := waitLink(t, dir, "", sv)
	code, out, errOut := atTerminal(t, h, "serve", "--listen", "127.0.0.1:0", "--port", "0", "--no-open")
	m := linkLineRe.FindStringSubmatch(out)
	if code != 0 || !strings.Contains(errOut, "already running") || m == nil {
		t.Fatalf("a second serve: %d %s %s", code, out, errOut)
	}
	if strings.SplitN(first, "?", 2)[0] != strings.SplitN(m[1], "?", 2)[0] {
		t.Fatalf("the second link names another server: %s, %s", first, m[1])
	}
	if _, resp := signInWith(t, m[1]); resp.StatusCode != 200 {
		t.Fatalf("the fresh link: %d", resp.StatusCode)
	}
}

// Without a terminal (the service unit), or for another API address, a
// second impr serve always starts its own API; its web part opens the running
// web UI with a fresh link and starts no second web listener.
func TestASecondServeStillStartsItsAPI(t *testing.T) {
	h := newHarness(t)
	sv := startServe(t, h, "--listen", "127.0.0.1:0", "--port", "0", "--no-open")
	dir := webDirOf(t, h)
	first := waitLink(t, dir, "", sv)
	for name, args := range map[string][]string{
		"no terminal, the same API address": {"--listen", "127.0.0.1:0", "--port", "0", "--no-open"},
		"no terminal, another API address":  {"--listen", "localhost:0", "--port", "0", "--no-open"},
	} {
		second := startServe(t, h, args...)
		link := waitLink(t, dir, first, second)
		waitLog(t, second, "server    listening on")
		if strings.SplitN(first, "?", 2)[0] != strings.SplitN(link, "?", 2)[0] {
			t.Errorf("%s: the link names a second web UI: %s, %s", name, first, link)
		}
		if strings.Count(second.errOut.String(), "web       http://") != 1 || !strings.Contains(second.errOut.String(), "already running") {
			t.Errorf("%s: %s", name, second.errOut)
		}
		if code := second.stop(t); code != 0 {
			t.Errorf("%s: stop: %d", name, code)
		}
		if readWebInstance(dir) == nil {
			t.Errorf("%s: stopping the second serve removed the first one's record", name)
		}
		first = link
	}
	// At a terminal, another API address starts its API too.
	h2 := *h
	done := make(chan struct{})
	go func() {
		defer close(done)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		var o, e syncBuf
		a := &App{Stdout: &o, Stderr: &e, Getenv: func(k string) string { return h2.env[k] }, GOOS: h2.os, Home: t.TempDir(), User: "tester",
			Runner: h2.run, Now: time.Now, Notifier: h2.notifier, Stdin: strings.NewReader(""), Interactive: func() bool { return true }}
		code := a.Run(ctx, []string{"serve", "--listen", "localhost:0", "--port", "0", "--no-open"})
		if code != 0 || !strings.Contains(e.String(), "server    listening on") || !linkLineRe.MatchString(o.String()) {
			t.Errorf("at a terminal, another API address: %d %s %s", code, o.String(), e.String())
		}
	}()
	<-done
	_ = sv
}

// waitLog waits for a line in a running serve's log.
func waitLog(t *testing.T, sv *serving, want string) {
	t.Helper()
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if strings.Contains(sv.errOut.String(), want) {
			return
		}
	}
	t.Fatalf("no %q in: %s", want, sv.errOut)
}

// A web UI that cannot start (its state folder, its port) does not stop the
// API: impr serve logs why and serves the API.
func TestServeKeepsTheAPIWhenTheWebUIFails(t *testing.T) {
	h := newHarness(t)
	dir := webDirOf(t, h)
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("not a folder"), 0o600); err != nil {
		t.Fatal(err)
	}
	sv := startServe(t, h, "--listen", "127.0.0.1:0", "--port", "0", "--no-open")
	waitLog(t, sv, "server    listening on")
	waitLog(t, sv, "web       not started:")
	if code := sv.stop(t); code != 0 {
		t.Fatalf("stop: %d %s", code, sv.errOut)
	}
	// A pinned web port that is taken: the API still starts.
	h2 := newHarness(t)
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = taken.Close() }()
	port := strconv.Itoa(taken.Addr().(*net.TCPAddr).Port)
	sv2 := startServe(t, h2, "--listen", "127.0.0.1:0", "--port", port, "--no-open")
	waitLog(t, sv2, "server    listening on")
	waitLog(t, sv2, "web       not started:")
}

// The service unit never opens a browser: it passes --no-open, and nobody is
// at a terminal under it anyway.
func TestUnitServeDoesNotOpenABrowser(t *testing.T) {
	for kind, doc := range map[string]string{"systemd": SystemdUnit(oddUnit), "launchd": LaunchdPlist(oddUnit), "task": TaskXML(oddUnit)} {
		if !strings.Contains(doc, "--no-open") {
			t.Errorf("the %s unit does not pass --no-open", kind)
		}
	}
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	for name, tc := range map[string]struct {
		noOpen, terminal bool
		goos             string
		env              map[string]string
		want             bool
	}{
		"a desktop terminal":     {false, true, "darwin", nil, true},
		"--no-open":              {true, true, "darwin", nil, false},
		"no terminal (the unit)": {false, false, "darwin", nil, false},
		"over SSH":               {false, true, "darwin", map[string]string{"SSH_CONNECTION": "1 2 3 4"}, false},
		"Linux without display":  {false, true, "linux", nil, false},
		"Linux with Wayland":     {false, true, "linux", map[string]string{"WAYLAND_DISPLAY": "wayland-0"}, true},
	} {
		if got, _ := wantBrowser(tc.noOpen, tc.terminal, tc.goos, env(tc.env)); got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}

// A token revoked with impr server token revoke while impr serve runs stops
// working in the web UI at once: its session is refused on the next request,
// and it signs in no more (owner, 2026-11-25).
func TestATokenRevokedFromTheCLIStopsInTheWebUI(t *testing.T) {
	h := newHarness(t)
	tok := strings.TrimSpace(h.ok("server", "token", "add", "--scopes", "secrets"))
	sv := startServe(t, h, "--listen", "127.0.0.1:0", "--port", "0", "--no-open")
	link := waitLink(t, webDirOf(t, h), "", sv)
	base := strings.SplitN(link, "/?", 2)[0]
	signIn := func() (*http.Client, *http.Response) {
		jar, _ := cookiejar.New(nil)
		c := &http.Client{Jar: jar, Timeout: 10 * time.Second}
		req, _ := http.NewRequest("POST", base+"/signin", strings.NewReader(url.Values{"token": {tok}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", base)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return c, resp
	}
	session, r := signIn()
	if r.StatusCode != 200 || r.Request.URL.Path != "/secrets" {
		t.Fatalf("token sign-in: %d %s", r.StatusCode, r.Request.URL)
	}
	var list struct {
		Tokens []struct {
			ID string `json:"id"`
		} `json:"tokens"`
	}
	if err := json.Unmarshal([]byte(h.ok("server", "token", "list", "--json")), &list); err != nil || len(list.Tokens) != 1 {
		t.Fatalf("token list: %v", err)
	}
	h.ok("server", "token", "revoke", list.Tokens[0].ID)
	if r, err := session.Get(base + "/secrets"); err != nil || r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the revoked token's session: %v %v", err, r.StatusCode)
	}
	if _, r := signIn(); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the revoked token signed in: %d", r.StatusCode)
	}
}
