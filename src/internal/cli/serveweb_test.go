package cli

import (
	"bytes"
	"context"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"runtime"
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

// A second impr serve opens the running one with a fresh link instead of
// starting another.
func TestServeReusesTheRunningInstance(t *testing.T) {
	h := newHarness(t)
	sv := startServe(t, h, "--listen", "127.0.0.1:0", "--port", "0", "--no-open")
	dir := webDirOf(t, h)
	first := waitLink(t, dir, "", sv)
	code, _, errOut := h.impr("serve", "--listen", "127.0.0.1:0", "--port", "0", "--no-open")
	if code != 0 || !strings.Contains(errOut, "already running") {
		t.Fatalf("a second serve: %d %s", code, errOut)
	}
	second := waitLink(t, dir, first, sv)
	if strings.SplitN(first, "?", 2)[0] != strings.SplitN(second, "?", 2)[0] {
		t.Fatalf("the second link names another server: %s, %s", first, second)
	}
	if _, resp := signInWith(t, second); resp.StatusCode != 200 {
		t.Fatalf("the fresh link: %d", resp.StatusCode)
	}
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
