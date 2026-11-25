package e2e

import (
	"bufio"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

// webServe is a running impr serve with its web UI.
type webServe struct {
	t    *testing.T
	cmd  *exec.Cmd
	link string
	base string // http://127.0.0.1:port
	c    *http.Client
	csrf string
}

// startWeb starts the built impr serve on free ports with no browser, and
// reads the one-time link from the owner-only file the log names (nobody is
// at a terminal here, so the link is never printed).
func startWeb(t *testing.T, e *env) *webServe {
	t.Helper()
	cmd := exec.Command(impr, "serve", "--listen", "127.0.0.1:0", "--port", "0", "--no-open")
	cmd.Env = e.vars
	errOut, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	w := &webServe{t: t, cmd: cmd}
	t.Cleanup(w.stop)
	fileRe := regexp.MustCompile(`sign-in link is in (\S+), for`)
	found := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(errOut)
		for sc.Scan() {
			if m := fileRe.FindStringSubmatch(sc.Text()); m != nil {
				found <- m[1]
			}
		}
	}()
	var file string
	select {
	case file = <-found:
	case <-time.After(30 * time.Second):
		t.Fatal("impr serve named no sign-in link file")
	}
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	w.link = strings.TrimSpace(string(b))
	u, err := url.Parse(w.link)
	if err != nil || u.Host == "" {
		t.Fatalf("link %q", w.link)
	}
	w.base = "http://" + u.Host
	jar, _ := cookiejar.New(nil)
	w.c = &http.Client{Jar: jar, Timeout: 30 * time.Second}
	return w
}

func (w *webServe) stop() {
	if w.cmd.Process == nil || w.cmd.ProcessState != nil {
		return
	}
	if runtime.GOOS == "windows" {
		_ = w.cmd.Process.Kill()
	} else {
		_ = w.cmd.Process.Signal(os.Interrupt)
	}
	done := make(chan error, 1)
	go func() { done <- w.cmd.Wait() }()
	select {
	case err := <-done:
		_ = err // interrupted on purpose: its exit status says nothing
	case <-time.After(20 * time.Second):
		_ = w.cmd.Process.Kill()
		err := <-done
		_ = err
	}
}

var csrfMeta = regexp.MustCompile(`<meta name="csrf-token" content="([A-Za-z0-9_-]{43})">`)

// get loads a page and returns its status and body, keeping its CSRF token.
func (w *webServe) get(path string) (int, string) {
	w.t.Helper()
	resp, err := w.c.Get(w.base + path)
	if err != nil {
		w.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if m := csrfMeta.FindSubmatch(b); m != nil {
		w.csrf = string(m[1])
	}
	return resp.StatusCode, string(b)
}

// post sends a form from this server's own page, as a browser does.
func (w *webServe) post(path string, form url.Values) (int, string) {
	w.t.Helper()
	req, _ := http.NewRequest("POST", w.base+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", w.base)
	resp, err := w.c.Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// TestE2EWebUI: the built impr serve starts its web UI with no API token,
// a one-time link signs a browser in and is gone from the address, every page
// loads from the real command layer, a test certificate is made through its
// form, the link works once, and a change without the CSRF token is refused.
func TestE2EWebUI(t *testing.T) {
	e := newEnv(t)
	w := startWeb(t, e)
	if code, _ := w.get("/"); code != http.StatusUnauthorized {
		t.Fatalf("before sign-in: %d", code)
	}
	resp, err := w.c.Get(w.link)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || resp.Request.URL.RawQuery != "" {
		t.Fatalf("sign in: %d at %s", resp.StatusCode, resp.Request.URL)
	}
	code, body := w.get("/")
	if code != 200 || !strings.Contains(body, `rel="icon" type="image/svg+xml"`) || w.csrf == "" {
		t.Fatalf("the overview: %d", code)
	}
	// Every page answers, from the real command layer.
	for _, page := range []string{"/doctor", "/profiles", "/certs", "/certs/new", "/secrets", "/secrets/new", "/tokens", "/tokens/new",
		"/webhooks", "/webhooks/new", "/events", "/audit", "/about"} {
		if code, body := w.get(page); code != 200 || !strings.Contains(body, `<main id="main"`) {
			t.Fatalf("GET %s: %d", page, code)
		}
	}
	// One write: a test certificate, through the form, with the CSRF token.
	if code, body := w.post("/certs", url.Values{"csrf": {w.csrf}, "name": {"e2e-cert"}, "subject": {"E2E Test"}, "days": {"2"}}); code != 200 ||
		!strings.Contains(body, "CN=E2E Test") || !strings.Contains(body, `class="toast show"`) {
		t.Fatalf("create a test certificate: %d", code)
	}
	if code, body := w.get("/profiles/e2e-cert"); code != 200 || !strings.Contains(body, "e2e-cert") {
		t.Fatalf("the new test profile: %d", code)
	}
	if code, _ := w.post("/certs", url.Values{"name": {"e2e-other"}, "subject": {"X"}, "days": {"2"}}); code != http.StatusForbidden {
		t.Fatalf("a write without the CSRF token: %d", code)
	}
	jar, _ := cookiejar.New(nil)
	other := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	if r, err := other.Get(w.link); err != nil || r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the used link signed in another browser: %v %v", err, r.StatusCode)
	}
	if code, _ := w.post("/signout", url.Values{}); code != http.StatusForbidden {
		t.Fatalf("a change without the CSRF token: %d", code)
	}
	if code, _ := w.post("/signout", url.Values{"csrf": {w.csrf}}); code != http.StatusOK {
		t.Fatalf("sign out: %d", code)
	}
	if _, err := os.Stat(filepath.Join(stateDir(e), "web", "serve.json")); err != nil {
		t.Fatalf("serve.json: %v", err)
	}
	w.stop()
	// Windows has no interrupt to send another process: the server is killed
	// there, and a killed server cannot remove its record.
	if _, err := os.Stat(filepath.Join(stateDir(e), "web", "serve.json")); runtime.GOOS != "windows" && !os.IsNotExist(err) {
		t.Fatalf("serve.json outlived the server: %v", err)
	}
}

func stateDir(e *env) string {
	for _, v := range e.vars {
		if s, ok := strings.CutPrefix(v, "IMPR_STATE_DIR="); ok {
			return s
		}
	}
	return ""
}
