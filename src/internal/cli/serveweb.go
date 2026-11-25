package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/sangehq/imprimatur/src/internal/config"
	"github.com/sangehq/imprimatur/src/internal/events"
	"github.com/sangehq/imprimatur/src/internal/execx"
	"github.com/sangehq/imprimatur/src/internal/paths"
	"github.com/sangehq/imprimatur/src/internal/server"
	"github.com/sangehq/imprimatur/src/internal/web"
)

// The web UI's side of impr serve (design ID-34): a record of the running
// instance, the sign-in link file, and opening the browser. Everything lives
// in <state>/web, a 0700 directory: serve.json (the instance, 0600), the
// sign-in link when nobody is at a terminal (0600), and the launch pages that
// hand a link to the browser (0600).

// webInstance is what a running impr serve records in serve.json, so the next
// impr serve opens it with a fresh link instead of starting another.
type webInstance struct {
	PID      int       `json:"pid"`
	Addr     string    `json:"addr"` // 127.0.0.1:port, as bound
	Instance string    `json:"instance"`
	Control  string    `json:"control"` // the key /auth/link asks for
	Version  string    `json:"version"`
	Started  time.Time `json:"started"`
	// Listen is the API's server.listen this impr serve was started with
	// ("" for the default socket or pipe): a second impr serve at a terminal
	// for the same address only opens this one.
	Listen string `json:"listen"`
}

const (
	webRecordFile = "serve.json"
	webLinkFile   = "signin-link"
	launchPattern = "serve-open-*.html"
)

// webClient asks a recorded server whether it is still there: one that does
// not answer in two seconds is treated as gone.
var webClient = &http.Client{Timeout: 2 * time.Second}

// webDir makes <state>/web owner-only and returns it.
func webDir(state string) (string, error) {
	dir := filepath.Join(state, "web")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: a directory needs its execute bit; 0700 is owner-only
		return "", err
	}
	return dir, nil
}

// writePrivate writes data to path, owner-only, replacing what was there.
func writePrivate(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func readWebInstance(dir string) *webInstance {
	b, err := os.ReadFile(filepath.Join(dir, webRecordFile)) //nolint:gosec // G304: impr's own record in its owner-only state directory
	if err != nil {
		return nil
	}
	var r webInstance
	if json.Unmarshal(b, &r) != nil || r.Addr == "" || r.Instance == "" || r.Control == "" {
		return nil
	}
	return &r
}

func writeWebInstance(dir string, r webInstance) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return writePrivate(filepath.Join(dir, webRecordFile), append(b, '\n'))
}

// removeWebInstance removes the record if it is still this instance's, so a
// server stopping late never removes the record of one that replaced it.
func removeWebInstance(dir, instance string) {
	if r := readWebInstance(dir); r != nil && r.Instance == instance {
		_ = os.Remove(filepath.Join(dir, webRecordFile))
	}
}

// alive reports whether the recorded server still answers, as that instance.
// The instance id, not the pid or the port, proves it: a pid is reused and a
// port taken by something else once the server is gone.
func (r *webInstance) alive() bool {
	resp, err := webClient.Get("http://" + r.Addr + "/healthz")
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	var h struct {
		App      string `json:"app"`
		Instance string `json:"instance"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&h) != nil {
		return false
	}
	return h.App == "imprimatur" && h.Instance == r.Instance
}

// newLink asks the recorded server for a fresh sign-in link. The control key
// opens nothing but that server: if another process took its port, the key
// is worth nothing there.
func (r *webInstance) newLink() (string, error) {
	req, err := http.NewRequest(http.MethodPost, "http://"+r.Addr+web.LinkPath, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set(web.ControlHeader, r.Control)
	resp, err := webClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	var reply struct {
		SignIn string `json:"sign_in"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&reply) != nil ||
		!strings.HasPrefix(reply.SignIn, "?token=") {
		return "", fmt.Errorf("the web UI at %s answered %d", r.Addr, resp.StatusCode)
	}
	return "http://" + r.Addr + "/" + reply.SignIn, nil
}

// webPort reads --port: unset is the default port with fallbacks; a number
// (0 for any free port) pins it.
func webPort(p parsed) (port int, pinned bool, err error) {
	v := p.str("port")
	if v == "" {
		return web.DefaultPort, false, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > 65535 {
		return 0, false, fmt.Errorf("--port is a port number, 0 to 65535")
	}
	return n, true, nil
}

// wantBrowser reports whether impr serve opens the browser: not with
// --no-open, not without a terminal (a script or the service unit), and not
// where there is no desktop to open one on, which why says.
func wantBrowser(noOpen, terminal bool, goos string, getenv func(string) string) (ok bool, why string) {
	if noOpen || !terminal {
		return false, ""
	}
	for _, v := range []string{"SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"} {
		if getenv(v) != "" {
			return false, "this is an SSH session"
		}
	}
	if goos != "darwin" && goos != "windows" && getenv("DISPLAY") == "" && getenv("WAYLAND_DISPLAY") == "" {
		return false, "there is no desktop session (DISPLAY and WAYLAND_DISPLAY are not set)"
	}
	return true, ""
}

// openPage is execx.OpenPage, swappable in tests.
var openPage = execx.OpenPage

// openBrowser opens link without putting it on any command line: any local
// user can read another's argv, and the link signs in once. An owner-only page
// in dir redirects to it, and the opener is given the page's path (as
// authama and Jupyter do). Pages from earlier launches are swept once their
// link has expired.
func openBrowser(goos, dir, link string) error {
	old, _ := filepath.Glob(filepath.Join(dir, launchPattern))
	for _, f := range old {
		if fi, err := os.Lstat(f); err == nil && fi.Mode().IsRegular() && time.Since(fi.ModTime()) > web.LinkLifetime {
			_ = os.Remove(f)
		}
	}
	f, err := os.CreateTemp(dir, launchPattern)
	if err != nil {
		return err
	}
	page := f.Name()
	if err := f.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		_ = f.Close()
		_ = os.Remove(page)
		return err
	}
	if _, err := f.WriteString(launchPage(link)); err != nil {
		_ = f.Close()
		_ = os.Remove(page)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(page)
		return err
	}
	if err := openPage(goos, page); err != nil {
		_ = os.Remove(page)
		return err
	}
	return nil
}

// launchPage redirects to link at once.
func launchPage(link string) string {
	attr := html.EscapeString(link)
	return "<!doctype html>\n<html><head><meta charset=\"utf-8\">\n<meta http-equiv=\"refresh\" content=\"0;url=" + attr + "\">\n" +
		"<title>imprimatur</title></head><body><p><a href=\"" + attr + "\">Open imprimatur</a></p></body></html>\n"
}

// showLink hands a sign-in link to the person who started impr serve: on a
// terminal it is printed (and opened, at a desktop); with nobody there (the
// service unit, a script) it goes to an owner-only file, and the log names
// the file, never the token.
func (a *App) showLink(dir, link, addr string, noOpen bool) error {
	terminal := a.Interactive != nil && a.Interactive()
	if !terminal {
		file := filepath.Join(dir, webLinkFile)
		if err := writePrivate(file, []byte(link+"\n")); err != nil {
			return err
		}
		a.say("web       http://%s/ (its one-time sign-in link is in %s, for %d minutes)", addr, file, int(web.LinkLifetime/time.Minute))
		return nil
	}
	_, _ = fmt.Fprintf(a.Stdout, "web UI    %s\n", link)
	a.say("web       the link signs in once, within %d minutes; run impr serve again for a fresh one", int(web.LinkLifetime/time.Minute))
	ok, why := wantBrowser(noOpen, terminal, a.GOOS, a.Getenv)
	if why != "" {
		a.say("web       not opening a browser: %s; open the link above on this machine, or tunnel to it", why)
	}
	if ok {
		if err := openBrowser(a.GOOS, dir, link); err != nil {
			a.say("web       could not open a browser (%v); open the link above yourself", err)
		}
	}
	return nil
}

// openRunning opens the web UI a running impr serve already serves, with a
// fresh link. It reports false when there is none to open.
func (a *App) openRunning(dir string, noOpen bool) bool {
	r := readWebInstance(dir)
	if r == nil || !r.alive() {
		return false
	}
	link, err := r.newLink()
	if err != nil {
		a.say("web       the running web UI (pid %d) gave no link: %v; starting another", r.PID, err)
		return false
	}
	a.say("web       already running for this state directory (pid %d, http://%s/); stop it with Ctrl-C where it runs", r.PID, r.Addr)
	if err := a.showLink(dir, link, r.Addr, noOpen); err != nil {
		a.say("web       the link could not be written: %v", err)
	}
	return true
}

// boundPort is the port a listener bound.
func boundPort(ln net.Listener) (int, error) {
	if ta, ok := ln.Addr().(*net.TCPAddr); ok {
		return ta.Port, nil
	}
	return 0, errors.New("the web UI's listener is not TCP")
}

// startWeb starts the web UI on wln beside the API, records it and hands
// over its first link. A failure is logged and the web UI is left off; the
// API keeps serving (review B1). The returned channel closes once the web UI
// has shut down and removed its record, after ctx ends.
func (a *App) startWeb(ctx context.Context, wln net.Listener, wdir string, cfg config.Config, d paths.Dirs, verbose, noOpen bool) <-chan struct{} {
	done := make(chan struct{})
	ws, rec, link, err := a.newWeb(wln, cfg, d, verbose)
	if err == nil {
		rec.Listen = cfg.Server.Listen
		err = writeWebInstance(wdir, rec)
	}
	if err != nil {
		a.say("web       not started: %v", err)
		_ = wln.Close()
		close(done)
		return done
	}
	go func() {
		defer close(done)
		err := ws.Serve(ctx, wln)
		removeWebInstance(wdir, rec.Instance)
		if err != nil && !errors.Is(err, net.ErrClosed) {
			a.say("web       stopped: %v", err)
		}
	}()
	if err := a.showLink(wdir, link, rec.Addr, noOpen); err != nil {
		a.say("web       the sign-in link could not be written: %v", err)
	}
	return done
}

// newWeb builds the web UI on wln, with a first sign-in link and the record
// a second impr serve reads. With verbose it logs page views as well.
func (a *App) newWeb(wln net.Listener, cfg config.Config, d paths.Dirs, verbose bool) (*web.Server, webInstance, string, error) {
	port, err := boundPort(wln)
	if err != nil {
		return nil, webInstance{}, "", err
	}
	host, _ := os.Hostname()
	rec := webInstance{PID: os.Getpid(), Addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), Instance: web.NewToken()[:16],
		Control: web.NewToken(), Version: version, Started: a.Now()}
	first := web.NewToken()
	opts := web.Options{AllowedHosts: web.AllowedHosts(port), Version: version, Now: a.Now, Log: a.say, User: a.User, Host: host,
		Token: first, Control: rec.Control, Instance: rec.Instance, Tokens: cfg.Server.Tokens,
		// The pages run the same commands the API does, through the same
		// bridge; a secret is stored by PutSecret, never through a command line.
		Run: a.runCaptured, PutSecret: a.PutSecret,
		ListSecrets: func() ([]server.UISecret, error) { return envSecrets(d.Config) },
		Events:      events.Log{Dir: filepath.Join(d.State, "events")},
		Web:         cfg.Server.Web, AllowAdmin: cfg.Server.AllowAdmin,
		// The tokens as configured now, through the loader the CLI uses, so
		// impr server token revoke takes effect in the web UI at once.
		LiveTokens: func() ([]config.Token, error) {
			eff, err := a.effective(d)
			if err != nil {
				return nil, err
			}
			return eff.Config.Server.Tokens, nil
		}}
	if verbose { // --verbose: page views too, not only changes
		opts.Debug = a.say
	}
	ws, err := web.New(opts)
	if err != nil {
		return nil, webInstance{}, "", err
	}
	return ws, rec, "http://" + rec.Addr + "/?token=" + first, nil
}
