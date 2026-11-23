package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"html/template"
	"io"
	"net"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sangehq/imprimatur/src/internal/secrets"
)

// The secrets page (owner decision ID-31, threat I-23): impr serve's own
// local page for adding a signing secret, the App Store Connect key first,
// without a terminal. It exists only when the server is not reachable from
// other machines, answers only to a loopback Host, signs in with an API token
// holding the secrets scope, and never shows a value back.

// UISecret is a stored secret as the page lists it: its name and reference.
type UISecret struct {
	Name string
	Ref  string
}

const (
	uiCookie          = "impr_ui"
	uiSessionLife     = 15 * time.Minute
	uiMaxSessions     = 8
	uiMaxValue        = 64 << 10
	uiLoginsPerMinute = 5
)

type uiSession struct {
	csrf    string
	tokenID string
	expires time.Time
}

type uiState struct {
	mu       sync.Mutex
	sessions map[string]*uiSession
	failures []time.Time // failed sign-ins in the last minute
}

func randomHex() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // the OS random source failing is not recoverable
	}
	return hex.EncodeToString(b)
}

// uiRoutes adds the page when the server can store secrets and is local.
func (s *server) uiRoutes(mux *http.ServeMux) {
	if s.o.PutSecret == nil || s.o.Config.Server.Remote() {
		return
	}
	s.ui = &uiState{sessions: map[string]*uiSession{}}
	mux.HandleFunc("GET /ui/", s.uiGuard(s.uiPage))
	mux.HandleFunc("POST /ui/login", s.uiGuard(s.uiLogin))
	mux.HandleFunc("POST /ui/logout", s.uiGuard(s.uiWrite(s.uiLogout)))
	mux.HandleFunc("POST /ui/secrets", s.uiGuard(s.uiWrite(s.uiStore)))
}

// uiGuard sets the page's headers and refuses a Host that is not loopback,
// which a DNS-rebinding page cannot fake.
func (s *server) uiGuard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		if !loopbackHost(r.Host) {
			http.Error(w, "this page answers only on 127.0.0.1, [::1] or localhost", http.StatusMisdirectedRequest)
			return
		}
		if r.Method == http.MethodPost && !sameOrigin(r) {
			http.Error(w, "a request from another site was refused", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func loopbackHost(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	host = strings.Trim(host, "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// sameOrigin accepts a form posted from this page: the browser's Origin, when
// it sends one, names this host, and Sec-Fetch-Site does not say cross-site.
func sameOrigin(r *http.Request) bool {
	if sf := r.Header.Get("Sec-Fetch-Site"); sf != "" && sf != "same-origin" && sf != "none" {
		return false
	}
	o := r.Header.Get("Origin")
	return o == "" || o == "http://"+r.Host || o == "https://"+r.Host
}

// session returns the signed-in session, dropping expired ones.
func (s *server) session(r *http.Request) (string, *uiSession) {
	c, err := r.Cookie(uiCookie)
	if err != nil {
		return "", nil
	}
	s.ui.mu.Lock()
	defer s.ui.mu.Unlock()
	now := s.o.Now()
	for id, se := range s.ui.sessions {
		if now.After(se.expires) {
			delete(s.ui.sessions, id)
		}
	}
	se := s.ui.sessions[c.Value]
	if se == nil {
		return "", nil
	}
	se.expires = now.Add(uiSessionLife)
	return c.Value, se
}

// uiWrite requires a session and its CSRF token on a form post.
func (s *server) uiWrite(next func(w http.ResponseWriter, r *http.Request, id string, se *uiSession)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, se := s.session(r)
		if se == nil {
			http.Error(w, "sign in first", http.StatusUnauthorized)
			return
		}
		got := r.PostFormValue("csrf")
		if len(got) != len(se.csrf) || subtle.ConstantTimeCompare([]byte(got), []byte(se.csrf)) != 1 {
			http.Error(w, "the form is out of date; reload the page", http.StatusForbidden)
			return
		}
		next(w, r, id, se)
	}
}

func (s *server) uiLogin(w http.ResponseWriter, r *http.Request) {
	s.ui.mu.Lock()
	now := s.o.Now()
	s.ui.failures = slices.DeleteFunc(s.ui.failures, func(t time.Time) bool { return now.Sub(t) > time.Minute })
	limited := len(s.ui.failures) >= uiLoginsPerMinute
	s.ui.mu.Unlock()
	if limited {
		w.Header().Set("Retry-After", "60")
		s.render(w, http.StatusTooManyRequests, uiData{Message: "Too many failed sign-ins; wait a minute."})
		return
	}
	tok, found := s.token(r.PostFormValue("token"))
	if !found {
		s.ui.mu.Lock()
		s.ui.failures = append(s.ui.failures, now)
		s.ui.mu.Unlock()
		s.refusedEvent(r, "no valid token (secrets page)")
		s.render(w, http.StatusUnauthorized, uiData{Message: "That is not a valid API token."})
		return
	}
	if !slices.Contains(tok.Scopes, "secrets") {
		s.render(w, http.StatusForbidden, uiData{Message: "Token " + tok.ID + " lacks the secrets scope (impr server token add --scopes secrets)."})
		return
	}
	id := randomHex()
	s.ui.mu.Lock()
	if len(s.ui.sessions) >= uiMaxSessions {
		var oldest string
		for k, se := range s.ui.sessions {
			if oldest == "" || se.expires.Before(s.ui.sessions[oldest].expires) {
				oldest = k
			}
		}
		delete(s.ui.sessions, oldest)
	}
	s.ui.sessions[id] = &uiSession{csrf: randomHex(), tokenID: tok.ID, expires: now.Add(uiSessionLife)}
	s.ui.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: uiCookie, Value: id, Path: "/ui", HttpOnly: true, SameSite: http.SameSiteStrictMode, //nolint:gosec // G124: Secure is set under TLS; the page is loopback-only, where plain http is the norm
		Secure: r.TLS != nil, MaxAge: int(uiSessionLife.Seconds())})
	s.logf("server    secrets page: %s signed in", tok.ID)
	http.Redirect(w, r, "/ui/", http.StatusSeeOther)
}

func (s *server) uiLogout(w http.ResponseWriter, r *http.Request, id string, _ *uiSession) {
	s.ui.mu.Lock()
	delete(s.ui.sessions, id)
	s.ui.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: uiCookie, Value: "", Path: "/ui", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1, //nolint:gosec // G124: as the cookie it clears
		Secure: r.TLS != nil})
	s.render(w, http.StatusOK, uiData{Message: "Signed out."})
}

func (s *server) uiPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/ui/" {
		http.NotFound(w, r)
		return
	}
	_, se := s.session(r)
	if se == nil {
		s.render(w, http.StatusOK, uiData{})
		return
	}
	s.renderSecrets(w, http.StatusOK, se, "")
}

func (s *server) uiStore(w http.ResponseWriter, r *http.Request, _ string, se *uiSession) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	value := r.PostFormValue("value")
	if f, _, err := r.FormFile("file"); err == nil {
		b, rerr := io.ReadAll(io.LimitReader(f, uiMaxValue+1))
		_ = f.Close()
		if rerr == nil && len(b) > 0 {
			value = string(b)
		}
	}
	if !secrets.ValidName(name) {
		s.renderSecrets(w, http.StatusBadRequest, se, "A name is A-Z, 0-9 and _, starting with a letter, like IMPR_NOTARY_KEY.")
		return
	}
	if len(value) > uiMaxValue || strings.TrimSpace(value) == "" {
		s.renderSecrets(w, http.StatusBadRequest, se, "Give a value of at most 64 KiB, or a file.")
		return
	}
	ref, err := s.o.PutSecret(r.Context(), name, value)
	if err != nil {
		s.renderSecrets(w, http.StatusBadRequest, se, "Not stored: "+err.Error())
		return
	}
	s.logf("server    secrets page: %s stored %s as %s", se.tokenID, name, ref)
	s.renderSecrets(w, http.StatusOK, se, "Stored "+name+" as "+ref+". A profile names it env://"+name+".")
}

func (s *server) renderSecrets(w http.ResponseWriter, code int, se *uiSession, msg string) {
	d := uiData{SignedIn: true, CSRF: se.csrf, Message: msg}
	if s.o.ListSecrets != nil {
		if list, err := s.o.ListSecrets(); err == nil {
			sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
			d.Secrets = list
		}
	}
	s.render(w, code, d)
}

type uiData struct {
	SignedIn bool
	CSRF     string
	Message  string
	Secrets  []UISecret
}

var uiTemplate = template.Must(template.New("ui").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>impr secrets</title>
<style>body{font:15px/1.5 system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;color:#111}
label{display:block;margin-top:.8rem;font-weight:600}input,textarea{width:100%;box-sizing:border-box;font:inherit;padding:.4rem}
textarea{height:8rem;font-family:ui-monospace,monospace}button{margin-top:1rem;padding:.4rem 1rem;font:inherit}
p.msg{padding:.5rem;background:#eef}table{border-collapse:collapse;margin-top:1rem}td{padding:.2rem .8rem .2rem 0}
@media (prefers-color-scheme:dark){body{background:#111;color:#eee}p.msg{background:#223}}</style></head><body>
<h1>impr secrets</h1>
{{if .Message}}<p class="msg">{{.Message}}</p>{{end}}
{{if .SignedIn}}
<p>A value goes to this computer's secret store and is never shown again. The <code>.env</code> keeps only its reference.</p>
<form method="post" action="/ui/secrets" enctype="multipart/form-data" autocomplete="off">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<label for="name">Name</label><input id="name" name="name" required pattern="[A-Z][A-Z0-9_]{0,62}" placeholder="IMPR_NOTARY_KEY">
<label for="value">Value</label><textarea id="value" name="value" spellcheck="false"></textarea>
<label for="file">or a file (an App Store Connect .p8 key)</label><input id="file" name="file" type="file">
<button type="submit">Store</button></form>
{{if .Secrets}}<table><tr><td><strong>Name</strong></td><td><strong>Reference</strong></td></tr>
{{range .Secrets}}<tr><td><code>{{.Name}}</code></td><td><code>{{.Ref}}</code></td></tr>{{end}}</table>{{end}}
<form method="post" action="/ui/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button type="submit">Sign out</button></form>
{{else}}
<form method="post" action="/ui/login" autocomplete="off">
<label for="token">API token with the secrets scope</label><input id="token" name="token" type="password" required>
<button type="submit">Sign in</button></form>
<p>Make one with <code>impr server token add --scopes secrets</code>.</p>
{{end}}</body></html>
`))

func (s *server) render(w http.ResponseWriter, code int, d uiData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_ = uiTemplate.Execute(w, d)
}
