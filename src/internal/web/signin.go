package web

import (
	"encoding/json"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sangehq/imprimatur/src/internal/config"
	"github.com/sangehq/imprimatur/src/internal/server"
)

// A sign-in link works once, and only for LinkLifetime after it was made:
// the address impr serve prints, or one a second impr serve asks the running
// one for.
const LinkLifetime = 10 * time.Minute

// maxLinks bounds the links waiting to be used.
const maxLinks = 32

// LinkPath is where a second impr serve asks the running server for a new
// sign-in link, presenting the control key from serve.json in ControlHeader.
const (
	LinkPath      = "/auth/link"
	ControlHeader = "X-Impr-Control"
)

// loginsPerMinute bounds failed token sign-ins, as the API's secrets page did.
const loginsPerMinute = 5

// LinkState is a sign-in link not yet used.
type LinkState struct {
	Token   string    `json:"token"`
	Expires time.Time `json:"expires"`
}

type links struct {
	mu    sync.Mutex
	byTok map[string]time.Time
}

func (l *links) add(tok string, expires time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.byTok == nil {
		l.byTok = map[string]time.Time{}
	}
	if len(l.byTok) >= maxLinks {
		var oldest string
		for k, v := range l.byTok {
			if oldest == "" || v.Before(l.byTok[oldest]) {
				oldest = k
			}
		}
		delete(l.byTok, oldest)
	}
	l.byTok[tok] = expires
}

// take uses tok up: whether it was a link still waiting. It is forgotten
// either way, and every waiting link is compared in constant time.
func (l *links) take(tok string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	var found string
	for k := range l.byTok {
		if equal(k, tok) {
			found = k
		}
	}
	if found == "" {
		return false
	}
	expires := l.byTok[found]
	delete(l.byTok, found)
	return now.Before(expires)
}

// NewLink makes a sign-in link on s that works once, for LinkLifetime.
func NewLink(s *Server) LinkState {
	st := LinkState{Token: NewToken(), Expires: s.now().Add(LinkLifetime)}
	s.links.add(st.Token, st.Expires)
	return st
}

// auth admits a request with a live session, exchanges a valid ?token= for
// one, and refuses everything else with the styled 401. The assets, /healthz,
// the token sign-in page and the link endpoint answer without a session.
func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/assets/"), r.URL.Path == "/healthz", r.URL.Path == "/signin":
			next.ServeHTTP(w, r)
			return
		case r.URL.Path == LinkPath && r.Method == http.MethodPost:
			s.handleLink(w, r)
			return
		}
		tok := r.URL.Query().Get("token")
		if tok != "" {
			// A browser already signed in keeps its session; a link it carries
			// (a reload, a used link) is used up if it still works, and dropped
			// from the address either way. No page here has a parameter of
			// that name.
			if sess := s.cookieSession(r); sess != nil {
				if r.Method == http.MethodGet {
					// A valid link opened by a browser signed in with an API token
					// makes it the owner's: a new session, the token one ended.
					if s.links.take(tok, s.now()) && sess.tokenID != "" {
						if c, err := r.Cookie(SessionCookie); err == nil {
							s.sessions.end(c.Value)
						}
						id, _ := s.sessions.create(s.now(), "", nil)
						s.setSessionCookie(w, r, id)
						s.logf("web       signed in with a sign-in link, in place of an API token session")
					}
					redirectWithoutToken(w, r)
					return
				}
			} else {
				// Only a GET spends a link: a HEAD (a link preview) cannot.
				if r.Method != http.MethodGet || !s.links.take(tok, s.now()) {
					s.logf("web       a sign-in link was refused (used, expired or unknown)")
					s.renderUnauthorized(w, r)
					return
				}
				id, _ := s.sessions.create(s.now(), "", nil)
				s.setSessionCookie(w, r, id)
				s.logf("web       signed in with a sign-in link")
				redirectWithoutToken(w, r)
				return
			}
		}
		sess := s.cookieSession(r)
		if sess == nil {
			s.renderUnauthorized(w, r)
			return
		}
		// A token session is checked against the configured tokens on every
		// request: one no longer listed (revoked from the terminal, or here)
		// ends; a list that cannot be read refuses it (fails closed).
		if sess.tokenID != "" {
			tokens, err := s.configuredTokens()
			if err != nil {
				s.logf("web       a token session was refused: the token list cannot be read: %v", err)
				s.renderError(w, r, http.StatusServiceUnavailable, "Token sign-in is unavailable",
					"impr's configuration cannot be read just now, so this API token session is refused. Open the link impr serve printed, or fix the config and reload.")
				return
			}
			if !slices.ContainsFunc(tokens, func(t config.Token) bool { return t.ID == sess.tokenID }) {
				s.logf("web       %s is no longer configured: its sessions ended", sess.tokenID)
				s.revoke(sess.tokenID)
				s.renderUnauthorized(w, r)
				return
			}
		}
		r = r.WithContext(withSession(r.Context(), sess))
		if sess.tokenID != "" && !s.opts.Web.TokenScopes() && !tokenSessionPath(r) {
			s.renderError(w, r, http.StatusForbidden, "Secrets only",
				"This browser signed in with an API token, which reaches the secrets page only. Open the link impr serve printed for the whole web UI.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// configuredTokens are the API tokens configured now: Options.LiveTokens,
// which reads the config the CLI edits, or the start-up list without it.
func (s *Server) configuredTokens() ([]config.Token, error) {
	if s.opts.LiveTokens != nil {
		return s.opts.LiveTokens()
	}
	return s.opts.Tokens, nil
}

// tokenSessionPath is what a token sign-in reaches under
// server.web.tokenAccess secrets: the secrets page and its form, and signing
// out. Under scopes, each route's s.need decides.
func tokenSessionPath(r *http.Request) bool {
	switch r.URL.Path {
	case "/secrets", "/secrets/new":
		return true
	case "/signout":
		return r.Method == http.MethodPost
	}
	return false
}

func (s *Server) cookieSession(r *http.Request) *session {
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		return nil
	}
	return s.sessions.get(c.Value, s.now())
}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, id string) {
	// Secure only under TLS: the listener is loopback-only plain http.
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, //nolint:gosec // G124: see above
		Secure: r.TLS != nil, MaxAge: int(SessionMax.Seconds())})
}

// localPath is a path on this server: "/" alone, or "/" and then anything but
// a second "/" or a backslash, which a browser reads as another host.
var localPath = regexp.MustCompile(`^/(?:$|[^/\\])`)

// redirectWithoutToken sends the browser to the same address without
// ?token=, so the token leaves the address bar and the history.
func redirectWithoutToken(w http.ResponseWriter, r *http.Request) {
	clean := *r.URL
	q := clean.Query()
	q.Del("token")
	target := clean.EscapedPath()
	if enc := q.Encode(); enc != "" {
		target += "?" + enc
	}
	// The check guards the redirect call itself.
	if localPath.MatchString(target) {
		http.Redirect(w, r, target, http.StatusSeeOther) //nolint:gosec // G710: target is a local path, checked on this line's condition
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) renderUnauthorized(w http.ResponseWriter, r *http.Request) {
	s.render(w, http.StatusUnauthorized, "signin", s.newView(r, "", "Sign in", signinData{Unauthorized: true}))
}

type signinData struct {
	Unauthorized bool
	Message      string
}

// signinPage is GET /signin: sign in with an API token that holds the secrets
// scope.
func (s *Server) signinPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, http.StatusOK, "signin", s.newView(r, "", "Sign in", signinData{}))
}

// signinToken is POST /signin.
func (s *Server) signinToken(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	// The limit is checked, the token matched and a failure counted in one
	// locked step, so requests at once cannot all pass the check.
	// The configured tokens now, never a copy from start-up: a token revoked
	// from the terminal signs in no more. A list that cannot be read refuses.
	tokens, terr := s.configuredTokens()
	if terr != nil {
		s.logf("web       a token sign-in was refused: the token list cannot be read: %v", terr)
		s.renderError(w, r, http.StatusServiceUnavailable, "Token sign-in is unavailable",
			"impr's configuration cannot be read just now, so no API token is accepted. Open the link impr serve printed, or fix the config and try again.")
		return
	}
	s.failMu.Lock()
	s.failures = slices.DeleteFunc(s.failures, func(t time.Time) bool { return now.Sub(t) > time.Minute })
	limited := len(s.failures) >= loginsPerMinute
	var tok config.Token
	found := false
	if !limited {
		tok, found = server.MatchToken(tokens, r.PostFormValue("token"))
		if found && s.isRevoked(tok.ID) {
			found = false
		}
		if !found {
			s.failures = append(s.failures, now)
		}
	}
	s.failMu.Unlock()
	if limited {
		w.Header().Set("Retry-After", "60")
		s.render(w, http.StatusTooManyRequests, "signin", s.newView(r, "", "Sign in", signinData{Message: "Too many failed sign-ins; wait a minute."}))
		return
	}
	if !found {
		s.logf("web       a token sign-in was refused")
		s.render(w, http.StatusUnauthorized, "signin", s.newView(r, "", "Sign in", signinData{Message: "That is not a valid API token."}))
		return
	}
	landing := "/secrets"
	if s.opts.Web.TokenScopes() {
		landing = ""
		for _, l := range []struct{ scope, path string }{{"read", "/"}, {"secrets", "/secrets"}, {"admin", "/tokens"}, {"events", "/events"}} {
			if landing == "" && slices.Contains(tok.Scopes, l.scope) {
				landing = l.path
			}
		}
		if landing == "" {
			s.render(w, http.StatusForbidden, "signin", s.newView(r, "", "Sign in",
				signinData{Message: "Token " + tok.ID + " has none of the scopes the web UI uses (" + strings.Join(webScopes, ", ") + ")."}))
			return
		}
	} else if !slices.Contains(tok.Scopes, "secrets") {
		s.render(w, http.StatusForbidden, "signin", s.newView(r, "", "Sign in",
			signinData{Message: "Token " + tok.ID + " lacks the secrets scope (impr server token add --scopes secrets)."}))
		return
	}
	id, sess := s.sessions.create(now, tok.ID, tok.Scopes)
	if sess == nil {
		w.Header().Set("Retry-After", "60")
		s.renderError(w, r, http.StatusTooManyRequests, "Too many sessions",
			"Every session is in use by a sign-in link; sign out of one, or open the link impr serve printed.")
		return
	}
	s.setSessionCookie(w, r, id)
	s.logf("web       %s signed in with an API token", tok.ID)
	http.Redirect(w, r, landing, http.StatusSeeOther)
}

// signout is POST /signout: it ends the session on the server and clears the
// cookie.
func (s *Server) signout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(SessionCookie); err == nil {
		s.sessions.end(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, //nolint:gosec // G124: as the cookie it clears
		SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil})
	s.logf("web       signed out")
	v := s.newView(r, "", "Signed out", errorData{Status: http.StatusOK, Heading: "Signed out",
		Message: "This browser is signed out, and its session has ended. Run impr serve again for a new sign-in link."})
	v.Authed, v.TokenOnly, v.CSRF = false, false, ""
	s.render(w, http.StatusOK, "error", v)
}

// handleLink answers a second impr serve with a new sign-in link. Only a
// caller on this machine holding the control key gets one: the key is in
// serve.json (0600, in a 0700 directory), beside nothing a browser can read.
// The key is worth nothing to anything but this server, so a process that
// took the port after this server stopped learns a key that opens nothing.
func (s *Server) handleLink(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.opts.Control == "" || !loopback(r) || forwarded(r) || !equal(r.Header.Get(ControlHeader), s.opts.Control) {
		s.renderError(w, r, http.StatusForbidden, "Forbidden", "A new sign-in link needs the key impr serve keeps for this server.")
		return
	}
	st := NewLink(s)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"sign_in": "?token=" + st.Token, "expires": st.Expires})
}

func loopback(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	return err == nil && ip != nil && ip.IsLoopback()
}

// forwarded reports a request a proxy passed on: behind a proxy on this
// machine every caller arrives from loopback.
func forwarded(r *http.Request) bool {
	return r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("Forwarded") != "" || r.Header.Get("X-Real-Ip") != ""
}

func (s *Server) logf(format string, args ...any) {
	if s.opts.Log != nil {
		s.opts.Log(format, args...)
	}
}
