package web

import (
	"context"
	"crypto/subtle"
	"net/http"
	"slices"
	"sync"
	"time"
)

// A session ends after SessionIdle without a request, or SessionMax after it
// began, whichever comes first (authama's terms).
const (
	SessionIdle = 8 * time.Hour
	SessionMax  = 24 * time.Hour
)

// SessionCookie is the cookie a sign-in is exchanged for.
const SessionCookie = "impr_web"

// csrfField is the hidden form field that carries the session's CSRF token on
// every change.
const csrfField = "csrf"

// maxSessions bounds the session table: a ceiling on memory, not a defence.
const maxSessions = 64

type session struct {
	csrf    string
	created time.Time
	// tokenID names the API token a token sign-in used; such a session
	// reaches the secrets page only. "" for a sign-in link's session.
	tokenID string
	// scopes are that token's scopes, for server.web.tokenAccess scopes.
	scopes []string

	// mu guards what follows: requests in one session run concurrently.
	mu   sync.Mutex
	seen time.Time
	// flash is the message a change leaves for the page it redirects to.
	flash    string
	flashBad bool
	// once is a value shown once on the next page (a new API token), then
	// dropped.
	once string
}

type sessions struct {
	mu   sync.Mutex
	byID map[string]*session
}

func (ss *sessions) create(now time.Time, tokenID string, scopes []string) (string, *session) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.byID == nil {
		ss.byID = map[string]*session{}
	}
	if len(ss.byID) >= maxSessions {
		var oldest string
		for k, v := range ss.byID {
			if oldest == "" || v.created.Before(ss.byID[oldest].created) {
				oldest = k
			}
		}
		delete(ss.byID, oldest)
	}
	id := NewToken()
	sess := &session{csrf: NewToken(), created: now, seen: now, tokenID: tokenID, scopes: scopes}
	ss.byID[id] = sess
	return id, sess
}

// get returns the live session id names, marked seen now, or nil.
func (ss *sessions) get(id string, now time.Time) *session {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	sess := ss.byID[id]
	if sess == nil {
		return nil
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if now.Sub(sess.created) >= SessionMax || now.Sub(sess.seen) >= SessionIdle {
		delete(ss.byID, id)
		return nil
	}
	sess.seen = now
	return sess
}

func (ss *sessions) end(id string) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	delete(ss.byID, id)
}

// setFlash leaves a message for the next page.
func (sess *session) setFlash(msg string, bad bool) {
	sess.mu.Lock()
	sess.flash, sess.flashBad = msg, bad
	sess.mu.Unlock()
}

// setOnce keeps a value for one showing; takeOnce returns it and forgets it.
func (sess *session) setOnce(v string) {
	sess.mu.Lock()
	sess.once = v
	sess.mu.Unlock()
}

func (sess *session) takeOnce() string {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	v := sess.once
	sess.once = ""
	return v
}

// takeFlash returns the message and forgets it.
func (sess *session) takeFlash() (string, bool) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	msg, bad := sess.flash, sess.flashBad
	sess.flash, sess.flashBad = "", false
	return msg, bad
}

func equal(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

type ctxKey int

const sessionKey ctxKey = 0

func withSession(ctx context.Context, s *session) context.Context {
	return context.WithValue(ctx, sessionKey, s)
}

func sessionFrom(ctx context.Context) *session {
	s, _ := ctx.Value(sessionKey).(*session)
	return s
}

// fillSession puts the signed-in session's state into a page's view, and
// hands over (once) the message a change left for it.
func (s *Server) fillSession(r *http.Request, v *view) {
	sess := sessionFrom(r.Context())
	if sess == nil {
		return
	}
	v.Authed, v.TokenOnly, v.CSRF = true, sess.tokenID != "", sess.csrf
	v.Owner, v.Reach = sess.tokenID == "", s.reach(sess)
	if !v.Panel {
		v.Flash, v.FlashBad = sess.takeFlash()
	}
}

// webScopes are the scopes that reach anything in the web UI.
var webScopes = []string{"read", "secrets", "admin", "events"}

// reach is what a token sign-in may use: the Secrets page alone under
// server.web.tokenAccess secrets (the default), else the token's scopes.
func (s *Server) reach(sess *session) []string {
	if sess == nil || sess.tokenID == "" {
		return nil
	}
	if !s.opts.Web.TokenScopes() {
		return []string{"secrets"}
	}
	return sess.scopes
}

// can reports whether sess may use scope: a sign-in link's session always.
func (s *Server) can(sess *session, scope string) bool {
	if sess == nil {
		return false
	}
	return sess.tokenID == "" || slices.Contains(s.reach(sess), scope)
}

// need lets a request through only when its session may use scope; any
// other answers the styled 403 and runs nothing.
func (s *Server) need(scope string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.can(sessionFrom(r.Context()), scope) {
			s.renderError(w, r, http.StatusForbidden, "Not for this sign-in",
				"This browser signed in with an API token that does not reach this page. Open the link impr serve printed for the whole web UI.")
			return
		}
		next(w, r)
	}
}
