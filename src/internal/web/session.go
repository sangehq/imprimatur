package web

import (
	"context"
	"crypto/subtle"
	"net/http"
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

	// mu guards what follows: requests in one session run concurrently.
	mu   sync.Mutex
	seen time.Time
	// flash is the message a change leaves for the page it redirects to.
	flash    string
	flashBad bool
}

type sessions struct {
	mu   sync.Mutex
	byID map[string]*session
}

func (ss *sessions) create(now time.Time, tokenID string) (string, *session) {
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
	sess := &session{csrf: NewToken(), created: now, seen: now, tokenID: tokenID}
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
	if !v.Panel {
		v.Flash, v.FlashBad = sess.takeFlash()
	}
}
