package web

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// ContentSecurityPolicy is sent on every response. Everything is same-origin
// and nothing is inline: no <style>, no style=, no inline script. img-src
// allows data: because Tabler's CSS draws checkboxes and selects with data:
// SVG URLs.
const ContentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"

// PermissionsPolicy turns off every device API for these pages.
const PermissionsPolicy = "camera=(), microphone=(), geolocation=(), usb=(), serial=(), bluetooth=(), payment=(), clipboard-read=(), display-capture=()"

// MaxBodyBytes is the largest request body the web UI reads. The largest form
// is a secret (64 KiB); nothing comes near this.
const MaxBodyBytes = 1 << 20

// securityHeaders sets the headers every response carries, error pages
// included, so they are set before anything else can answer.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", ContentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		// same-origin, not no-referrer: under no-referrer Chromium sends
		// "Origin: null" on this server's own form posts, which sameOrigin
		// refuses. same-origin still sends nothing to another site, and the
		// sign-in token leaves the address before any page can link out.
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", PermissionsPolicy)
		if r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
			r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

// hostCheck refuses any Host outside the allowed set with 421.
func (s *Server) hostCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hostAllowed(r.Host) {
			s.renderError(w, r, http.StatusMisdirectedRequest, "Unknown host",
				"This server only answers to the address impr serve printed when it started.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) hostAllowed(host string) bool {
	for _, h := range s.opts.AllowedHosts {
		if strings.EqualFold(h, host) {
			return true
		}
	}
	return false
}

// sameOrigin lets a request that can change state through only when it came
// from this server's own pages: an Origin naming the host it was sent to (or,
// with no Origin, Sec-Fetch-Site: same-origin), and the session's CSRF token.
// The form is parsed here, so a body over MaxBodyBytes is refused as what it
// is. The token sign-in has no session yet, so the Origin is its check (with
// the failed sign-in limit).
func (s *Server) sameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if !s.originAllowed(r) {
			s.renderError(w, r, http.StatusForbidden, "Cross-origin request refused",
				"Changes can only be made from this server's own pages.")
			return
		}
		err := r.ParseForm()
		if err == nil && strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
			err = r.ParseMultipartForm(MaxBodyBytes) //nolint:gosec // G120: securityHeaders caps the body at MaxBodyBytes first
		}
		if err != nil {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				s.renderError(w, r, http.StatusRequestEntityTooLarge, "Too large", "That form is larger than any change here sends.")
				return
			}
			s.renderError(w, r, http.StatusBadRequest, "Unreadable form", "The form could not be read; reload the page and try again.")
			return
		}
		if r.URL.Path != "/signin" {
			sess := sessionFrom(r.Context())
			if sess == nil || !equal(r.PostFormValue(csrfField), sess.csrf) {
				s.renderError(w, r, http.StatusForbidden, "Missing or stale form token", "Reload the page and try again.")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" || origin == "null" {
		return origin == "" && r.Header.Get("Sec-Fetch-Site") == "same-origin"
	}
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	return s.hostAllowed(u.Host) && strings.EqualFold(u.Host, r.Host)
}

// healthz says that this is imprimatur's web UI and which instance, so impr
// serve can tell a server it recorded from anything else on the port. It
// carries no state.
func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]string{"app": "imprimatur", "instance": s.opts.Instance})
}

// NewToken returns 32 random bytes, base64url: a sign-in link, a session or a
// CSRF token. Since Go 1.24 crypto/rand.Read never fails; it ends the program
// rather than hand back a predictable value.
func NewToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
