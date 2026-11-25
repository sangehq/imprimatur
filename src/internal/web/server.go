// Package web is `impr serve`'s own web UI, on a loopback listener of its
// own beside the API (design ID-34): server-rendered html/template pages over
// the same commands the CLI runs, with Tabler's CSS and a few small ES
// modules, all embedded in the binary, so a page makes no request beyond this
// server. It follows the sange and authama web UI behaviour: a one-time
// sign-in link, a strict session, a CSRF token on every change, and one set of
// security headers on every response.
package web

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

// Options configure a Server.
type Options struct {
	// AllowedHosts are the Host header values answered (AllowedHosts); any
	// other is refused with 421, the DNS-rebinding defence.
	AllowedHosts []string
	// Version is shown in the footer and on About.
	Version string
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Log writes a change (any request but GET or HEAD) to the server's log;
	// Debug writes a page view, and nil logs none. Only the path is written,
	// never the query.
	Log   func(format string, args ...any)
	Debug func(format string, args ...any)
}

// Server is the web UI.
type Server struct {
	opts    Options
	handler http.Handler
}

// New builds a Server.
func New(opts Options) (*Server, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	s := &Server{opts: opts}
	s.handler = s.logRequests(securityHeaders(s.hostCheck(s.sameOrigin(s.routes()))))
	return s, nil
}

// Handler is the whole middleware chain and the routes.
func (s *Server) Handler() http.Handler { return s.handler }

// Serve answers on ln until ctx ends, then shuts down with a ten-second grace
// for requests in flight. There is no WriteTimeout: the events page holds a
// stream open; a body is read in 30 seconds or not at all.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, done := context.WithTimeout(context.Background(), 10*time.Second)
	defer done()
	if err := srv.Shutdown(shutdown); err != nil {
		return err
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
