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
	"sync"
	"time"

	"github.com/sangehq/imprimatur/src/internal/config"
	"github.com/sangehq/imprimatur/src/internal/events"
	"github.com/sangehq/imprimatur/src/internal/server"
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
	// User and Host are who the server runs as and where, for the user menu.
	User, Host string

	// Token is the first sign-in link's token: it works once, within
	// LinkLifetime. Control is the key a second impr serve presents at
	// LinkPath for a new link; empty makes none that way. Instance is a
	// random id /healthz answers with, so that impr serve can tell this
	// server from anything else on the port.
	Token, Control, Instance string
	// Tokens are the configured API tokens: one with the secrets scope still
	// signs in on /signin, into a session that reaches the secrets page only.
	Tokens []config.Token

	// Run runs one impr command line and returns its exit code and stdout:
	// the same bridge the API uses (App.runCaptured), so every page shows
	// what the CLI prints and every write is the CLI's own command.
	Run func(ctx context.Context, args []string) (int, []byte)
	// PutSecret stores a signing secret and returns its reference; it takes
	// the value as data, never on a command line. ListSecrets lists the
	// stored ones by name and reference.
	PutSecret   func(ctx context.Context, name, value string) (string, error)
	ListSecrets func() ([]server.UISecret, error)
	// Events is the event log the events page streams; Poll is how often it
	// is read (default a second).
	Events events.Log
	Poll   time.Duration

	// Web are the server.web settings; AllowAdmin is server.allowAdmin,
	// which webhook writes need unless Web.WebhookAdmin is owner.
	Web        config.ServerWeb
	AllowAdmin bool
}

// Server is the web UI.
type Server struct {
	opts     Options
	assets   *assetSet
	pages    pageSet
	sessions sessions
	links    links
	handler  http.Handler

	streams streamCount

	// tokensMu guards revoked: token ids revoked on /tokens while this server
	// runs, which sign in no more (Options.Tokens is what it started with).
	tokensMu sync.Mutex
	revoked  map[string]bool

	failMu   sync.Mutex
	failures []time.Time // failed token sign-ins in the last minute
}

// New builds a Server. It parses every template once, so a template error is
// a start-up error, not a 500 on the first visit.
func New(opts Options) (*Server, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	assets, err := loadAssets()
	if err != nil {
		return nil, err
	}
	pages, err := parsePages(assets)
	if err != nil {
		return nil, err
	}
	if opts.Token == "" {
		return nil, errors.New("web: a first sign-in link token is required")
	}
	s := &Server{opts: opts, assets: assets, pages: pages}
	s.links.add(opts.Token, opts.Now().Add(LinkLifetime))
	s.handler = s.logRequests(securityHeaders(s.hostCheck(s.auth(s.sameOrigin(s.routes())))))
	return s, nil
}

func (s *Server) now() time.Time { return s.opts.Now() }

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
