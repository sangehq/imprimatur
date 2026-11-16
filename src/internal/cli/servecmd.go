package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/sangehq/imprimatur/src/internal/config"
	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/events"
	"github.com/sangehq/imprimatur/src/internal/server"
)

var serveFlags = flagSpec{"listen": stringFlag, "check-config": boolFlag, "json": boolFlag, "yes": boolFlag}

// runCaptured runs one command line in a copy of the app with its own output
// buffers: what the API returns is what the CLI prints.
func (a *App) runCaptured(ctx context.Context, args []string) (int, []byte) {
	var out, errOut bytes.Buffer
	b := *a
	b.Stdout, b.Stderr = &out, &errOut
	// Nobody is at a terminal for an API call: nothing it runs may prompt.
	b.Stdin, b.Interactive = nil, nil
	return b.Run(ctx, args), out.Bytes()
}

func cmdServe(ctx context.Context, a *App, args []string) (int, error) {
	if len(args) > 0 && args[0] == "install-unit" {
		return cmdServeUnit(ctx, a, args[1:])
	}
	p, err := parse(args, serveFlags)
	if err != nil {
		return 0, err
	}
	d, err := a.dirs()
	if err != nil {
		return 0, contract.Wrap(contract.Unavailable, err, "locate the imprimatur config")
	}
	eff, err := a.effective(d)
	cfg := eff.Config
	if err != nil {
		return 0, contract.Wrap(contract.Usage, err, "the imprimatur config cannot be read")
	}
	if v := p.str("listen"); v != "" {
		cfg.Server.Listen = v
	}
	if ps := cfg.Validate(); len(ps) > 0 {
		return 0, contract.New(contract.Usage, "the server config is not valid").WithDetails(ps...)
	}
	if len(cfg.Server.Tokens) == 0 && len(cfg.Server.Inbound) == 0 {
		return 0, contract.New(contract.Usage, "no API token or inbound endpoint is configured, so nothing could call the server").
			WithFix("impr server token add --scopes read,verify")
	}
	var tlsCfg *tls.Config
	if cfg.Server.TLS != nil {
		if tlsCfg, err = serverTLS(*cfg.Server.TLS); err != nil {
			return 0, contract.Wrap(contract.Usage, err, "the server TLS files cannot be used")
		}
	}
	if p.on("check-config") {
		a.say("server    config ok: %d token(s), %d inbound endpoint(s), %d root(s), sign %v", len(cfg.Server.Tokens), len(cfg.Server.Inbound), len(cfg.Server.Roots), cfg.Server.AllowSign)
		return 0, nil
	}
	if cfg.Server.Remote() && a.Interactive != nil && a.Interactive() && !p.on("yes") {
		// A person started it at a terminal: say plainly what is about to be
		// reachable, and ask (owner decision 2026-11-15: prompt when needed).
		a.say("server    %s is reachable from other machines. Callers need a client certificate signed by %s and a token.", cfg.Server.Listen, cfg.Server.TLS.ClientCAFile)
		_, _ = fmt.Fprint(a.Stderr, "type yes to listen there: ")
		var answer string
		if a.Stdin != nil {
			_, _ = fmt.Fscanln(a.Stdin, &answer)
		}
		if answer != "yes" {
			return 0, contract.New(contract.Usage, "not started")
		}
	}
	ln, where, err := listen(d.State, cfg.Server.Listen)
	if err != nil {
		return 0, contract.Wrap(contract.Unavailable, err, "the server cannot listen")
	}
	if strings.HasPrefix(where, "unix:") {
		ln = peerListener{Listener: ln, uid: os.Getuid(), refused: func(uid int) {
			a.say("server    refused a socket connection from uid %d", uid)
			a.bus().Emit(context.Background(), "server.auth.refused", "server", map[string]any{"reason": "socket peer is another user", "uid": uid})
		}}
	}
	if tlsCfg != nil {
		ln = tls.NewListener(ln, tlsCfg)
		where = "https+" + where
	}
	res := a.host().Secrets
	h := server.Handler(server.Options{Config: cfg, Run: a.runCaptured, Secret: res.Resolve, StateDir: d.State, Now: a.Now, Log: a.say,
		Events: events.Log{Dir: filepath.Join(d.State, "events")},
		Emit: func(short, subject string, data map[string]any) {
			a.bus().Emit(context.Background(), short, subject, data)
		}})
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 60 * time.Second,
		WriteTimeout: 35 * time.Minute, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	bus := a.bus()
	bus.Emit(ctx, "server.started", "server", map[string]any{"listen": strings.SplitN(where, ":", 2)[0]})
	a.say("server    listening on %s (Ctrl-C to stop)", where)
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	// The long-running mode: answer impr notify ping, and check certificate
	// expiry every six hours.
	if n := a.notifier(); n != nil {
		go func() { _ = n.Listen(ctx) }()
	}
	go func() {
		t := time.NewTicker(anchorEvery(cfg))
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if _, err := a.anchor(ctx, false); err != nil {
					a.say("audit     not anchored: %v", err)
				}
			}
		}
	}()
	go func() {
		t := time.NewTicker(6 * time.Hour)
		defer t.Stop()
		for {
			a.runCaptured(ctx, []string{"cert", "list", "--json"})
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return 0, contract.Wrap(contract.Unavailable, err, "the server stopped")
		}
	}
	shut, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = srv.Shutdown(shut)
	bus.Emit(context.Background(), "server.stopped", "server", map[string]any{})
	a.say("server    stopped")
	return 0, nil
}

// listen opens the Unix socket in a private directory, or a loopback TCP port.
func listen(state, spec string) (net.Listener, string, error) {
	if spec == "" || spec == "unix" {
		dir := filepath.Join(state, "server")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, "", err
		}
		if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: a directory needs its execute bit; 0700 is owner-only
			return nil, "", err
		}
		sock := filepath.Join(dir, "impr.sock")
		if st, err := os.Lstat(sock); err == nil {
			if st.Mode().Type() != fs.ModeSocket {
				return nil, "", fmt.Errorf("%s exists and is not a socket", sock)
			}
			_ = os.Remove(sock) // a stale socket from an earlier run
		}
		ln, err := net.Listen("unix", sock)
		if err != nil {
			return nil, "", err
		}
		if err := os.Chmod(sock, 0o600); err != nil {
			_ = ln.Close()
			return nil, "", err
		}
		return ln, "unix:" + sock, nil
	}
	ln, err := net.Listen("tcp", spec)
	if err != nil {
		return nil, "", err
	}
	return ln, "tcp:" + ln.Addr().String(), nil
}

var serverFlags = flagSpec{"json": boolFlag, "scopes": listFlag}

// NewToken makes an API token: impr_ and 32 random bytes, base64url.
func NewToken() (token, id, sum string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return
	}
	token = "impr_" + base64.RawURLEncoding.EncodeToString(b)
	s := sha256.Sum256([]byte(token))
	sum = hex.EncodeToString(s[:])
	idb := make([]byte, 6)
	if _, err = rand.Read(idb); err != nil {
		return
	}
	return token, "tok_" + hex.EncodeToString(idb), sum, nil
}

func cmdServer(_ context.Context, a *App, args []string) (int, error) {
	p, err := parse(args, serverFlags)
	if err != nil {
		return 0, err
	}
	if len(p.pos) < 2 || p.pos[0] != "token" {
		return 0, contract.New(contract.Usage, "impr server token add|list|revoke").WithFix("impr server token add --scopes read,verify")
	}
	d, err := a.dirs()
	if err != nil {
		return 0, contract.Wrap(contract.Unavailable, err, "locate the imprimatur config")
	}
	cfg, err := config.Load(d.Config)
	if err != nil {
		return 0, contract.Wrap(contract.Usage, err, "the imprimatur config cannot be read")
	}
	switch p.pos[1] {
	case "add":
		scopes := p.list("scopes")
		if len(scopes) == 0 {
			return 0, contract.New(contract.Usage, "--scopes is required (%s)", strings.Join(config.Scopes, ", "))
		}
		tok, id, sum, err := NewToken()
		if err != nil {
			return 0, err
		}
		cfg.Server.Tokens = append(cfg.Server.Tokens, config.Token{ID: id, SHA256: sum, Scopes: scopes})
		if err := config.Save(d.Config, cfg); err != nil {
			return 0, contract.Wrap(contract.Usage, err, "the token was not saved")
		}
		// The token itself is printed once, to stdout; only its digest is kept.
		_, _ = fmt.Fprintln(a.Stdout, tok)
		a.say("server    token %s added with scopes %s; it is shown once, store it now", id, strings.Join(scopes, ","))
		return 0, nil
	case "list":
		if p.on("json") {
			type row struct {
				ID     string   `json:"id"`
				Scopes []string `json:"scopes"`
			}
			out := []row{}
			for _, t := range cfg.Server.Tokens {
				out = append(out, row{t.ID, t.Scopes})
			}
			a.json(map[string]any{"contract": contract.Version, "tokens": out})
			return 0, nil
		}
		for _, t := range cfg.Server.Tokens {
			a.say("%s  %s", t.ID, strings.Join(t.Scopes, ","))
		}
		return 0, nil
	case "revoke":
		if len(p.pos) != 3 {
			return 0, contract.New(contract.Usage, "impr server token revoke ID")
		}
		i := slices.IndexFunc(cfg.Server.Tokens, func(t config.Token) bool { return t.ID == p.pos[2] })
		if i < 0 {
			return 0, contract.New(contract.Usage, "no token %s", p.pos[2])
		}
		cfg.Server.Tokens = slices.Delete(cfg.Server.Tokens, i, i+1)
		if err := config.Save(d.Config, cfg); err != nil {
			return 0, err
		}
		a.say("server    token %s revoked; a running server keeps it until restarted", p.pos[2])
		return 0, nil
	}
	return 0, contract.New(contract.Usage, "unknown server token subcommand %q", p.pos[1])
}

// serverTLS builds the mTLS configuration: TLS 1.3 only, and every client
// must present a certificate that chains to the configured CA. A private key
// readable by group or others is refused.
func serverTLS(t config.ServerTLS) (*tls.Config, error) {
	if st, err := os.Stat(t.KeyFile); err != nil {
		return nil, err
	} else if runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by others (%v); chmod 600 it", t.KeyFile, st.Mode().Perm())
	}
	cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(t.ClientCAFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("%s holds no PEM certificate", t.ClientCAFile)
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}, nil
}
