// Package server is `impr serve`: a REST API over the same commands the CLI
// runs (design §7). Every endpoint answers with exactly the --json document
// the CLI prints, because each handler builds a fixed argument list from
// validated fields and runs the command through Options.Run; the API cannot
// drift from the CLI, and contract v1 holds for both.
//
// Safety, in order: a private transport (Unix socket in a 0700 dir, or
// loopback TCP); a scoped bearer token on every endpoint but /v1/health; a
// body cap and strict JSON; artifacts read only under configured roots;
// /v1/sign off unless the owner enables it, and then only with the sign
// scope and a manifest bound to a commit and tree, exactly as the CLI
// requires (not a signing oracle, design ID-05).
package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sangehq/imprimatur/src/internal/config"
	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/events"
)

// MaxBody bounds every request body. Requests carry manifests and names,
// never artifacts.
const MaxBody = 1 << 20

// Options configure the handler.
type Options struct {
	Config config.Config
	// Run runs one impr command line and returns its exit code and stdout.
	Run func(ctx context.Context, args []string) (int, []byte)
	// Secret resolves a secret reference (inbound webhook keys).
	Secret func(ctx context.Context, ref string) (string, error)
	// StateDir holds the inbound replay ledger.
	StateDir string
	Now      func() time.Time
	Log      func(format string, args ...any)
	// Events is the event log GET /v1/events/stream tails; Poll is how often
	// (default a second).
	Events events.Log
	Poll   time.Duration
}

type server struct {
	o       Options
	signMu  sync.Mutex
	rateMu  sync.Mutex
	window  map[string]*bucket
	replay  *ledger
	nameRe  *regexp.Regexp
	tokenRe *regexp.Regexp

	streamMu sync.Mutex
	streams  int
}

type bucket struct {
	start time.Time
	n     int
}

// RatePerMinute is how many requests one token may make in a minute.
const RatePerMinute = 120

// Handler builds the API.
func Handler(o Options) http.Handler {
	s := &server{o: o, window: map[string]*bucket{}, replay: newLedger(filepath.Join(o.StateDir, "server", "replay.json"), o.Now),
		nameRe: regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`), tokenRe: regexp.MustCompile(`^impr_[A-Za-z0-9_-]{43}$`)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", s.health)
	mux.HandleFunc("GET /v1/companion", s.auth("read", s.cmd("companion", "info")))
	mux.HandleFunc("GET /v1/doctor", s.auth("read", s.cmd("doctor")))
	mux.HandleFunc("GET /v1/profiles", s.auth("read", s.cmd("profile", "list")))
	mux.HandleFunc("GET /v1/profiles/{name}", s.auth("read", s.profileShow))
	mux.HandleFunc("GET /v1/certs", s.auth("read", s.cmd("cert", "list")))
	mux.HandleFunc("GET /v1/openapi.json", s.openapi)
	mux.HandleFunc("GET /v1/events", s.auth("events", s.events))
	mux.HandleFunc("GET /v1/events/stream", s.auth("events", s.stream))
	mux.HandleFunc("POST /v1/verify", s.auth("verify", s.verify))
	mux.HandleFunc("POST /v1/sign", s.auth("sign", s.sign))
	mux.HandleFunc("POST /v1/hooks/{name}", s.inbound)
	return s.common(mux)
}

// common sets a request id, caps the body and keeps responses JSON.
func (s *server) common(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-Id", newID())
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)
		next.ServeHTTP(w, r)
	})
}

func (s *server) logf(format string, args ...any) {
	if s.o.Log != nil {
		s.o.Log(format, args...)
	}
}

// ---- responses -----------------------------------------------------------------

// status maps a contract exit code to HTTP. A skipped run (2) is a 200 whose
// document says ok:false, as the CLI's is.
func status(code int) int {
	switch contract.Code(code) {
	case contract.OK, contract.Skipped:
		return http.StatusOK
	case contract.Usage:
		return http.StatusBadRequest
	case contract.SignFailed, contract.VerifyFailed:
		return http.StatusUnprocessableEntity
	}
	return http.StatusServiceUnavailable
}

func writeDoc(w http.ResponseWriter, httpStatus int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	_, _ = w.Write(bytes.TrimSpace(body))
	_, _ = w.Write([]byte("\n"))
}

func writeErr(w http.ResponseWriter, httpStatus int, code contract.Code, format string, args ...any) {
	b, _ := json.Marshal(contract.DocOf(contract.New(code, format, args...)))
	writeDoc(w, httpStatus, b)
}

func (s *server) run(w http.ResponseWriter, r *http.Request, args ...string) {
	code, out := s.o.Run(r.Context(), append(args, "--json"))
	if !json.Valid(bytes.TrimSpace(out)) {
		writeErr(w, http.StatusInternalServerError, contract.Unavailable, "the command printed no JSON document")
		return
	}
	writeDoc(w, status(code), out)
}

// ---- auth ----------------------------------------------------------------------

// auth requires a bearer token with the scope. Every refusal is the same 401
// body, so a caller does not learn whether a token exists.
func (s *server) auth(scope string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		tok, found := s.token(raw)
		if !ok || !found {
			s.logf("server    refused %s %s: no valid token", r.Method, r.URL.Path)
			writeErr(w, http.StatusUnauthorized, contract.Usage, "a valid API token is required")
			return
		}
		if !slices.Contains(tok.Scopes, scope) {
			writeErr(w, http.StatusForbidden, contract.Usage, "token %s lacks the %s scope", tok.ID, scope)
			return
		}
		if !s.allow(tok.ID) {
			w.Header().Set("Retry-After", "60")
			writeErr(w, http.StatusTooManyRequests, contract.Unavailable, "rate limit: %d requests a minute", RatePerMinute)
			return
		}
		next(w, r)
	}
}

// token finds the configured token whose sha256 equals the presented one's,
// comparing every entry in constant time.
func (s *server) token(raw string) (config.Token, bool) {
	if !s.tokenRe.MatchString(raw) {
		return config.Token{}, false
	}
	sum := sha256.Sum256([]byte(raw))
	got := hex.EncodeToString(sum[:])
	var match config.Token
	found := false
	for _, t := range s.o.Config.Server.Tokens {
		if subtle.ConstantTimeCompare([]byte(t.SHA256), []byte(got)) == 1 {
			match, found = t, true
		}
	}
	return match, found
}

func (s *server) allow(id string) bool {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	now := s.o.Now()
	b := s.window[id]
	if b == nil || now.Sub(b.start) >= time.Minute {
		b = &bucket{start: now}
		s.window[id] = b
	}
	b.n++
	return b.n <= RatePerMinute
}

// ---- handlers ------------------------------------------------------------------

func (s *server) health(w http.ResponseWriter, _ *http.Request) {
	writeDoc(w, http.StatusOK, []byte(fmt.Sprintf(`{"contract":%d,"ok":true}`, contract.Version)))
}

func (s *server) cmd(args ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { s.run(w, r, args...) }
}

func (s *server) profileShow(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !s.nameRe.MatchString(name) {
		writeErr(w, http.StatusBadRequest, contract.Usage, "%q is not a profile name", name)
		return
	}
	s.run(w, r, "profile", "show", name)
}

func (s *server) events(w http.ResponseWriter, r *http.Request) {
	args := []string{"events", "tail"}
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err != nil || n < 1 || n > 1000 {
			writeErr(w, http.StatusBadRequest, contract.Usage, "limit is 1 to 1000")
			return
		}
		args = append(args, "--limit="+v)
	}
	for _, t := range r.URL.Query()["type"] {
		if !typeGlobRe.MatchString(t) {
			writeErr(w, http.StatusBadRequest, contract.Usage, "type is an event type glob")
			return
		}
		args = append(args, "--type="+t)
	}
	s.run(w, r, args...)
}

// VerifyRequest is POST /v1/verify (and an inbound verify action).
type VerifyRequest struct {
	Root     string   `json:"root"`
	Profile  string   `json:"profile"`
	Signed   string   `json:"signed,omitempty"`   // impr-manifest.json, relative to root
	Manifest string   `json:"manifest,omitempty"` // build manifest, relative to root
	Files    []string `json:"files,omitempty"`    // relative to root
	Strict   bool     `json:"strict,omitempty"`
}

// SignRequest is POST /v1/sign.
type SignRequest struct {
	Root      string   `json:"root"`
	Manifest  string   `json:"manifest"`
	Commit    string   `json:"commit"`
	Tree      string   `json:"tree"`
	Profile   string   `json:"profile"`
	Purpose   string   `json:"purpose"`
	Platforms []string `json:"platforms,omitempty"`
	Repo      string   `json:"repo,omitempty"`
	Strict    bool     `json:"strict,omitempty"`
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("one JSON object only")
	}
	return nil
}

// inRoot resolves a configured root and a path under it. The root must be one
// of server.roots (or under one); the path must stay inside the root. The
// command re-checks every artifact path against --root and symlinks.
func (s *server) inRoot(root, rel string) (string, string, error) {
	clean := filepath.Clean(root)
	ok := false
	for _, allowed := range s.o.Config.Server.Roots {
		if r, err := filepath.Rel(filepath.Clean(allowed), clean); err == nil && r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator)) {
			ok = true
		}
	}
	if !filepath.IsAbs(root) || !ok {
		return "", "", fmt.Errorf("root %q is not under a configured server.roots entry", root)
	}
	if rel == "" {
		return clean, "", nil
	}
	// A rooted path ("/etc/x" on Windows is rooted but not absolute) or one
	// naming a volume is refused as firmly as an absolute one.
	if filepath.IsAbs(rel) || filepath.VolumeName(rel) != "" || strings.HasPrefix(filepath.ToSlash(rel), "/") ||
		strings.HasPrefix(filepath.ToSlash(filepath.Clean(rel)), "..") {
		return "", "", fmt.Errorf("%q must be relative to the root and inside it", rel)
	}
	return clean, filepath.Join(clean, filepath.Clean(rel)), nil
}

func (s *server) verifyArgs(q VerifyRequest) ([]string, error) {
	if !s.nameRe.MatchString(q.Profile) {
		return nil, errors.New("profile is required")
	}
	root, _, err := s.inRoot(q.Root, "")
	if err != nil {
		return nil, err
	}
	args := []string{"verify", "--root=" + root, "--profile=" + q.Profile}
	if q.Strict {
		args = append(args, "--strict")
	}
	if q.Signed != "" {
		_, p, err := s.inRoot(q.Root, q.Signed)
		if err != nil {
			return nil, err
		}
		args = append(args, "--signed="+p)
		if q.Manifest != "" {
			_, mp, err := s.inRoot(q.Root, q.Manifest)
			if err != nil {
				return nil, err
			}
			args = append(args, "--manifest="+mp)
		}
	}
	if len(q.Files) > 0 {
		for _, f := range q.Files {
			if _, _, err := s.inRoot(q.Root, f); err != nil {
				return nil, err
			}
		}
		args = append(append(args, "--"), q.Files...)
	}
	return args, nil
}

func (s *server) verify(w http.ResponseWriter, r *http.Request) {
	var q VerifyRequest
	if err := decode(r, &q); err != nil {
		writeErr(w, http.StatusBadRequest, contract.Usage, "the request is not a verify request: %v", err)
		return
	}
	args, err := s.verifyArgs(q)
	if err != nil {
		writeErr(w, http.StatusBadRequest, contract.Usage, "%v", err)
		return
	}
	s.runVerify(w, r, args)
}

// runVerify puts --json before "--", so it is read as an option and never as
// a file name.
func (s *server) runVerify(w http.ResponseWriter, r *http.Request, args []string) {
	if i := slices.Index(args, "--"); i >= 0 {
		args = append(append(append([]string{}, args[:i]...), "--json"), args[i:]...)
		code, out := s.o.Run(r.Context(), args)
		if !json.Valid(bytes.TrimSpace(out)) {
			writeErr(w, http.StatusInternalServerError, contract.Unavailable, "the command printed no JSON document")
			return
		}
		writeDoc(w, status(code), out)
		return
	}
	s.run(w, r, args...)
}

var hexRe = regexp.MustCompile(`^[0-9a-f]{7,64}$`)

func (s *server) sign(w http.ResponseWriter, r *http.Request) {
	if !s.o.Config.Server.AllowSign {
		writeErr(w, http.StatusForbidden, contract.Usage, "signing over the API is off (server.allowSign)")
		return
	}
	var q SignRequest
	if err := decode(r, &q); err != nil {
		writeErr(w, http.StatusBadRequest, contract.Usage, "the request is not a sign request: %v", err)
		return
	}
	root, mp, err := s.inRoot(q.Root, q.Manifest)
	switch {
	case err != nil:
		writeErr(w, http.StatusBadRequest, contract.Usage, "%v", err)
		return
	case q.Manifest == "" || !hexRe.MatchString(q.Commit) || !hexRe.MatchString(q.Tree) || !s.nameRe.MatchString(q.Profile):
		writeErr(w, http.StatusBadRequest, contract.Usage, "manifest, commit, tree and profile are required")
		return
	case q.Purpose != "release" && q.Purpose != "test" && q.Purpose != "internal":
		writeErr(w, http.StatusBadRequest, contract.Usage, "purpose is release, test or internal")
		return
	}
	args := []string{"sign", "--root=" + root, "--manifest=" + mp, "--commit=" + q.Commit, "--tree=" + q.Tree,
		"--profile=" + q.Profile, "--purpose=" + q.Purpose}
	for _, p := range q.Platforms {
		if !regexp.MustCompile(`^[a-z]+$`).MatchString(p) {
			writeErr(w, http.StatusBadRequest, contract.Usage, "%q is not a platform", p)
			return
		}
		args = append(args, "--platforms="+p)
	}
	if q.Repo != "" {
		if strings.ContainsAny(q.Repo, " \t\n") || strings.HasPrefix(q.Repo, "-") {
			writeErr(w, http.StatusBadRequest, contract.Usage, "repo is a repository URL")
			return
		}
		args = append(args, "--repo="+q.Repo)
	}
	if q.Strict {
		args = append(args, "--strict")
	}
	s.signMu.Lock() // one signing run at a time on this host
	defer s.signMu.Unlock()
	s.run(w, r, args...)
}

// ---- inbound webhooks ----------------------------------------------------------

// InboundRequest is the body other apps send to POST /v1/hooks/{name}.
type InboundRequest struct {
	Action string         `json:"action"`
	Verify *VerifyRequest `json:"verify,omitempty"`
}

func (s *server) inbound(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var ep *config.Inbound
	for i := range s.o.Config.Server.Inbound {
		if s.o.Config.Server.Inbound[i].Name == name {
			ep = &s.o.Config.Server.Inbound[i]
		}
	}
	unauthorized := func(reason string) {
		s.logf("server    inbound %s refused: %s", name, reason)
		writeErr(w, http.StatusUnauthorized, contract.Usage, "the delivery does not verify")
	}
	if ep == nil {
		unauthorized("no such endpoint")
		return
	}
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(30 * time.Second))
	body, err := readAll(r)
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, contract.Usage, "the body is too large or unreadable")
		return
	}
	keys, err := s.keys(r.Context(), ep)
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, contract.Unavailable, "the endpoint's secret cannot be read")
		s.logf("server    inbound %s: %v", name, err)
		return
	}
	tol, _ := time.ParseDuration(ep.Tolerance)
	if _, err := verifySig(r.Header, body, keys, s.o.Now(), tol); err != nil {
		unauthorized(err.Error())
		return
	}
	// Claimed only after verification, so a forger cannot burn ids.
	if !s.replay.claim(name+"/"+r.Header.Get("webhook-id"), 2*maxDur(tol, 5*time.Minute)) {
		writeErr(w, http.StatusConflict, contract.Usage, "delivery %s was already processed", r.Header.Get("webhook-id"))
		return
	}
	var q InboundRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&q); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, contract.Usage, "the body is not an impr action: %v", err)
		return
	}
	if !slices.Contains(ep.Allow, q.Action) {
		writeErr(w, http.StatusForbidden, contract.Usage, "action %q is not allowed on endpoint %s", q.Action, name)
		return
	}
	switch q.Action {
	case "verify":
		if q.Verify == nil {
			writeErr(w, http.StatusBadRequest, contract.Usage, "a verify action carries a verify object")
			return
		}
		args, err := s.verifyArgs(*q.Verify)
		if err != nil {
			writeErr(w, http.StatusBadRequest, contract.Usage, "%v", err)
			return
		}
		s.runVerify(w, r, args)
	case "doctor":
		s.run(w, r, "doctor")
	case "cert.list":
		s.run(w, r, "cert", "list")
	case "profile.list":
		s.run(w, r, "profile", "list")
	}
}

func maxDur(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}
