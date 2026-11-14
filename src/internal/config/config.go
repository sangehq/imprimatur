// Package config reads imprimatur's application config, <config>/config.json
// (schema imprimatur.config/v1), as distinct from signing profiles. This first
// version carries the hooks section (design §5); the layering, configuration
// profiles, webhooks and server sections of design §2 extend it additively.
//
// Only the user's own config dir is read. A repository never contributes
// hooks (design ID-06): what runs on a signing host is the host owner's choice.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/sangehq/imprimatur/src/internal/events"
	"github.com/sangehq/imprimatur/src/internal/webhook"
)

// Schema identifies config.json.
const Schema = "imprimatur.config/v1"

// File is config.json's name in the config dir.
const File = "config.json"

// Hook phases.
const (
	PhasePreSign   = "pre-sign"
	PhasePreVerify = "pre-verify"
	PhaseEvent     = "event"
)

// Hook is one configured hook.
type Hook struct {
	Name    string   `json:"name"`
	Phase   string   `json:"phase"`        // pre-sign | pre-verify | event
	On      []string `json:"on,omitempty"` // event type globs (phase event); default every type
	Exec    string   `json:"exec"`         // absolute path
	Args    []string `json:"args,omitempty"`
	SHA256  string   `json:"sha256"`
	Timeout string   `json:"timeout,omitempty"` // Go duration, default 30s, at most 5m
	// Veto makes a non-zero exit of a pre-* hook stop the run.
	Veto bool `json:"veto,omitempty"`
}

// Outbound is one webhook subscription: where impr sends events (design §6.1).
type Outbound struct {
	Name  string   `json:"name"`
	URL   string   `json:"url"`
	Types []string `json:"types,omitempty"` // event type globs; default every internal-class type
	// SecretRef holds the whsec_ signing secret, as a reference (secret://,
	// env://); impr webhooks secret makes one. PreviousSecretRef signs too
	// while a rotation overlaps, so the receiver can switch keys.
	SecretRef         string `json:"secretRef"`
	PreviousSecretRef string `json:"previousSecretRef,omitempty"`
	AllowPrivate      bool   `json:"allowPrivate,omitempty"`
}

// Webhooks is the webhooks section.
type Webhooks struct {
	Outbound []Outbound `json:"outbound,omitempty"`
}

// Inbound is one endpoint other apps call with a signed Standard Webhooks
// delivery (POST /v1/hooks/{name} under impr serve, design §6.2).
type Inbound struct {
	Name              string   `json:"name"`
	SecretRef         string   `json:"secretRef"`
	PreviousSecretRef string   `json:"previousSecretRef,omitempty"`
	Allow             []string `json:"allow"` // actions: verify, doctor, cert.list, profile.list
	Tolerance         string   `json:"tolerance,omitempty"`
}

// Token is one API token, stored only as its sha256.
type Token struct {
	ID     string   `json:"id"`
	SHA256 string   `json:"sha256"`
	Scopes []string `json:"scopes"` // read, verify, sign, events
}

// Server is the impr serve section (design §7).
type Server struct {
	// Listen is "unix" (the default: <state>/server/impr.sock) or a
	// loopback host:port. Other addresses are refused until the owner
	// decides on TLS (design ID-04).
	Listen string `json:"listen,omitempty"`
	// Roots are the only directories verify and sign may read artifacts
	// from. With none, those endpoints refuse.
	Roots []string `json:"roots,omitempty"`
	// AllowSign enables POST /v1/sign (off by default, design ID-05).
	AllowSign bool      `json:"allowSign,omitempty"`
	Tokens    []Token   `json:"tokens,omitempty"`
	Inbound   []Inbound `json:"inbound,omitempty"`
}

// Config is config.json.
type Config struct {
	Schema   string   `json:"schema"`
	Hooks    []Hook   `json:"hooks,omitempty"`
	Webhooks Webhooks `json:"webhooks,omitempty"`
	Server   Server   `json:"server,omitempty"`
}

// Scopes are the API token scopes.
var Scopes = []string{"read", "verify", "sign", "events"}

// InboundActions are what an inbound webhook may ask for. sign is never one:
// a signature needs a bound manifest and an authenticated caller with the sign
// scope (design ID-05).
var InboundActions = []string{"verify", "doctor", "cert.list", "profile.list"}

// Save writes config.json atomically, owner-only, after validating it.
func Save(dir string, c Config) error {
	if c.Schema == "" {
		c.Schema = Schema
	}
	if ps := c.Validate(); len(ps) > 0 {
		return fmt.Errorf("config not saved: %v", ps)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".config.json.tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if _, err := f.Write(append(b, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, File))
}

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Load reads <dir>/config.json. A missing file is an empty config. The file
// must be owner-only on Unix (it decides what runs), and unknown fields are
// refused so a typo cannot silently disable a check.
func Load(dir string) (Config, error) {
	p := filepath.Join(dir, File)
	st, err := os.Stat(p)
	if errors.Is(err, os.ErrNotExist) {
		return Config{Schema: Schema}, nil
	}
	if err != nil {
		return Config{}, err
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o022 != 0 {
		return Config{}, fmt.Errorf("%s is writable by group or others (%v); chmod 600 it", p, st.Mode().Perm())
	}
	b, err := os.ReadFile(p) //nolint:gosec // G304: the user's own config
	if err != nil {
		return Config{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("%s: %w", p, err)
	}
	if problems := c.Validate(); len(problems) > 0 {
		return Config{}, fmt.Errorf("%s: %v", p, problems)
	}
	return c, nil
}

// Validate lists what is wrong.
func (c Config) Validate() []string {
	var ps []string
	if c.Schema != Schema {
		ps = append(ps, fmt.Sprintf("schema must be %q", Schema))
	}
	seen := map[string]bool{}
	for i, h := range c.Hooks {
		at := fmt.Sprintf("hooks[%d]", i)
		if !nameRe.MatchString(h.Name) {
			ps = append(ps, at+": name must be lower-case letters, digits and dashes")
		}
		if seen[h.Name] {
			ps = append(ps, at+": duplicate name "+h.Name)
		}
		seen[h.Name] = true
		switch h.Phase {
		case PhasePreSign, PhasePreVerify, PhaseEvent:
		default:
			ps = append(ps, at+": phase must be pre-sign, pre-verify or event")
		}
		if h.Veto && h.Phase == PhaseEvent {
			ps = append(ps, at+": only a pre-* hook can veto")
		}
		if !filepath.IsAbs(h.Exec) {
			ps = append(ps, at+": exec must be an absolute path")
		}
		if !regexp.MustCompile(`^(sha256:)?[0-9a-fA-F]{64}$`).MatchString(h.SHA256) {
			ps = append(ps, at+": sha256 must pin the program (impr hooks pin "+h.Name+")")
		}
		if h.Timeout != "" {
			if d, err := time.ParseDuration(h.Timeout); err != nil || d <= 0 || d > 5*time.Minute {
				ps = append(ps, at+": timeout must be a duration up to 5m")
			}
		}
		for _, g := range h.On {
			if !events.KnownGlob(g) {
				ps = append(ps, at+": "+g+" matches no event type")
			}
		}
	}
	subs := map[string]bool{}
	for i, w := range c.Webhooks.Outbound {
		at := fmt.Sprintf("webhooks.outbound[%d]", i)
		if !nameRe.MatchString(w.Name) || subs[w.Name] {
			ps = append(ps, at+": name must be unique lower-case letters, digits and dashes")
		}
		subs[w.Name] = true
		if !regexp.MustCompile(`^(secret|env)://.+`).MatchString(w.SecretRef) {
			ps = append(ps, at+": secretRef must be a secret:// or env:// reference (impr webhooks secret makes one)")
		}
		if w.PreviousSecretRef != "" && !regexp.MustCompile(`^(secret|env)://.+`).MatchString(w.PreviousSecretRef) {
			ps = append(ps, at+": previousSecretRef must be a secret:// or env:// reference")
		}
		for _, g := range w.Types {
			if !events.KnownGlob(g) {
				ps = append(ps, at+": "+g+" matches no event type")
			}
		}
		if _, err := webhook.CheckURL(w.URL, w.AllowPrivate); err != nil {
			ps = append(ps, at+": "+err.Error())
		}
	}
	ps = append(ps, c.Server.validate()...)
	return ps
}

func (s Server) validate() []string {
	var ps []string
	if s.Listen != "" && s.Listen != "unix" {
		host, _, err := net.SplitHostPort(s.Listen)
		ip := net.ParseIP(host)
		if err != nil || (host != "localhost" && (ip == nil || !ip.IsLoopback())) {
			ps = append(ps, "server.listen must be \"unix\" or a loopback host:port")
		}
	}
	for i, r := range s.Roots {
		if !filepath.IsAbs(r) {
			ps = append(ps, fmt.Sprintf("server.roots[%d] must be an absolute path", i))
		}
	}
	ids := map[string]bool{}
	for i, t := range s.Tokens {
		at := fmt.Sprintf("server.tokens[%d]", i)
		if !regexp.MustCompile(`^tok_[0-9a-f]{8,32}$`).MatchString(t.ID) || ids[t.ID] {
			ps = append(ps, at+": id must be unique tok_<hex>")
		}
		ids[t.ID] = true
		if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(t.SHA256) {
			ps = append(ps, at+": sha256 must be the token's 64-hex digest (impr server token add makes both)")
		}
		if len(t.Scopes) == 0 {
			ps = append(ps, at+": scopes are required")
		}
		for _, sc := range t.Scopes {
			if !slices.Contains(Scopes, sc) {
				ps = append(ps, at+": unknown scope "+sc)
			}
		}
	}
	names := map[string]bool{}
	for i, in := range s.Inbound {
		at := fmt.Sprintf("server.inbound[%d]", i)
		if !nameRe.MatchString(in.Name) || names[in.Name] {
			ps = append(ps, at+": name must be unique lower-case letters, digits and dashes")
		}
		names[in.Name] = true
		if !regexp.MustCompile(`^(secret|env)://.+`).MatchString(in.SecretRef) {
			ps = append(ps, at+": secretRef must be a secret:// or env:// reference")
		}
		if len(in.Allow) == 0 {
			ps = append(ps, at+": allow must name at least one action")
		}
		for _, a := range in.Allow {
			if !slices.Contains(InboundActions, a) {
				ps = append(ps, at+": action "+a+" is not allowed inbound ("+strings.Join(InboundActions, ", ")+")")
			}
		}
		if in.Tolerance != "" {
			if d, err := time.ParseDuration(in.Tolerance); err != nil || d <= 0 || d > 15*time.Minute {
				ps = append(ps, at+": tolerance must be a duration up to 15m")
			}
		}
	}
	return ps
}
