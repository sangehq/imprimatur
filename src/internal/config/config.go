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
	"os"
	"path/filepath"
	"regexp"
	"runtime"
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

// Config is config.json.
type Config struct {
	Schema   string   `json:"schema"`
	Hooks    []Hook   `json:"hooks,omitempty"`
	Webhooks Webhooks `json:"webhooks,omitempty"`
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
	return ps
}
