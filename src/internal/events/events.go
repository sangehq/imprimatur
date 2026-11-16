// Package events is imprimatur's event model (design ID-01, ID-02): one
// CloudEvents 1.0 envelope in structured JSON, the estate shape of sange's
// webhooks-and-events.md §3.1, typed sh.sange.imprimatur.<context>.<noun>.<verb>.
//
// Events never go to stdout: --json keeps printing exactly one document. They
// go to sinks: the append-only log in the state directory (log.go), and later
// hooks, webhooks and the server's SSE stream, all through Bus.
package events

import (
	"github.com/sangehq/imprimatur/src/internal/redact"

	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// SpecVersion is the CloudEvents version.
const SpecVersion = "1.0"

// TypePrefix starts every imprimatur event type.
const TypePrefix = "sh.sange.imprimatur."

// Data classes (the imprclass extension): who may store the event.
const (
	ClassInternal = "internal" // may leave the machine to a configured receiver
	ClassLocal    = "local"    // stays on this machine
)

// Event is one CloudEvent.
type Event struct {
	SpecVersion     string          `json:"specversion"`
	ID              string          `json:"id"`
	Source          string          `json:"source"`
	Type            string          `json:"type"`
	Subject         string          `json:"subject,omitempty"`
	Time            time.Time       `json:"time"`
	DataContentType string          `json:"datacontenttype"`
	DataSchema      string          `json:"dataschema,omitempty"`
	Class           string          `json:"imprclass"`
	Prev            string          `json:"imprprev,omitempty"` // sha256 of the previous log line (log.go)
	Data            json.RawMessage `json:"data"`
}

// Catalogue is every event type imprimatur emits, with its data class. A type
// not listed here is refused by New, so the list is the single source the
// docs, the schema test and `impr events types` read.
var Catalogue = map[string]string{
	"signing.run.started":        ClassInternal,
	"verification.run.started":   ClassInternal,
	"signing.artifact.signed":    ClassInternal,
	"signing.run.completed":      ClassInternal,
	"signing.run.failed":         ClassInternal,
	"signing.run.skipped":        ClassInternal,
	"verification.run.completed": ClassInternal,
	"verification.run.failed":    ClassInternal,
	"cert.expiring":              ClassInternal,
	"cert.expired":               ClassInternal,
	"profile.created":            ClassInternal,
	"profile.changed":            ClassInternal,
	"profile.removed":            ClassInternal,
	"profile.bundle.installed":   ClassInternal,
	"approval.created":           ClassInternal,
	"audit.head":                 ClassInternal,
	"webhook.test":               ClassInternal,
	"webhook.delivery.dead":      ClassLocal,
	"webhook.secret.rotated":     ClassLocal,
	"server.auth.refused":        ClassLocal,
	"webhook.inbound.received":   ClassLocal,
	"config.changed":             ClassLocal,
	"hook.failed":                ClassLocal,
	"hook.vetoed":                ClassLocal,
	"server.started":             ClassLocal,
	"audit.command.completed":    ClassLocal,
	"server.stopped":             ClassLocal,
}

var typeRe = regexp.MustCompile(`^[a-z0-9-]+(\.[a-z0-9-]+){1,2}$`)

// Source is the CloudEvents source for an install id.
func Source(installID string) string { return "https://sange.sh/imprimatur/install/" + installID }

// SchemaURL is the published JSON Schema for a type at major version 1.
func SchemaURL(short string) string {
	return "https://sange.sh/schemas/imprimatur/events/" + short + "/v1.json"
}

// Env supplies time and ids; tests pass fixed ones.
type Env struct {
	Now       func() time.Time
	NewID     func() string
	InstallID string
}

// NewID is a random 128-bit hex id.
func NewID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return hex.EncodeToString(b)
}

// New builds an event of a catalogued type. data must marshal to a JSON
// object and must not carry secrets: callers pass ids, names and digests only.
func (e Env) New(short, subject string, data any) (Event, error) {
	class, ok := Catalogue[short]
	if !ok || !typeRe.MatchString(short) {
		return Event{}, fmt.Errorf("event type %q is not in the catalogue", short)
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return Event{}, err
	}
	// Events reach the log, hooks, webhooks and the desktop: no secret shape
	// leaves in one. The masks replace text inside JSON strings only, so the
	// document stays valid.
	raw = []byte(redact.String(string(raw)))
	if len(raw) == 0 || raw[0] != '{' {
		return Event{}, fmt.Errorf("event %s: data must be a JSON object", short)
	}
	return Event{SpecVersion: SpecVersion, ID: e.NewID(), Source: Source(e.InstallID), Type: TypePrefix + short,
		Subject: subject, Time: e.Now().UTC(), DataContentType: "application/json", DataSchema: SchemaURL(short),
		Class: class, Data: raw}, nil
}

// Short is the type without the prefix.
func (ev Event) Short() string { return strings.TrimPrefix(ev.Type, TypePrefix) }

// Sink receives events.
type Sink interface {
	Write(ctx context.Context, ev Event) error
}

// Bus fans an event out to its sinks. A sink failure is reported to Warn and
// does not stop the others or the operation that emitted the event.
type Bus struct {
	Env   Env
	Sinks []Sink
	Warn  func(format string, args ...any)
	// Required records the first failure to write the event log, for Err:
	// config events.required, where a run that cannot be logged fails closed.
	Required bool
	mu       sync.Mutex
	err      error
}

// Err is the first event-log write failure when Required is set, else nil.
func (b *Bus) Err() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.err
}

// Emit builds and publishes an event. A nil Bus is a no-op, so code that
// emits does not need to know whether events are configured.
func (b *Bus) Emit(ctx context.Context, short, subject string, data any) {
	if b == nil {
		return
	}
	ev, err := b.Env.New(short, subject, data)
	if err != nil {
		b.warn("events    %v", err)
		return
	}
	b.Publish(ctx, ev)
}

// Publish sends an event that is already built (one a pre-hook has seen) to
// every sink.
func (b *Bus) Publish(ctx context.Context, ev Event) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, s := range b.Sinks {
		if err := s.Write(ctx, ev); err != nil {
			b.warn("events    %s not recorded: %v", ev.Type, err)
			if _, isLog := s.(Log); isLog && b.Required && b.err == nil {
				b.err = fmt.Errorf("%s was not written to the event log: %w", ev.Type, err)
			}
		}
	}
}

func (b *Bus) warn(format string, args ...any) {
	if b.Warn != nil {
		b.Warn(format, args...)
	}
}

// InstallID reads the install id from the state dir, creating it once: 64
// random bits, never the host or user name (they are personal data).
func InstallID(stateDir string) (string, error) {
	p := filepath.Join(stateDir, "install-id")
	if b, err := os.ReadFile(p); err == nil { //nolint:gosec // G304: impr's own state file
		id := strings.TrimSpace(string(b))
		if regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(id) {
			return id, nil
		}
		return "", fmt.Errorf("%s is not an install id; remove it to make a new one", p)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", err
	}
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	id := hex.EncodeToString(b)
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: impr's own state file
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return InstallID(stateDir)
		}
		return "", err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(id + "\n"); err != nil {
		return "", err
	}
	return id, nil
}

// KnownGlob reports whether a type glob matches at least one catalogued type,
// so a misspelt filter is refused instead of silently matching nothing.
func KnownGlob(glob string) bool {
	for short := range Catalogue {
		if Matches(glob, TypePrefix+short) {
			return true
		}
	}
	return false
}
