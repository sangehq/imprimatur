package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sangehq/imprimatur/src/internal/config"
	"github.com/sangehq/imprimatur/src/internal/events"
)

// Anchor is the two chain heads an audit.head event carries off the machine.
type Anchor struct {
	Audit  events.Head `json:"audit"`
	Events events.Head `json:"events"`
}

// anchor reads both chain heads and, when anchoring is on (or force is set),
// emits them as an audit.head event, which outbound webhooks subscribed to
// it deliver off the machine. The events head is the one before the
// audit.head event itself is written.
func (a *App) anchor(ctx context.Context, force bool) (Anchor, error) {
	d, err := a.dirs()
	if err != nil {
		return Anchor{}, err
	}
	cfg := config.Config{}
	if eff, err := a.effective(d); err == nil {
		cfg = eff.Config
	}
	if !force && !cfg.Audit.Anchor.Enabled {
		return Anchor{}, nil
	}
	var h Anchor
	if h.Audit, err = (events.Log{Dir: filepath.Join(d.State, "audit")}).Head(); err != nil {
		return h, err
	}
	if h.Events, err = (events.Log{Dir: filepath.Join(d.State, "events")}).Head(); err != nil {
		return h, err
	}
	a.bus().Emit(ctx, "audit.head", "anchor", h)
	return h, nil
}

// verifyAnchor checks a saved anchor against the local chains: the
// audit.head CloudEvent a receiver stored, or its data alone.
func (a *App) verifyAnchor(state, file string) error {
	b, err := os.ReadFile(file) //nolint:gosec // G304: a file the operator named
	if err != nil {
		return err
	}
	var doc struct {
		Anchor
		Data *Anchor `json:"data"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return fmt.Errorf("%s is not an audit.head event or anchor: %w", file, err)
	}
	h := doc.Anchor
	if doc.Data != nil {
		h = *doc.Data
	}
	if h.Audit.Count == 0 && h.Events.Count == 0 {
		return fmt.Errorf("%s names no chain head", file)
	}
	if h.Audit.Count > 0 {
		if err := (events.Log{Dir: filepath.Join(state, "audit")}).Matches(h.Audit); err != nil {
			return fmt.Errorf("audit trail: %w", err)
		}
	}
	if h.Events.Count > 0 {
		if err := (events.Log{Dir: filepath.Join(state, "events")}).Matches(h.Events); err != nil {
			return fmt.Errorf("event log: %w", err)
		}
	}
	return nil
}

// anchorEvery is how often a running impr serve anchors, when on.
func anchorEvery(c config.Config) time.Duration {
	if c.Audit.Anchor.EveryHours > 0 {
		return time.Duration(c.Audit.Anchor.EveryHours) * time.Hour
	}
	return 6 * time.Hour
}
