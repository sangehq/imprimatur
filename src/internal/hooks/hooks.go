// Package hooks runs the user's configured hooks (design §5). A hook is a
// program named by absolute path and pinned by sha256 in the user's own
// config; it runs with no shell, the CloudEvent on stdin, a minimal
// environment (never a secret) and a timeout.
//
//   - pre-sign and pre-verify hooks run after every check has passed and
//     before the first signature or verification; with veto, a non-zero exit
//     stops the run, and a hook that cannot run (a failed pin, a timeout)
//     stops it too, because a pre-hook is a gate.
//   - event hooks are an events.Sink: they run for each matching event and
//     their failures are warnings, never a change to the command's result.
package hooks

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/sangehq/imprimatur/src/internal/config"
	"github.com/sangehq/imprimatur/src/internal/events"
	"github.com/sangehq/imprimatur/src/internal/execx"
)

// Runner runs hooks.
type Runner struct {
	Hooks []config.Hook
	Warn  func(format string, args ...any)
	// Run starts a pinned program; nil uses execx.RunPinned. Tests replace it.
	Run func(ctx context.Context, p execx.Pinned) (execx.Result, error)
}

func (r *Runner) run(ctx context.Context, h config.Hook, ev events.Event) (execx.Result, error) {
	body, err := json.Marshal(ev)
	if err != nil {
		return execx.Result{}, err
	}
	d, _ := time.ParseDuration(h.Timeout)
	p := execx.Pinned{Path: h.Exec, SHA256: h.SHA256, Args: h.Args, Stdin: body, Timeout: d,
		Env: []string{"IMPR_HOOK=" + h.Name, "IMPR_HOOK_PHASE=" + h.Phase, "IMPR_EVENT_TYPE=" + ev.Type, "IMPR_EVENT_ID=" + ev.ID}}
	if r.Run != nil {
		return r.Run(ctx, p)
	}
	return execx.RunPinned(ctx, p)
}

// Vetoed is a pre-hook's refusal.
type Vetoed struct {
	Hook   string
	Reason string
}

func (v *Vetoed) Error() string { return fmt.Sprintf("hook %s stopped the run: %s", v.Hook, v.Reason) }

// Pre runs every hook of a pre-* phase, in config order, and returns the
// first refusal. A nil Runner runs nothing.
func (r *Runner) Pre(ctx context.Context, phase string, ev events.Event) error {
	if r == nil {
		return nil
	}
	for _, h := range r.Hooks {
		if h.Phase != phase {
			continue
		}
		res, err := r.run(ctx, h, ev)
		switch {
		case err != nil:
			return &Vetoed{Hook: h.Name, Reason: err.Error()}
		case res.ExitCode != 0 && h.Veto:
			return &Vetoed{Hook: h.Name, Reason: fmt.Sprintf("exit %d: %s", res.ExitCode, firstLine(res.Output()))}
		case res.ExitCode != 0:
			r.warn("hooks     %s exited %d (not a veto hook): %s", h.Name, res.ExitCode, firstLine(res.Output()))
		}
	}
	return nil
}

// Write is the events.Sink for event hooks.
func (r *Runner) Write(ctx context.Context, ev events.Event) error {
	if r == nil {
		return nil
	}
	for _, h := range r.Hooks {
		if h.Phase != config.PhaseEvent || !matches(h.On, ev.Type) {
			continue
		}
		res, err := r.run(ctx, h, ev)
		if err != nil {
			r.warn("hooks     %s could not run: %v", h.Name, err)
		} else if res.ExitCode != 0 {
			r.warn("hooks     %s exited %d: %s", h.Name, res.ExitCode, firstLine(res.Output()))
		}
	}
	return nil
}

func matches(globs []string, typ string) bool {
	if len(globs) == 0 {
		return true
	}
	for _, g := range globs {
		if events.Matches(g, typ) {
			return true
		}
	}
	return false
}

func (r *Runner) warn(format string, args ...any) {
	if r.Warn != nil {
		r.Warn(format, args...)
	}
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return s
}
