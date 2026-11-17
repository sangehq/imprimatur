package cli

import (
	"context"
	"path/filepath"

	"github.com/sangehq/imprimatur/src/internal/config"
	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/execx"
	"github.com/sangehq/imprimatur/src/internal/hooks"
)

var hooksFlags = flagSpec{"json": boolFlag, "strict": boolFlag}

// HookStatus is one hook in `impr hooks list --json`.
type HookStatus struct {
	config.Hook
	PinOK   bool   `json:"pinOk"`
	Problem string `json:"problem,omitempty"`
}

// HooksList is `impr hooks list --json`.
type HooksList struct {
	Contract int          `json:"contract"`
	Config   string       `json:"config"`
	Hooks    []HookStatus `json:"hooks"`
}

func cmdHooks(ctx context.Context, a *App, args []string) (int, error) {
	p, err := parse(args, hooksFlags)
	if err != nil {
		return 0, err
	}
	sub := "list"
	if len(p.pos) > 0 {
		sub = p.pos[0]
	}
	d, err := a.dirs()
	if err != nil {
		return 0, contract.Wrap(contract.Unavailable, err, "locate the imprimatur config")
	}
	cfgPath := filepath.Join(d.Config, config.File)
	switch sub {
	case "pin":
		if len(p.pos) != 2 {
			return 0, contract.New(contract.Usage, "impr hooks pin FILE prints the sha256 to put in config.json")
		}
		abs, err := filepath.Abs(p.pos[1])
		if err != nil {
			return 0, err
		}
		sum, err := execx.CheckPinned(abs, "")
		if sum == "" {
			return 0, contract.Wrap(contract.Usage, err, "cannot pin %s", p.pos[1])
		}
		if p.on("json") {
			a.json(map[string]any{"contract": contract.Version, "exec": abs, "sha256": sum})
		} else {
			_, _ = a.Stdout.Write([]byte(sum + "\n"))
			a.say("hooks     add to %s: {\"exec\": %q, \"sha256\": %q, ...}", cfgPath, abs, sum)
		}
		return 0, nil
	}
	eff, err := a.effective(d)
	cfg := eff.Config
	if err != nil {
		return 0, contract.Wrap(contract.Usage, err, "the imprimatur config cannot be read")
	}
	switch sub {
	case "list":
		out := HooksList{Contract: contract.Version, Config: cfgPath, Hooks: []HookStatus{}}
		for _, h := range cfg.Hooks {
			st := HookStatus{Hook: h, PinOK: true}
			if _, err := execx.CheckPinned(h.Exec, h.SHA256); err != nil {
				st.PinOK, st.Problem = false, err.Error()
			}
			out.Hooks = append(out.Hooks, st)
		}
		if p.on("json") {
			a.json(out)
			return 0, nil
		}
		if len(out.Hooks) == 0 {
			a.say("hooks     none configured in %s", cfgPath)
		}
		for _, h := range out.Hooks {
			state := "pinned"
			if !h.PinOK {
				state = "REFUSED: " + h.Problem
			}
			a.say("%-20s %-11s %s  %s", h.Name, h.Phase, h.Exec, state)
		}
		return 0, nil
	case "test":
		if len(p.pos) != 2 {
			return 0, contract.New(contract.Usage, "impr hooks test NAME runs one hook with a sample event")
		}
		for _, h := range cfg.Hooks {
			if h.Name != p.pos[1] {
				continue
			}
			env := a.eventEnv("0000000000000000")
			ev, err := env.New("verification.run.started", "hooks-test", map[string]any{"test": true})
			if err != nil {
				return 0, err
			}
			r := &hooks.Runner{Hooks: []config.Hook{h}, Warn: a.say}
			if h.Phase == config.PhaseEvent || config.IsPostPhase(h.Phase) {
				h.Phase = config.PhasePreVerify // run it as a gate, so its result is reported
				r.Hooks = []config.Hook{h}
			}
			if err := r.Pre(ctx, h.Phase, ev); err != nil {
				return 0, contract.Wrap(contract.SignFailed, err, "hook %s failed its test", h.Name)
			}
			a.say("hooks     %s ran and passed", h.Name)
			return 0, nil
		}
		return 0, contract.New(contract.Usage, "no hook named %q in %s", p.pos[1], cfgPath)
	}
	return 0, contract.New(contract.Usage, "unknown hooks subcommand %q", sub).WithFix("impr hooks list", "impr hooks pin FILE", "impr hooks test NAME")
}
