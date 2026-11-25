package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sangehq/imprimatur/src/internal/config"
	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/paths"
)

var configFlags = flagSpec{"json": boolFlag, "strict": boolFlag, "profile": stringFlag, "none": boolFlag}

// ConfigPaths is `impr config path --json`.
type ConfigPaths struct {
	Contract      int            `json:"contract"`
	Layers        []config.Layer `json:"layers"`
	ProfilesDir   string         `json:"profilesDir"`
	ActiveProfile string         `json:"activeProfile,omitempty"`
	State         string         `json:"state"`
}

// ConfigShow is `impr config show --json`.
type ConfigShow struct {
	Contract int `json:"contract"`
	config.Effective
}

func cmdConfig(ctx context.Context, a *App, args []string) (int, error) {
	p, err := parse(args, configFlags)
	if err != nil {
		return 0, err
	}
	sub := "show"
	if len(p.pos) > 0 {
		sub = p.pos[0]
	}
	if sub == "list" { // the PowerShell toolkit's word (ID-16)
		sub = "show"
	}
	d, err := a.dirs()
	if err != nil {
		return 0, contract.Wrap(contract.Unavailable, err, "locate the imprimatur config")
	}
	switch sub {
	case "path", "show", "validate", "get":
		eff, err := a.effective(d)
		if err != nil {
			return 0, contract.Wrap(contract.Usage, err, "the configuration does not load")
		}
		switch sub {
		case "path":
			out := ConfigPaths{Contract: contract.Version, Layers: eff.Layers, ProfilesDir: filepath.Join(d.Config, config.ProfilesDir),
				ActiveProfile: eff.Profile, State: d.State}
			if p.on("json") {
				a.json(out)
				return 0, nil
			}
			for _, l := range out.Layers {
				state := "absent"
				if l.Present {
					state = "present"
				}
				a.say("%-16s %s (%s)", l.Name, l.Path, state)
			}
			a.say("%-16s %s", "profiles", out.ProfilesDir)
			return 0, nil
		case "show":
			if p.on("json") {
				a.json(ConfigShow{Contract: contract.Version, Effective: eff})
				return 0, nil
			}
			b, _ := json.MarshalIndent(eff.Config, "", "  ")
			_, _ = fmt.Fprintln(a.Stdout, string(b))
			return 0, nil
		case "validate":
			if p.on("json") {
				a.json(map[string]any{"contract": contract.Version, "ok": true, "layers": eff.Layers})
			} else {
				a.say("config    ok: %d layer(s), profile %q", len(eff.Layers), eff.Profile)
			}
			return 0, nil
		case "get":
			if len(p.pos) != 2 {
				return 0, contract.New(contract.Usage, "impr config get KEY")
			}
			var m map[string]any
			b, _ := json.Marshal(eff.Config)
			_ = json.Unmarshal(b, &m)
			v, ok := config.Get(m, p.pos[1])
			if !ok {
				return 0, contract.New(contract.Usage, "%s is not set", p.pos[1])
			}
			out, _ := json.Marshal(v)
			_, _ = fmt.Fprintln(a.Stdout, string(out))
			return 0, nil
		}
	case "set", "unset":
		return a.configEdit(ctx, d, sub, p)
	case "profile":
		return a.configProfile(ctx, d, p)
	}
	return 0, contract.New(contract.Usage, "unknown config subcommand %q", sub).
		WithFix("impr config show", "impr config set KEY VALUE", "impr config profile list")
}

// layerPath is the file a set or unset edits: the user config, or a profile.
func layerPath(d paths.Dirs, profile string) (string, error) {
	if profile == "" {
		return filepath.Join(d.Config, config.File), nil
	}
	if !config.ProfileNameOK(profile) {
		return "", contract.New(contract.Usage, "%q is not a configuration profile name", profile)
	}
	return filepath.Join(d.Config, config.ProfilesDir, profile+".json"), nil
}

// configEdit sets or unsets one key in one layer, then reloads the effective
// configuration and puts the file back as it was if the result is invalid or
// touches a locked key.
func (a *App) configEdit(ctx context.Context, d paths.Dirs, sub string, p parsed) (int, error) {
	if (sub == "unset" && len(p.pos) != 2) || (sub == "set" && len(p.pos) < 3) {
		return 0, contract.New(contract.Usage, "impr config set KEY VALUE | unset KEY [--profile NAME]")
	}
	// The value's words are joined, as the PowerShell toolkit did (ID-16):
	// a JSON list split by the shell still arrives whole.
	value := strings.Join(p.pos[min(2, len(p.pos)):], " ")
	// Spaces and one matched pair of quotes around it are trimmed (O-74).
	value = trimValueQuotes(value)
	if sub == "set" && strings.TrimSpace(value) == "" {
		return 0, contract.New(contract.Usage, "config set %s needs a value; to remove the key: impr config unset %s", p.pos[1], p.pos[1])
	}
	key := p.pos[1]
	if key == "locked" || strings.HasPrefix(key, "locked.") {
		return 0, contract.New(contract.Usage, "only the system config may lock keys")
	}
	path, err := layerPath(d, p.str("profile"))
	if err != nil {
		return 0, err
	}
	m, existed, err := config.ReadLayer(path)
	if err != nil {
		return 0, contract.Wrap(contract.Usage, err, "cannot read %s", path)
	}
	if p.str("profile") != "" && !existed {
		return 0, contract.New(contract.Usage, "configuration profile %s does not exist", p.str("profile")).
			WithFix("impr config profile create " + p.str("profile"))
	}
	if m == nil {
		m = map[string]any{"schema": config.Schema}
	}
	before, _ := os.ReadFile(path) //nolint:gosec // G304: the layer being edited
	if sub == "set" {
		var v any
		if err := json.Unmarshal([]byte(value), &v); err != nil {
			v = value // not JSON: a plain string
		}
		if err := config.Set(m, key, v); err != nil {
			return 0, contract.Wrap(contract.Usage, err, "cannot set %s", key)
		}
	} else if !config.Unset(m, key) {
		return 0, contract.New(contract.Usage, "%s is not set in %s", key, path)
	}
	if err := config.WriteLayer(path, m); err != nil {
		return 0, err
	}
	if _, err := a.effective(d); err != nil {
		if existed {
			_ = os.WriteFile(path, before, 0o600) //nolint:gosec // G703: path is the config dir plus a validated profile name; this restores it
		} else {
			_ = os.Remove(path)
		}
		return 0, contract.Wrap(contract.Usage, err, "not changed: the result would not load")
	}
	a.bus().Emit(ctx, "config.changed", "config", map[string]any{"layer": filepath.Base(path), "key": key, "action": sub})
	a.say("config    %s %s in %s", sub, key, path)
	return 0, nil
}

func (a *App) configProfile(ctx context.Context, d paths.Dirs, p parsed) (int, error) {
	if len(p.pos) < 2 {
		return 0, contract.New(contract.Usage, "impr config profile list|create|use|rm")
	}
	dir := filepath.Join(d.Config, config.ProfilesDir)
	userPath := filepath.Join(d.Config, config.File)
	switch p.pos[1] {
	case "list":
		m, _ := filepath.Glob(filepath.Join(dir, "*.json"))
		names := []string{}
		for _, f := range m {
			names = append(names, strings.TrimSuffix(filepath.Base(f), ".json"))
		}
		sort.Strings(names)
		active := ""
		if eff, err := a.effective(d); err == nil {
			active = eff.Profile
		}
		if p.on("json") {
			a.json(map[string]any{"contract": contract.Version, "profiles": names, "active": active})
			return 0, nil
		}
		for _, n := range names {
			mark := ""
			if n == active {
				mark = " (active)"
			}
			a.say("%s%s", n, mark)
		}
		return 0, nil
	case "create":
		if len(p.pos) != 3 || !config.ProfileNameOK(p.pos[2]) {
			return 0, contract.New(contract.Usage, "impr config profile create NAME (lower-case letters, digits, - and _)")
		}
		path := filepath.Join(dir, p.pos[2]+".json")
		if _, err := os.Stat(path); err == nil {
			return 0, contract.New(contract.Usage, "configuration profile %s exists", p.pos[2])
		}
		if err := config.WriteLayer(path, map[string]any{}); err != nil {
			return 0, err
		}
		a.say("config    created %s; add keys with impr config set KEY VALUE --profile %s", path, p.pos[2])
		return 0, nil
	case "use":
		m, _, err := config.ReadLayer(userPath)
		if err != nil {
			return 0, err
		}
		if m == nil {
			m = map[string]any{"schema": config.Schema}
		}
		if p.on("none") {
			config.Unset(m, "activeProfile")
		} else {
			if len(p.pos) != 3 {
				return 0, contract.New(contract.Usage, "impr config profile use NAME | use --none")
			}
			m["activeProfile"] = p.pos[2]
		}
		before, _ := os.ReadFile(userPath) //nolint:gosec // G304: the user config
		if err := config.WriteLayer(userPath, m); err != nil {
			return 0, err
		}
		if _, err := a.effective(d); err != nil {
			_ = os.WriteFile(userPath, before, 0o600) //nolint:gosec // G703: the user config path; this restores it
			return 0, contract.Wrap(contract.Usage, err, "not changed")
		}
		a.bus().Emit(ctx, "config.changed", "config", map[string]any{"layer": config.File, "key": "activeProfile", "action": "use"})
		a.say("config    active profile: %v", m["activeProfile"])
		return 0, nil
	case "rm":
		if len(p.pos) != 3 || !config.ProfileNameOK(p.pos[2]) {
			return 0, contract.New(contract.Usage, "impr config profile rm NAME")
		}
		if eff, err := a.effective(d); err == nil && eff.Profile == p.pos[2] {
			return 0, contract.New(contract.Usage, "configuration profile %s is active; impr config profile use --none first", p.pos[2])
		}
		if err := os.Remove(filepath.Join(dir, p.pos[2]+".json")); err != nil {
			return 0, contract.Wrap(contract.Usage, err, "cannot remove configuration profile %s", p.pos[2])
		}
		a.say("config    removed configuration profile %s", p.pos[2])
		return 0, nil
	}
	return 0, contract.New(contract.Usage, "unknown config profile subcommand %q", p.pos[1])
}

// trimValueQuotes trims the spaces around a config value, then one matched
// pair of quotes (both " or both '), so a value quoted once by the shell and
// once by hand is stored bare. The PowerShell toolkit trimmed every quote
// character at either end (impr.ps1:474, .Trim('"', "'")); impr keeps
// quotes inside the pair and a quote with no partner, which are part of the
// value (Phase 6c review, 2026-11-25).
func trimValueQuotes(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1]
	}
	return v
}
