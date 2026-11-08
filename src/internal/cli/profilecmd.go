package cli

import (
	"context"
	"encoding/json"
	"os"
	"regexp"
	"strings"

	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/profile"
)

var profileFlags = flagSpec{"json": boolFlag, "force": boolFlag, "scope": stringFlag, "owner": stringFlag, "purpose": listFlag,
	"allowed-repo": listFlag, "requires-approval": boolFlag, "notes": stringFlag, "set": repeatFlag, "unset": repeatFlag,
	"from-file": stringFlag, "out-file": stringFlag, "from": stringFlag}

var profileSubs = []string{"list", "show", "add", "edit", "rm", "import", "export", "validate", "default", "capabilities", "import-legacy"}

// withContract adds "contract": 1 to a profile document, as every contract
// document carries it.
func withContract(p profile.Profile) map[string]any {
	b, _ := json.Marshal(p)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	m["contract"] = contract.Version
	return m
}

// ProfileList is `impr profile list --json`.
type ProfileList struct {
	Contract int               `json:"contract"`
	Default  string            `json:"default,omitempty"`
	Profiles []profile.Profile `json:"profiles"`
}

// ValidateReport is `impr profile validate --json`.
type ValidateReport struct {
	Contract int               `json:"contract"`
	OK       bool              `json:"ok"`
	Profiles []ValidateProfile `json:"profiles"`
}

// ValidateProfile is one profile's problems.
type ValidateProfile struct {
	Name           string   `json:"name"`
	IdentityDigest string   `json:"identityDigest"`
	Problems       []string `json:"problems"`
}

func cmdProfile(ctx context.Context, a *App, args []string) (int, error) {
	p, err := parse(args, profileFlags)
	if err != nil {
		return 0, err
	}
	sub, arg := "list", ""
	if len(p.pos) > 0 {
		sub = p.pos[0]
	}
	if len(p.pos) > 1 {
		arg = p.pos[1]
	}
	if len(p.pos) > 2 {
		return 0, contract.New(contract.Usage, "impr profile %s takes one name (got %s)", sub, strings.Join(p.pos[1:], " "))
	}
	if sub == "import-legacy" {
		return a.importLegacy(p)
	}
	s, err := a.store()
	if err != nil {
		return 0, err
	}
	switch sub {
	case "list":
		all, err := s.List()
		if err != nil {
			return 0, err
		}
		idx, _, err := s.LoadIndex()
		if err != nil {
			return 0, err
		}
		if p.on("json") {
			a.json(ProfileList{Contract: contract.Version, Default: idx.Default, Profiles: all})
			return 0, nil
		}
		if len(all) == 0 {
			a.say("profiles  none yet: impr profile add NAME --scope personal --owner <you> --purpose test ...")
		}
		for _, x := range all {
			mark := ""
			if x.Name == idx.Default {
				mark = " (default)"
			}
			a.say("%-20s %s %s, %v, %s%s", x.Name, x.Scope, x.Owner, x.Purpose, strings.Join(x.Platforms.Names(), " "), mark)
		}
		return 0, nil
	case "show":
		if arg == "" {
			return 0, contract.New(contract.Usage, "which profile?").WithFix("impr profile show NAME")
		}
		x, err := s.Resolve(arg)
		if err != nil {
			return 0, err
		}
		if p.on("json") {
			a.json(withContract(x))
			return 0, nil
		}
		b, _ := json.MarshalIndent(x, "", "  ")
		_, _ = a.Stdout.Write(append(b, '\n'))
		a.say("identity  %s", x.Pinned().Digest())
		return 0, nil
	case "add":
		if arg == "" {
			return 0, contract.New(contract.Usage, "name the new profile").WithFix("impr profile add NAME --scope personal --owner <you> --purpose test ...")
		}
		x := profile.Profile{}
		if f := p.str("from-file"); f != "" {
			b, err := os.ReadFile(f) //nolint:gosec // G304: the profile file the user named
			if err != nil {
				return 0, contract.Wrap(contract.Usage, err, "read %s", f)
			}
			if x, _, err = profile.Decode(b); err != nil {
				return 0, contract.Wrap(contract.Usage, err, "%s is not a profile", f)
			}
			if x.Name != "" && x.Name != arg {
				return 0, contract.New(contract.Usage, "the file names profile %s, not %s", x.Name, arg)
			}
		}
		x.Name = arg
		if x, err = applyOptions(x, p); err != nil {
			return 0, err
		}
		if err := s.Save(x, p.on("force")); err != nil {
			return 0, err
		}
		a.say("saved     %s", arg)
		idx, _, err := s.LoadIndex()
		if err != nil {
			return 0, err
		}
		if idx.Default == "" {
			idx.Default = arg
			if err := s.SaveIndex(idx); err != nil {
				return 0, err
			}
			a.say("default   %s", arg)
		}
		return 0, nil
	case "edit":
		x, err := s.Resolve(arg)
		if err != nil {
			return 0, err
		}
		if x.Managed {
			return 0, profile.ErrManaged(x.Name, "edited")
		}
		if x, err = applyOptions(x, p); err != nil {
			return 0, err
		}
		if err := s.Save(x, true); err != nil {
			return 0, err
		}
		a.say("saved     %s", x.Name)
		return 0, nil
	case "rm":
		if arg == "" {
			return 0, contract.New(contract.Usage, "which profile?").WithFix("impr profile rm NAME")
		}
		idx, _, err := s.LoadIndex()
		if err != nil {
			return 0, err
		}
		if arg == idx.Default && !p.on("force") {
			return 0, contract.New(contract.Usage, "%s is the default profile", arg).WithFix("impr profile default OTHER first", "or: impr profile rm "+arg+" --force")
		}
		if err := s.Remove(arg); err != nil {
			return 0, err
		}
		if arg == idx.Default {
			idx.Default = ""
			if err := s.SaveIndex(idx); err != nil {
				return 0, err
			}
		}
		a.say("removed   %s", arg)
		return 0, nil
	case "import":
		if arg == "" {
			return 0, contract.New(contract.Usage, "which file?").WithFix("impr profile import FILE")
		}
		b, err := os.ReadFile(arg)
		if err != nil {
			return 0, contract.Wrap(contract.Usage, err, "profile file not found: %s", arg)
		}
		x, ps, err := profile.Check(b)
		if err != nil {
			return 0, contract.Wrap(contract.Usage, err, "%s is not a profile", arg)
		}
		if len(ps) > 0 {
			return 0, contract.New(contract.Usage, "%s is not a valid profile; nothing was imported", arg).WithDetails(ps.Strings()...)
		}
		if err := s.Save(x, p.on("force")); err != nil {
			return 0, err
		}
		a.say("imported  %s", x.Name)
		return 0, nil
	case "export":
		x, err := s.Resolve(arg)
		if err != nil {
			return 0, err
		}
		b, _ := json.MarshalIndent(x, "", "  ")
		b = append(b, '\n')
		if out := p.str("out-file"); out != "" {
			if err := os.WriteFile(out, b, 0o600); err != nil {
				return 0, err
			}
			a.say("exported  %s", out)
			return 0, nil
		}
		_, _ = a.Stdout.Write(b)
		return 0, nil
	case "validate":
		var names []string
		if arg != "" {
			names = []string{arg}
		} else {
			all, err := s.List()
			if err != nil {
				return 0, err
			}
			for _, x := range all {
				names = append(names, x.Name)
			}
		}
		rep := ValidateReport{Contract: contract.Version, OK: true, Profiles: []ValidateProfile{}}
		for _, n := range names {
			raw, err := s.Raw(n)
			if err != nil {
				if os.IsNotExist(err) {
					return 0, profile.ErrMissing(n)
				}
				return 0, err
			}
			x, ps, err := profile.Check(raw)
			if err != nil {
				return 0, contract.Wrap(contract.Usage, err, "profile %s is not JSON", n)
			}
			vp := ValidateProfile{Name: n, IdentityDigest: x.Pinned().Digest(), Problems: ps.Strings()}
			rep.OK = rep.OK && len(ps) == 0
			rep.Profiles = append(rep.Profiles, vp)
			if !p.on("json") {
				if len(ps) == 0 {
					a.say("%-20s valid", n)
				}
				for _, q := range vp.Problems {
					a.say("%-20s %s", n, q)
				}
			}
		}
		if p.on("json") {
			a.json(rep)
		}
		if !rep.OK {
			return int(contract.Usage), nil
		}
		return 0, nil
	case "default":
		idx, _, err := s.LoadIndex()
		if err != nil {
			return 0, err
		}
		if arg == "" {
			if p.on("json") {
				a.json(map[string]any{"contract": contract.Version, "default": idx.Default})
			} else {
				_, _ = a.Stdout.Write([]byte(orNone(idx.Default) + "\n"))
			}
			return 0, nil
		}
		if _, err := s.Resolve(arg); err != nil {
			return 0, err
		}
		idx.Default = arg
		if err := s.SaveIndex(idx); err != nil {
			return 0, err
		}
		a.say("default   %s", arg)
		return 0, nil
	case "capabilities":
		svc, err := a.service()
		if err != nil {
			return 0, err
		}
		rep, err := svc.Capabilities(ctx, arg)
		if err != nil {
			return 0, err
		}
		if p.on("json") {
			a.json(rep)
			return 0, nil
		}
		for _, pc := range rep.Profiles {
			for _, pl := range profile.AllPlatforms() {
				c, ok := pc.Platforms[pl]
				if !ok {
					continue
				}
				state := "can sign here"
				if !c.Sign {
					state = "cannot sign here: " + c.Reason
				}
				a.say("%-20s %-12s %s", pc.Name, pl, state)
			}
		}
		return 0, nil
	}
	return 0, contract.New(contract.Usage, "unknown subcommand impr profile %s", sub).WithFix("impr profile " + strings.Join(profileSubs, "|"))
}

func (a *App) importLegacy(p parsed) (int, error) {
	d, err := a.dirs()
	if err != nil {
		return 0, contract.Wrap(contract.Unavailable, err, "locate the imprimatur config")
	}
	s := profile.Store{Dir: d.Config}
	env := a.legacyEnv(d)
	src := p.str("from")
	if src == "" {
		src = profile.FindLegacy(env)
	}
	if src == "" {
		return 0, contract.New(contract.Usage, "no PowerShell imprimatur configuration was found").
			WithFix("impr profile import-legacy --from <toolkit>/config", "or --from <path to imprimatur.settings.json>")
	}
	rep, err := profile.ImportLegacy(s, src, env)
	if err != nil {
		return 0, err
	}
	if p.on("json") {
		a.json(rep)
		return 0, nil
	}
	a.say("source    %s", rep.Source)
	a.say("imported  %s", orNone(strings.Join(rep.Imported, ", ")))
	for _, x := range rep.Skipped {
		a.say("skipped   %s", x)
	}
	for n, ps := range rep.Problems {
		for _, x := range ps {
			a.say("finish    %s: %s", n, x)
		}
	}
	for _, x := range rep.Notes {
		a.say("note      %s", x)
	}
	return 0, nil
}

var setRe = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9.]*)=(.*)$`)

// applyOptions applies the add/edit options to a profile through its JSON
// form, so --set reaches any field and an unknown one is refused.
func applyOptions(x profile.Profile, p parsed) (profile.Profile, error) {
	if p.has("scope") {
		x.Scope = profile.Scope(p.str("scope"))
	}
	if p.has("owner") {
		x.Owner = p.str("owner")
	}
	if p.has("notes") {
		x.Notes = p.str("notes")
	}
	if p.has("purpose") {
		x.Purpose = nil
		for _, v := range p.list("purpose") {
			x.Purpose = append(x.Purpose, profile.Purpose(v))
		}
	}
	if p.has("allowed-repo") {
		x.AllowedRepos = p.list("allowed-repo")
	}
	if p.on("requires-approval") {
		x.RequiresApproval = true
	}
	if !p.has("set") && !p.has("unset") {
		return x, nil
	}
	b, _ := json.Marshal(x)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	for _, kv := range p.list("set") {
		g := setRe.FindStringSubmatch(kv)
		if g == nil {
			return x, contract.New(contract.Usage, "--set takes KEY=VALUE, not %q", kv).WithFix("impr profile edit NAME --set platforms.macos.teamId=ABCDE12345")
		}
		if g[1] == "name" {
			return x, contract.New(contract.Usage, "a profile cannot be renamed with --set; export it, change the name, and import it")
		}
		setPath(m, g[1], valueOf(g[2]))
	}
	for _, k := range p.list("unset") {
		setPath(m, k, nil)
	}
	nb, _ := json.Marshal(m)
	out, ps, err := profile.Decode(nb)
	if err != nil {
		return x, contract.Wrap(contract.Usage, err, "the edited profile does not fit the profile format")
	}
	for _, q := range ps {
		if q.Code == "profile.unknown" || q.Code == "profile.secret" {
			return x, contract.New(contract.Usage, "%s", q.String()).WithFix("impr help profile")
		}
	}
	return out, nil
}

// valueOf reads a value typed on the command line: JSON when it looks like
// JSON, a string otherwise.
func valueOf(t string) any {
	s := strings.TrimSpace(t)
	if s == "true" || s == "false" || s == "null" || strings.HasPrefix(s, "[") || strings.HasPrefix(s, "{") {
		var v any
		if json.Unmarshal([]byte(s), &v) == nil {
			return v
		}
	}
	return t
}

// setPath sets a dotted path, creating objects on the way; nil removes it.
func setPath(m map[string]any, path string, v any) {
	parts := strings.Split(path, ".")
	cur := m
	for _, k := range parts[:len(parts)-1] {
		next, ok := cur[k].(map[string]any)
		if !ok {
			if v == nil {
				return
			}
			next = map[string]any{}
			cur[k] = next
		}
		cur = next
	}
	leaf := parts[len(parts)-1]
	if v == nil {
		delete(cur, leaf)
		return
	}
	cur[leaf] = v
}
