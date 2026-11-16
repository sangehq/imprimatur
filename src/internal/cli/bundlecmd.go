package cli

import (
	"context"
	"os"
	"sort"

	"github.com/sangehq/imprimatur/src/internal/bundle"
	"github.com/sangehq/imprimatur/src/internal/contract"
)

var bundleFlags = flagSpec{"json": boolFlag, "strict": boolFlag, "sig": stringFlag}

// BundleCheck is one managed profile in `impr profile bundle verify --json`.
type BundleCheck struct {
	Profile string `json:"profile"`
	Owner   string `json:"owner"`
	OK      bool   `json:"ok"`
	Problem string `json:"problem,omitempty"`
}

func cmdBundle(ctx context.Context, a *App, args []string) (int, error) {
	p, err := parse(args, bundleFlags)
	if err != nil {
		return 0, err
	}
	if len(p.pos) == 0 {
		return 0, contract.New(contract.Usage, "impr profile bundle install BUNDLE.json | list | verify")
	}
	d, err := a.dirs()
	if err != nil {
		return 0, contract.Wrap(contract.Unavailable, err, "locate the imprimatur config")
	}
	eff, err := a.effective(d)
	if err != nil {
		return 0, contract.Wrap(contract.Usage, err, "the imprimatur config cannot be read")
	}
	trusted := eff.Config.Bundles.TrustedKeys
	s, err := a.store()
	if err != nil {
		return 0, err
	}
	r := a.host().Runner
	switch p.pos[0] {
	case "install":
		if len(p.pos) != 2 {
			return 0, contract.New(contract.Usage, "impr profile bundle install BUNDLE.json [--sig BUNDLE.json.sig]")
		}
		data, err := os.ReadFile(p.pos[1])
		if err != nil {
			return 0, contract.Wrap(contract.Usage, err, "read the bundle")
		}
		sig, err := os.ReadFile(orDefault(p.str("sig"), p.pos[1]+".sig"))
		if err != nil {
			return 0, contract.Wrap(contract.Usage, err, "read the bundle's signature")
		}
		b, names, err := bundle.Install(ctx, r, s, d.Config, data, sig, trusted)
		if err != nil {
			return 0, err
		}
		a.bus().Emit(ctx, "profile.bundle.installed", b.Owner, map[string]any{"owner": b.Owner, "profiles": names})
		if p.on("json") {
			a.json(map[string]any{"contract": contract.Version, "owner": b.Owner, "profiles": names})
		} else {
			a.say("bundle    installed %s: %v (managed)", b.Owner, names)
		}
		return 0, nil
	case "list":
		inst, err := bundle.Installed(d.Config)
		if err != nil {
			return 0, err
		}
		if p.on("json") {
			a.json(map[string]any{"contract": contract.Version, "bundles": inst})
			return 0, nil
		}
		owners := make([]string, 0, len(inst))
		for o := range inst {
			owners = append(owners, o)
		}
		sort.Strings(owners)
		for _, o := range owners {
			a.say("%-20s %v", o, inst[o])
		}
		return 0, nil
	case "verify":
		ps, err := s.List()
		if err != nil {
			return 0, err
		}
		out := []BundleCheck{}
		ok := true
		for _, pr := range ps {
			if !pr.Managed {
				continue
			}
			c := BundleCheck{Profile: pr.Name, Owner: pr.Owner, OK: true}
			if err := bundle.Check(ctx, r, d.Config, pr, trusted); err != nil {
				c.OK, c.Problem, ok = false, err.Error(), false
			}
			out = append(out, c)
		}
		if p.on("json") {
			a.json(map[string]any{"contract": contract.Version, "ok": ok, "profiles": out})
		} else {
			for _, c := range out {
				state := "matches its signed bundle"
				if !c.OK {
					state = "FAIL " + c.Problem
				}
				a.say("%-24s %s", c.Profile, state)
			}
		}
		if !ok {
			return 0, contract.New(contract.VerifyFailed, "a managed profile does not match its signed bundle")
		}
		return 0, nil
	}
	return 0, contract.New(contract.Usage, "unknown bundle subcommand %q", p.pos[0])
}
