package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/execx"
	"github.com/sangehq/imprimatur/src/internal/rules"
	"github.com/sangehq/imprimatur/src/internal/signing"
)

// CompanionInfo is `impr companion info --json`.
type CompanionInfo struct {
	Contract     int             `json:"contract"`
	Version      string          `json:"version"`
	Commands     []string        `json:"commands"`
	Capabilities map[string]bool `json:"capabilities"`
	// CapabilityList is the true capabilities as a list, rules included.
	CapabilityList []string        `json:"capabilityList"`
	Backends       map[string]bool `json:"backends"`
	Host           string          `json:"host"`
	ExitCodes      map[string]int  `json:"exitCodes"`
	Tools          []string        `json:"tools"`
}

// StrictReadsCapability tells a caller that the read commands (companion
// info, profile list and show, cert list) accept --strict. They have no
// partial or skipped answer, so --strict changes nothing: every problem is
// already an error. It is accepted so a caller can pass --strict to every
// call without first learning which ones take it.
const StrictReadsCapability = "strictReads"

// EventsCapability tells a caller that impr records CloudEvents in its event
// log (`impr events tail|verify|types`). Events never appear on stdout, so the
// --json documents are unchanged.
const EventsCapability = "events"

// HooksCapability tells a caller that impr runs the host owner's pinned
// pre-sign, pre-verify and event hooks from config.json (impr hooks list).
const HooksCapability = "hooks"

// WebhooksCapability tells a caller that impr can send its events to other
// apps as signed Standard Webhooks deliveries (impr webhooks list).
const WebhooksCapability = "webhooks"

// ServerCapability tells a caller that `impr serve` exposes these commands
// as a REST API, with signed inbound webhooks.
const ServerCapability = "server"

// MultiSignerCapability tells a caller that a profile's Windows spec may list
// several certificates (signers), one chosen per file. Such a profile's
// identity pins every signer, and its records name the signer (signerId).
const MultiSignerCapability = "multiSigner"

// ConfigProfilesCapability tells a caller that config.json is layered
// (system < user < configuration profile) and `impr config` reads and edits it.
const ConfigProfilesCapability = "configProfiles"

// readFlags are the flags of the read commands.
var readFlags = flagSpec{"json": boolFlag, "strict": boolFlag}

func (a *App) companionInfo() CompanionInfo {
	platforms, backends := signing.HostCapabilities(a.host())
	caps := map[string]bool{"rules": true, StrictReadsCapability: true, EventsCapability: true, HooksCapability: true, WebhooksCapability: true, ServerCapability: true, MultiSignerCapability: true, ConfigProfilesCapability: true}
	list := []string{}
	for k, v := range platforms {
		caps[k] = v
	}
	for _, k := range []string{"windows", "macos", "checksums", "containers", "attestations", "rules"} {
		if caps[k] {
			list = append(list, k)
		}
	}
	return CompanionInfo{Contract: contract.Version, Version: version, Commands: ContractCommands, Capabilities: caps,
		CapabilityList: list, Backends: backends, Host: signing.HostName(a.GOOS), ExitCodes: contract.ExitCodes(), Tools: execx.Names()}
}

func cmdCompanion(_ context.Context, a *App, args []string) (int, error) {
	p, err := parse(args, readFlags)
	if err != nil {
		return 0, err
	}
	if len(p.pos) == 0 || p.pos[0] != "info" || len(p.pos) > 1 {
		return 0, contract.New(contract.Usage, "impr companion info is the only companion command").WithFix("impr companion info --json")
	}
	info := a.companionInfo()
	if p.on("json") {
		a.json(info)
		return 0, nil
	}
	a.say("contract  %d", info.Contract)
	a.say("version   %s", info.Version)
	for _, k := range []string{"windows", "macos", "checksums", "containers", "attestations", "rules"} {
		state := "not on this host"
		if info.Capabilities[k] {
			state = "available"
		}
		a.say("%-13s %s", k, state)
	}
	return 0, nil
}

// DoctorReport is `impr doctor --json`.
type DoctorReport struct {
	Contract       int                         `json:"contract"`
	Version        string                      `json:"version"`
	Config         string                      `json:"config"`
	State          string                      `json:"state"`
	Capabilities   map[string]bool             `json:"capabilities"`
	DefaultProfile string                      `json:"defaultProfile"`
	Profiles       []signing.ProfileCapability `json:"profiles"`
	// Tools is every allow-listed tool with its path, sha256 and pin.
	Tools    []ToolRow `json:"tools"`
	Problems []string  `json:"problems"`
	OK       bool      `json:"ok"`
}

func cmdDoctor(ctx context.Context, a *App, args []string) (int, error) {
	p, err := parse(args, flagSpec{"json": boolFlag})
	if err != nil {
		return 0, err
	}
	if err := needNoArgs(p, "impr doctor"); err != nil {
		return 0, err
	}
	d, err := a.dirs()
	if err != nil {
		return 0, contract.Wrap(contract.Unavailable, err, "locate the imprimatur config")
	}
	svc, err := a.service()
	if err != nil {
		return 0, err
	}
	caps, err := svc.Capabilities(ctx, "")
	if err != nil {
		return 0, err
	}
	idx, _, err := svc.Store.LoadIndex()
	if err != nil {
		return 0, err
	}
	rep := DoctorReport{Contract: contract.Version, Version: version, Config: d.Config, State: d.State,
		Capabilities: a.companionInfo().Capabilities, DefaultProfile: idx.Default, Profiles: caps.Profiles, Problems: []string{}}
	for _, pc := range caps.Profiles {
		for _, x := range pc.Problems {
			rep.Problems = append(rep.Problems, "profile "+pc.Name+": "+x)
		}
	}
	if idx.Default == "" {
		rep.Problems = append(rep.Problems, "no default signing profile (impr profile default <name>)")
	}
	rep.Tools = a.toolRows()
	for _, t := range rep.Tools {
		if t.Problem != "" {
			rep.Problems = append(rep.Problems, "tool "+t.Name+": "+t.Problem)
		}
	}
	rep.Problems = append(rep.Problems, a.permissionProblems(d)...)
	rep.Problems = append(rep.Problems, a.legacyAgentProblems()...)
	rep.OK = len(rep.Problems) == 0
	if p.on("json") {
		a.json(rep)
	} else {
		a.say("config    %s", rep.Config)
		a.say("default   %s", orNone(rep.DefaultProfile))
		for _, pc := range rep.Profiles {
			a.say("profile   %s: ready for %s", pc.Name, orNone(strings.Join(pc.Ready, ", ")))
		}
		for _, t := range rep.Tools {
			if t.Path != "" {
				pin := "unpinned"
				if t.Pinned {
					pin = "pinned"
				}
				a.say("tool      %-13s %s %s (%s)", t.Name, t.Path, shortSum(t.SHA256), pin)
			}
		}
		for _, x := range rep.Problems {
			a.say("problem   %s", x)
		}
	}
	if !rep.OK {
		// Not ready is "unavailable", never the usage code (O-162).
		return int(contract.Unavailable), nil
	}
	return 0, nil
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func cmdCert(ctx context.Context, a *App, args []string) (int, error) {
	if len(args) > 0 && args[0] == "create" {
		return cmdCertCreate(ctx, a, args[1:])
	}
	if len(args) > 0 && args[0] == "install-check" {
		return cmdCertInstallCheck(ctx, a, args[1:])
	}
	p, err := parse(args, readFlags)
	if err != nil {
		return 0, err
	}
	if len(p.pos) != 1 || p.pos[0] != "list" {
		return 0, contract.New(contract.Usage, "impr cert list | impr cert create").WithFix("impr cert list --json")
	}
	svc, err := a.service()
	if err != nil {
		return 0, err
	}
	list, err := svc.Certificates(ctx)
	if err != nil {
		return 0, err
	}
	a.expiryEvents(ctx, svc.Events, list.Certificates)
	if p.on("json") {
		a.json(list)
		return 0, nil
	}
	for _, c := range list.Certificates {
		exp := "expiry unknown here"
		if c.NotAfter != nil {
			exp = "expires " + c.NotAfter.Format("2006-01-02")
		}
		state := "not found"
		if c.Present {
			state = "present"
		}
		a.say("%-10s %s: %s, %s (%s)", c.Platform, c.Profile, state, exp, c.Source)
	}
	return 0, nil
}

var signFlags = flagSpec{"json": boolFlag, "strict": boolFlag, "manifest": stringFlag, "commit": stringFlag, "tree": stringFlag,
	"profile": stringFlag, "purpose": stringFlag, "platforms": listFlag, "root": stringFlag, "repo": stringFlag, "approval": listFlag}

func cmdSign(ctx context.Context, a *App, args []string) (int, error) {
	p, err := parse(args, signFlags)
	if err != nil {
		return 0, err
	}
	if p.on("help") {
		a.usage()
		return 0, nil
	}
	if len(p.pos) > 0 {
		if p.str("manifest") != "" || p.str("commit") != "" || p.str("tree") != "" {
			return 0, contract.New(contract.Usage, "name files or --manifest, not both; loose files take their commit and tree from git")
		}
		manifest, commit, tree, err := a.looseManifest(ctx, p)
		if err != nil {
			return 0, err
		}
		p.strs["manifest"], p.strs["commit"], p.strs["tree"] = manifest, commit, tree
		p.seen["manifest"], p.seen["commit"], p.seen["tree"] = true, true, true
	}
	if p.str("manifest") == "" {
		return 0, contract.New(contract.Usage, "--manifest is required").WithFix("impr help")
	}
	svc, err := a.service()
	if err != nil {
		return 0, err
	}
	res, err := svc.Sign(ctx, signing.SignOptions{Root: p.str("root"), Manifest: p.str("manifest"), Commit: p.str("commit"), Tree: p.str("tree"),
		Profile: p.str("profile"), Purpose: p.str("purpose"), Platforms: p.list("platforms"), Repo: p.str("repo"), Strict: p.on("strict"),
		Approvals: p.list("approval")})
	if err != nil && contract.CodeOf(err) == contract.Skipped && res.Contract != 0 {
		_, _ = a.Stderr.Write([]byte(contract.Text(err)))
		if p.on("json") {
			a.json(res)
		}
		return int(contract.Skipped), nil
	}
	if err != nil {
		return 0, err
	}
	if p.on("json") {
		a.json(res)
	} else {
		a.say("wrote     %s", res.ManifestPath)
	}
	return 0, nil
}

var verifyFlags = flagSpec{"json": boolFlag, "strict": boolFlag, "manifest": stringFlag, "signed": stringFlag, "profile": stringFlag, "root": stringFlag}

func cmdVerify(ctx context.Context, a *App, args []string) (int, error) {
	p, err := parse(args, verifyFlags)
	if err != nil {
		return 0, err
	}
	if p.on("help") {
		a.usage()
		return 0, nil
	}
	if p.str("signed") != "" && len(p.pos) > 0 {
		return 0, contract.New(contract.Usage, "give either FILE... or --signed, not both")
	}
	svc, err := a.service()
	if err != nil {
		return 0, err
	}
	res, err := svc.Verify(ctx, signing.VerifyOptions{Root: p.str("root"), Manifest: p.str("manifest"), Signed: p.str("signed"),
		Files: p.pos, Profile: p.str("profile"), Strict: p.on("strict")})
	if err != nil && res.Contract != 0 {
		// A failed verification still prints its report.
		_, _ = a.Stderr.Write([]byte(contract.Text(err)))
		if p.on("json") {
			a.json(res)
		}
		return int(contract.CodeOf(err)), nil
	}
	if err != nil {
		return 0, err
	}
	if p.on("json") {
		a.json(res)
	}
	return 0, nil
}

func cmdRules(ctx context.Context, a *App, args []string) (int, error) {
	if len(args) > 0 && args[0] == "test" {
		return cmdRulesTest(ctx, a, args[1:])
	}
	p, err := parse(args, rulesFlags)
	if err != nil {
		return 0, err
	}
	var req rules.Request
	switch {
	case len(p.pos) > 0 && p.str("request") != "":
		return 0, contract.New(contract.Usage, "name signed files or --request, not both")
	case len(p.pos) > 0:
		if req, err = rulesFromFiles(a, p); err != nil {
			return 0, err
		}
	case p.str("request") == "":
		return 0, contract.New(contract.Usage, "--request or signed files are required").
			WithDetails("impr rules renders allow rules for signed files: named on the command line, or listed in a request (sange writes one from a signed manifest).").
			WithFix("impr rules build/windows/tool.exe --base-policy {GUID}", "impr rules --json --strict --request rules-request.json")
	default:
		b, err := os.ReadFile(p.str("request"))
		if err != nil {
			return 0, contract.Wrap(contract.Usage, err, "read the request")
		}
		// Shapes only ever gain fields, so a newer caller's extra fields are ignored.
		if err := json.Unmarshal(b, &req); err != nil {
			return 0, contract.Wrap(contract.Usage, err, "the request is not an allow-rules request")
		}
		// The flag can add the default rules to a request; it never removes them.
		req.Options.IncludeDefaultRules = req.Options.IncludeDefaultRules || p.on("include-default-rules")
	}
	res, err := rules.Render(req, "imprimatur "+version)
	if err != nil {
		return 0, err
	}
	if dir := p.str("out-dir"); dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return 0, err
		}
		for name, body := range map[string]string{"applocker.xml": res.AppLocker, "wdac-supplemental.xml": res.WDAC} {
			if body == "" {
				continue
			}
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil { //nolint:gosec // G306: policies are meant to be deployed
				return 0, err
			}
			a.say("wrote     %s", filepath.Join(dir, name))
		}
	}
	if p.on("json") {
		a.json(res)
	} else if p.str("out-dir") == "" {
		_, _ = a.Stdout.Write([]byte(res.AppLocker + res.WDAC))
	}
	return 0, nil
}
