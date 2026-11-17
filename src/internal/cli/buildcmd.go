package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	gobuild "github.com/sangehq/imprimatur/src/internal/build"
	"github.com/sangehq/imprimatur/src/internal/contract"
)

var buildFlags = flagSpec{"json": boolFlag, "strict": boolFlag, "repo-root": stringFlag, "module": stringFlag, "main": stringFlag,
	"binary": stringFlag, "version": stringFlag, "version-var": stringFlag, "targets": listFlag, "clean": boolFlag,
	"allow-dirty": boolFlag, "profile": stringFlag, "purpose": stringFlag, "repo": stringFlag, "platforms": listFlag,
	"product": stringFlag, "company": stringFlag, "description": stringFlag, "copyright": stringFlag, "icon": stringFlag, "no-winres": boolFlag}

// BuildResult is `impr build --json`.
type BuildResult struct {
	Contract     int              `json:"contract"`
	ManifestPath string           `json:"manifestPath"`
	Manifest     gobuild.Manifest `json:"manifest"`
}

// ReleaseResult is `impr release --json`: one document holding each step's
// own result. Step names the step that failed.
type ReleaseResult struct {
	Contract int             `json:"contract"`
	OK       bool            `json:"ok"`
	Step     string          `json:"step,omitempty"`
	Build    BuildResult     `json:"build"`
	Sign     json.RawMessage `json:"sign,omitempty"`
	Verify   json.RawMessage `json:"verify,omitempty"`
}

// buildOptions turns flags into build options, with the estate defaults:
// the module in src/ when it has a go.mod, the only command under cmd/,
// targets from build/targets.txt, else this host.
func (a *App) buildOptions(p parsed) (gobuild.Options, error) {
	root, err := filepath.Abs(orDefault(p.str("repo-root"), "."))
	if err != nil {
		return gobuild.Options{}, err
	}
	mod := p.str("module")
	if mod == "" {
		mod = "."
		if _, err := os.Stat(filepath.Join(root, "src", "go.mod")); err == nil {
			mod = "src"
		}
	}
	if !filepath.IsAbs(mod) {
		mod = filepath.Join(root, mod)
	}
	main := p.str("main")
	if main == "" {
		cmds, _ := filepath.Glob(filepath.Join(mod, "cmd", "*", "main.go"))
		if len(cmds) != 1 {
			return gobuild.Options{}, contract.New(contract.Usage, "--main is required: found %d commands under %s/cmd", len(cmds), mod)
		}
		main = "./cmd/" + filepath.Base(filepath.Dir(cmds[0]))
	}
	var targets []gobuild.Target
	for _, s := range p.list("targets") {
		t, err := gobuild.ParseTarget(s)
		if err != nil {
			return gobuild.Options{}, contract.Wrap(contract.Usage, err, "--targets")
		}
		targets = append(targets, t)
	}
	if len(targets) == 0 {
		if ts, err := gobuild.ReadTargets(filepath.Join(root, "build", "targets.txt")); err == nil {
			targets = ts
		} else {
			targets = []gobuild.Target{{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}}
		}
	}
	var wr *gobuild.WinRes
	if !p.on("no-winres") {
		wr = &gobuild.WinRes{Product: p.str("product"), Company: p.str("company"), Description: p.str("description"),
			Copyright: p.str("copyright"), Icon: p.str("icon")}
	}
	version, err := versionArg(p)
	if err != nil {
		return gobuild.Options{}, err
	}
	return gobuild.Options{RepoRoot: root, ModuleDir: mod, Main: main, Binary: p.str("binary"), Version: version,
		VersionVar: p.str("version-var"), Targets: targets, Clean: p.on("clean"), AllowDirty: p.on("allow-dirty"), WinRes: wr}, nil
}

// versionArg is the version from --version or the one positional VERSION
// (O-14, O-22): both may be given only when they agree.
func versionArg(p parsed) (string, error) {
	v := p.str("version")
	switch {
	case len(p.pos) > 1:
		return "", contract.New(contract.Usage, "one VERSION at most (got %s)", strings.Join(p.pos, " "))
	case len(p.pos) == 1 && v != "" && v != p.pos[0]:
		return "", contract.New(contract.Usage, "VERSION %s and --version %s disagree", p.pos[0], v)
	case len(p.pos) == 1:
		v = p.pos[0]
	}
	return v, nil
}

// releaseOnly are options impr release reads and impr build refuses: build
// only builds, and signing is release's job.
var releaseOnly = []string{"profile", "purpose", "repo", "platforms"}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

func cmdBuild(ctx context.Context, a *App, args []string) (int, error) {
	p, err := parse(args, buildFlags)
	if err != nil {
		return 0, err
	}
	for _, f := range releaseOnly {
		if p.has(f) {
			return 0, contract.New(contract.Usage, "impr build only builds; --%s is for impr release", f).
				WithFix("impr release --profile NAME --purpose P [build options]")
		}
	}
	o, err := a.buildOptions(p)
	if err != nil {
		return 0, err
	}
	path, m, err := gobuild.Builder{Runner: a.Runner, Log: a.say}.Build(ctx, o)
	if err != nil {
		return 0, err
	}
	if p.on("json") {
		a.json(BuildResult{Contract: contract.Version, ManifestPath: path, Manifest: m})
	} else {
		a.say("build     %d file(s), manifest %s (commit %s)", len(m.Artifacts), path, m.Commit[:12])
	}
	return 0, nil
}

// cmdRelease builds, signs the build manifest with a profile and verifies the
// result, through the same commands the CLI runs. It never tags, pushes or
// publishes: what to do with the signed files is the caller's.
func cmdRelease(ctx context.Context, a *App, args []string) (int, error) {
	p, err := parse(args, buildFlags)
	if err != nil {
		return 0, err
	}
	if p.str("profile") == "" || p.str("purpose") == "" {
		return 0, contract.New(contract.Usage, "impr release needs --profile and --purpose")
	}
	if p.on("allow-dirty") {
		return 0, contract.New(contract.Usage, "a release is never built from uncommitted changes")
	}
	o, err := a.buildOptions(p)
	if err != nil {
		return 0, err
	}
	b := gobuild.Builder{Runner: a.Runner, Log: a.say}
	path, m, err := b.Build(ctx, o)
	if err != nil {
		return 0, err
	}
	repo := p.str("repo")
	if repo == "" {
		repo = b.Remote(ctx, o.RepoRoot)
	}
	sign := []string{"sign", "--manifest", path, "--commit", m.Commit, "--tree", m.Tree, "--profile", p.str("profile"),
		"--purpose", p.str("purpose"), "--root", o.RepoRoot, "--strict"}
	if repo != "" {
		sign = append(sign, "--repo", repo)
	}
	for _, pl := range p.list("platforms") {
		sign = append(sign, "--platforms", pl)
	}
	verify := []string{"verify", "--signed", filepath.Join(filepath.Dir(path), "impr-manifest.json"), "--manifest", path,
		"--profile", p.str("profile"), "--root", o.RepoRoot, "--strict"}
	if !p.on("json") {
		if code := a.Run(ctx, sign); code != 0 {
			return code, nil
		}
		code := a.Run(ctx, verify)
		if code == 0 {
			a.say("release   built, signed and verified %d file(s); nothing was tagged, pushed or published", len(m.Artifacts))
		}
		return code, nil
	}
	// One document on stdout (O-150): each step writes its own into a
	// buffer, and the release result carries them.
	r := ReleaseResult{Contract: contract.Version, Build: BuildResult{Contract: contract.Version, ManifestPath: path, Manifest: m}}
	step := func(name string, args []string) int {
		var out bytes.Buffer
		sub := *a
		sub.Stdout = &out
		code := sub.Run(ctx, append(args, "--json"))
		doc := json.RawMessage(bytes.TrimSpace(out.Bytes()))
		if !json.Valid(doc) {
			doc = nil
		}
		if name == "sign" {
			r.Sign = doc
		} else {
			r.Verify = doc
		}
		if code != 0 {
			r.Step = name
		}
		return code
	}
	code := step("sign", sign)
	if code == 0 {
		code = step("verify", verify)
	}
	r.OK = code == 0
	a.json(r)
	if r.OK {
		a.say("release   built, signed and verified %d file(s); nothing was tagged, pushed or published", len(m.Artifacts))
	}
	return code, nil
}
