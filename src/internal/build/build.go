// Package build is impr's standalone build (design ID-09): it cross-compiles
// a Go module into the estate layout, build/{os}/{binary}_{os}_{arch}, and
// writes a sange.build-manifest/v1 bound to the git commit and tree, which
// impr sign then signs. It runs `go build` itself, never a repository's
// GoReleaser config, so no repository-controlled hook ever runs on a signing
// host (audit IM-02). It never tags, pushes or publishes.
package build

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/execx"
)

// Target is one GOOS/GOARCH (and GOARM for arm).
type Target struct {
	GOOS, GOARCH, GOARM string
}

// OSName is the folder and file token for an OS: macos, never darwin.
func (t Target) OSName() string {
	if t.GOOS == "darwin" {
		return "macos"
	}
	return t.GOOS
}

// ArchName is the file token for the architecture: armv7 for arm with GOARM 7.
func (t Target) ArchName() string {
	if t.GOARCH == "arm" && t.GOARM != "" {
		return "armv" + t.GOARM
	}
	return t.GOARCH
}

var (
	tokenRe   = regexp.MustCompile(`^[a-z0-9]{2,16}$`)
	armRe     = regexp.MustCompile(`^[5-7]$`)
	versionRe = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
	varRe     = regexp.MustCompile(`^[A-Za-z0-9_./-]+\.[A-Za-z_][A-Za-z0-9_]*$`)
	binRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	mainRe    = regexp.MustCompile(`^\./[A-Za-z0-9_./-]+$`)
	hexRe     = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
)

// ParseTarget reads "goos/goarch[/goarm]" or "goos goarch [goarm]".
func ParseTarget(s string) (Target, error) {
	f := strings.FieldsFunc(s, func(r rune) bool { return r == '/' || r == ' ' || r == '\t' })
	if len(f) < 2 || len(f) > 3 {
		return Target{}, fmt.Errorf("%q is not GOOS/GOARCH[/GOARM]", s)
	}
	t := Target{GOOS: f[0], GOARCH: f[1]}
	if len(f) == 3 {
		t.GOARM = f[2]
	}
	if !tokenRe.MatchString(t.GOOS) || !tokenRe.MatchString(t.GOARCH) || (t.GOARM != "" && (t.GOARCH != "arm" || !armRe.MatchString(t.GOARM))) {
		return Target{}, fmt.Errorf("%q is not GOOS/GOARCH[/GOARM]", s)
	}
	return t, nil
}

// ReadTargets reads build/targets.txt: one target per line, # comments.
func ReadTargets(path string) ([]Target, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the repository's own targets file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var out []Target
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		t, err := ParseTarget(line)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, sc.Err()
}

// Options are one build.
type Options struct {
	RepoRoot  string // the git work tree; build/ is written here
	ModuleDir string // holds go.mod (src/ in the estate layout)
	Main      string // the main package, ./cmd/name, relative to ModuleDir
	Binary    string // file name stem; default the main package's base name
	// Version is vX.Y.Z[-pre]. Empty takes a snapshot version: the latest
	// v* tag plus -snapshot, or v0.0.0-snapshot when there is none.
	Version string
	// VersionVar is the -X variable, e.g. github.com/acme/tool/src/internal/cli.version;
	// empty is main.version, the PowerShell build's variable.
	VersionVar string
	Targets    []Target
	Clean      bool // remove this binary's earlier files from build/ first
	AllowDirty bool // build a work tree with uncommitted changes (never for a release)
	// Universal joins the darwin/amd64 and darwin/arm64 builds into a macOS
	// universal binary, listed in the manifest (ID-12; macOS only, lipo).
	Universal bool
	// WinRes is the Windows version information embedded in each Windows
	// binary; nil embeds none.
	WinRes *WinRes
}

// WinRes is what goes into a Windows binary's resources. Empty fields take
// defaults from the build: the product name is the binary name, and the
// versions come from Version.
type WinRes struct {
	Product, Company, Description, Copyright string
	Icon                                     string // a .ico file
}

// Artifact is one entry of the build manifest.
type Artifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Manifest is sange.build-manifest/v1.
type Manifest struct {
	Schema    string     `json:"schema"`
	Commit    string     `json:"commit"`
	Tree      string     `json:"tree"`
	Version   string     `json:"version"`
	Dirty     bool       `json:"dirty,omitempty"`
	Artifacts []Artifact `json:"artifacts"`
}

// ManifestFile is the build manifest's name under build/.
const ManifestFile = "build-manifest.json"

// Builder runs builds.
type Builder struct {
	Runner execx.Runner
	Log    func(format string, args ...any)
}

func (b Builder) logf(format string, args ...any) {
	if b.Log != nil {
		b.Log(format, args...)
	}
}

func (b Builder) git(ctx context.Context, dir string, args ...string) (string, error) {
	r, err := b.Runner.Run(ctx, execx.Cmd{Tool: "git", Args: args, Dir: dir})
	if err != nil {
		return "", contract.Wrap(contract.Unavailable, err, "git could not run")
	}
	if r.ExitCode != 0 {
		return "", contract.New(contract.Usage, "git %s failed", strings.Join(args, " ")).WithDetails(strings.TrimSpace(r.Output()))
	}
	return strings.TrimSpace(string(r.Stdout)), nil
}

// Commit returns HEAD's commit, its tree, and whether the work tree has
// uncommitted changes to tracked files.
func (b Builder) Commit(ctx context.Context, repo string) (commit, tree string, dirty bool, err error) {
	if commit, err = b.git(ctx, repo, "rev-parse", "HEAD"); err != nil {
		return
	}
	if tree, err = b.git(ctx, repo, "rev-parse", "HEAD^{tree}"); err != nil {
		return
	}
	if !hexRe.MatchString(commit) || !hexRe.MatchString(tree) {
		return "", "", false, contract.New(contract.Usage, "git did not give a commit and tree")
	}
	st, err := b.git(ctx, repo, "-c", "core.fsmonitor=false", "status", "--porcelain", "--untracked-files=no")
	return commit, tree, st != "", err
}

// DefaultVersionVar is the variable a version is stamped into when no
// --version-var is given.
const DefaultVersionVar = "main.version"

// SnapshotVersion is the version of a build given none: the latest v* tag
// with -snapshot added, or v0.0.0-snapshot when there is no such tag. The
// estate's src/v* module tags never match.
func (b Builder) SnapshotVersion(ctx context.Context, repo string) string {
	r, err := b.Runner.Run(ctx, execx.Cmd{Tool: "git", Dir: repo, Args: []string{"describe", "--tags", "--abbrev=0", "--match", "v[0-9]*"}})
	if err == nil && r.ExitCode == 0 {
		if tag := strings.TrimSpace(string(r.Stdout)); versionRe.MatchString(tag + "-snapshot") {
			b.logf("version   %s-snapshot (latest tag %s; pass VERSION for an exact one)", tag, tag)
			return tag + "-snapshot"
		}
	}
	b.logf("version   v0.0.0-snapshot: no v* tag yet; pass VERSION, or tag a commit (git tag v1.2.0)")
	return "v0.0.0-snapshot"
}

// Remote returns the origin remote's URL, or "" without one.
func (b Builder) Remote(ctx context.Context, repo string) string {
	u, err := b.git(ctx, repo, "remote", "get-url", "origin")
	if err != nil {
		return ""
	}
	return u
}

// Build validates everything, then builds every target and writes the
// manifest. Nothing is written until every option is checked.
func (b Builder) Build(ctx context.Context, o Options) (string, Manifest, error) {
	if !mainRe.MatchString(o.Main) || strings.Contains(o.Main, "..") {
		return "", Manifest{}, contract.New(contract.Usage, "--main is a package path inside the module, like ./cmd/tool")
	}
	if o.Binary == "" {
		o.Binary = filepath.Base(o.Main)
	}
	if !binRe.MatchString(o.Binary) {
		return "", Manifest{}, contract.New(contract.Usage, "%q is not a binary name (lower-case letters, digits, _ and -)", o.Binary)
	}
	if o.Version != "" && !versionRe.MatchString(o.Version) {
		// The version goes into -ldflags; anything but a semantic version
		// could add linker flags (the PowerShell build's flag injection).
		return "", Manifest{}, contract.New(contract.Usage, "%q is not a semantic version (v1.2.3, 1.2.3-rc.1)", o.Version)
	}
	if o.VersionVar == "" {
		o.VersionVar = DefaultVersionVar
	}
	if !varRe.MatchString(o.VersionVar) {
		return "", Manifest{}, contract.New(contract.Usage, "--version-var is a package.variable path, like main.version")
	}
	if len(o.Targets) == 0 {
		return "", Manifest{}, contract.New(contract.Usage, "no targets: add build/targets.txt or pass --targets")
	}
	// The same target twice would build one file twice and list one path
	// twice in the manifest, which impr sign refuses; keep the first.
	seenT := map[Target]bool{}
	var uniq []Target
	for _, t := range o.Targets {
		if !seenT[t] {
			seenT[t] = true
			uniq = append(uniq, t)
		}
	}
	o.Targets = uniq
	if _, err := os.Stat(filepath.Join(o.ModuleDir, "go.mod")); err != nil {
		return "", Manifest{}, contract.New(contract.Usage, "%s holds no go.mod", o.ModuleDir).WithFix("--module DIR")
	}
	commit, tree, dirty, err := b.Commit(ctx, o.RepoRoot)
	if err != nil {
		return "", Manifest{}, err
	}
	if dirty && !o.AllowDirty {
		return "", Manifest{}, contract.New(contract.Usage, "the work tree has uncommitted changes, so the binaries would not match commit %s", commit[:12]).
			WithFix("commit or stash them", "impr build --allow-dirty (never for a release)")
	}
	explicit := o.Version != ""
	if !explicit {
		o.Version = b.SnapshotVersion(ctx, o.RepoRoot)
	}
	outRoot := filepath.Join(o.RepoRoot, "build")
	if o.Clean {
		// Only this binary's own earlier files, only inside build/{os}/.
		old, _ := filepath.Glob(filepath.Join(outRoot, "*", o.Binary+"_*"))
		for _, p := range old {
			if st, err := os.Lstat(p); err == nil && st.Mode().IsRegular() {
				_ = os.Remove(p)
			}
		}
	}
	ldflags := "-s -w -X " + o.VersionVar + "=" + o.Version
	warned := false
	built := map[Target]string{}
	m := Manifest{Schema: "sange.build-manifest/v1", Commit: commit, Tree: tree, Version: o.Version, Dirty: dirty, Artifacts: []Artifact{}}
	for _, t := range o.Targets {
		name := o.Binary + "_" + t.OSName() + "_" + t.ArchName()
		if t.GOOS == "windows" {
			name += ".exe"
		}
		dir := filepath.Join(outRoot, t.OSName())
		if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // G301: build output others read
			return "", Manifest{}, err
		}
		out := filepath.Join(dir, name)
		remove, err := b.writeSyso(o, t)
		if err != nil {
			return "", Manifest{}, err
		}
		env := []string{"CGO_ENABLED=0", "GOOS=" + t.GOOS, "GOARCH=" + t.GOARCH, "GOFLAGS=-mod=readonly", "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local"}
		if t.GOARM != "" {
			env = append(env, "GOARM="+t.GOARM)
		}
		r, err := b.Runner.Run(ctx, execx.Cmd{Tool: "go", Dir: o.ModuleDir, Env: env,
			Args: []string{"build", "-trimpath", "-ldflags", ldflags, "-o", out, o.Main}})
		remove()
		if err != nil {
			return "", Manifest{}, contract.Wrap(contract.Unavailable, err, "go could not run")
		}
		if r.ExitCode != 0 {
			return "", Manifest{}, contract.New(contract.Usage, "go build failed for %s/%s", t.GOOS, t.GOARCH).WithDetails(strings.TrimSpace(r.Output()))
		}
		// The linker ignores -X for a variable that does not exist, so a
		// binary can come out unversioned with no error; check the bytes.
		if bin, err := os.ReadFile(out); err == nil && !bytes.Contains(bin, []byte(o.Version)) { //nolint:gosec // G304: a binary this build wrote
			if explicit {
				return "", Manifest{}, contract.New(contract.Usage, "version %s was not stamped into %s: %s has no variable %s",
					o.Version, name, o.Main, o.VersionVar).WithFix("--version-var PKG.VAR naming the program's version variable")
			}
			if !warned {
				b.logf("version   %s was not stamped: %s has no variable %s (pass --version-var)", o.Version, o.Main, o.VersionVar)
				warned = true
			}
		}
		sum, size, err := digest(out)
		if err != nil {
			return "", Manifest{}, err
		}
		rel, _ := filepath.Rel(o.RepoRoot, out)
		m.Artifacts = append(m.Artifacts, Artifact{Path: filepath.ToSlash(rel), SHA256: sum, Size: size})
		b.logf("build     %s", filepath.ToSlash(rel))
		built[t] = out
	}
	if o.Universal {
		out, err := b.universal(ctx, outRoot, o.Binary, built)
		if err != nil {
			return "", Manifest{}, err
		}
		if out != "" {
			sum, size, err := digest(out)
			if err != nil {
				return "", Manifest{}, err
			}
			rel, _ := filepath.Rel(o.RepoRoot, out)
			m.Artifacts = append(m.Artifacts, Artifact{Path: filepath.ToSlash(rel), SHA256: sum, Size: size})
			b.logf("build     %s", filepath.ToSlash(rel))
		}
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", Manifest{}, err
	}
	path := filepath.Join(outRoot, ManifestFile)
	if err := writeAtomic(path, append(data, '\n')); err != nil {
		return "", Manifest{}, err
	}
	return path, m, nil
}

func digest(path string) (string, int64, error) {
	f, err := os.Open(path) //nolint:gosec // G304: a binary this build wrote
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), n, err
}

func writeAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".build-manifest.tmp-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(0o644); err != nil { //nolint:gosec // G302: published with the build
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
