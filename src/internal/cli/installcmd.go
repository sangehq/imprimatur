package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sangehq/imprimatur/src/internal/contract"
)

var installFlags = flagSpec{"json": boolFlag, "dir": stringFlag, "force": boolFlag}

// binName is impr's file name on this OS.
func (a *App) binName() string {
	if a.GOOS == "windows" {
		return "impr.exe"
	}
	return "impr"
}

// installDir is ~/.local/bin on every OS (Windows included, %USERPROFILE%),
// or --dir.
func (a *App) installDir(p parsed) string {
	if d := p.str("dir"); d != "" {
		return d
	}
	return filepath.Join(a.Home, ".local", "bin")
}

// onPath reports whether dir is on PATH.
func (a *App) onPath(dir string) bool {
	sep := ":"
	if a.GOOS == "windows" {
		sep = ";"
	}
	for _, d := range strings.Split(a.Getenv("PATH"), sep) {
		if d != "" && filepath.Clean(d) == filepath.Clean(dir) {
			return true
		}
	}
	return false
}

// isImpr reports whether a file is an impr binary: Go embeds the module path
// in every binary it builds, so this tells impr from another program of the
// same name, which install will not overwrite and uninstall will not remove.
func isImpr(path string) bool {
	f, err := os.Open(path) //nolint:gosec // G304: the install target the user named
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, 256<<20))
	return err == nil && bytes.Contains(b, []byte("github.com/sangehq/imprimatur/src"))
}

func fileSum(path string) string {
	b, err := os.ReadFile(path) //nolint:gosec // G304: impr's own binary or its install target
	if err != nil {
		return ""
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// cmdInstall copies the running binary into ~/.local/bin. It never edits
// PATH or a shell profile; it says what to add when the folder is not on
// PATH. A different program already at the target is never overwritten.
func cmdInstall(_ context.Context, a *App, args []string) (int, error) {
	p, err := parse(args, installFlags)
	if err != nil {
		return 0, err
	}
	if err := needNoArgs(p, "impr install"); err != nil {
		return 0, err
	}
	self, err := os.Executable()
	if err != nil {
		return 0, contract.Wrap(contract.Unavailable, err, "cannot find the running impr")
	}
	if real, err := filepath.EvalSymlinks(self); err == nil {
		self = real
	}
	dir := a.installDir(p)
	dst := filepath.Join(dir, a.binName())
	if fileSum(dst) != "" && fileSum(dst) == fileSum(self) {
		a.say("install   %s is already this impr", dst)
		return 0, nil
	}
	if _, err := os.Lstat(dst); err == nil && !isImpr(dst) && !p.on("force") {
		return 0, contract.New(contract.Usage, "%s exists and is not impr; nothing was replaced", dst).WithFix("impr install --dir OTHER_DIR", "impr install --force")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // G301: a bin folder on PATH
		return 0, err
	}
	src, err := os.Open(self) //nolint:gosec // G304: the running binary
	if err != nil {
		return 0, err
	}
	defer func() { _ = src.Close() }()
	tmp, err := os.CreateTemp(dir, ".impr-install-*")
	if err != nil {
		return 0, err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := io.Copy(tmp, src); err != nil {
		_ = tmp.Close()
		return 0, err
	}
	if err := tmp.Chmod(0o755); err != nil { //nolint:gosec // G302: an executable
		_ = tmp.Close()
		return 0, err
	}
	if err := tmp.Close(); err != nil {
		return 0, err
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return 0, err
	}
	a.say("install   copied impr to %s", dst)
	if !a.onPath(dir) {
		if a.GOOS == "windows" {
			a.say("install   %s is not on PATH; add it in Settings > Environment variables, or run:", dir)
			// The user PATH alone, read unexpanded and written back as
			// REG_EXPAND_SZ: $env:Path would copy the machine PATH into the
			// user's and fix every %VAR% entry (old security finding 14).
			a.say(`          $p = (Get-Item HKCU:\Environment).GetValue('Path', '', 'DoNotExpandEnvironmentNames'); `+
				`Set-ItemProperty HKCU:\Environment Path ($p.TrimEnd(';') + ';%s') -Type ExpandString`, dir)
			a.say("          then open a new terminal (sign out and in if it does not see it)")
		} else {
			a.say("install   %s is not on PATH; add to your shell profile: export PATH=\"%s:$PATH\"", dir, dir)
		}
	}
	a.say("install   shell completion: impr completion install bash|zsh|fish")
	return 0, nil
}

// cmdUninstall removes an installed impr, and only impr.
func cmdUninstall(_ context.Context, a *App, args []string) (int, error) {
	p, err := parse(args, installFlags)
	if err != nil {
		return 0, err
	}
	if err := needNoArgs(p, "impr uninstall"); err != nil {
		return 0, err
	}
	// impr installs no launch agent, so it removes none; it names any left,
	// under the current label or the one before 2026-11-17, since each runs
	// an impr that may be the one being removed.
	for _, l := range []string{launchdLabel, checkLabel, legacyLaunchdLabel, legacyCheckLabel} {
		if a.hasLaunchAgent(l) {
			a.say("uninstall the launch agent %s is still installed; to remove it: %s", l, removeAgentSteps(l))
		}
	}
	dst := filepath.Join(a.installDir(p), a.binName())
	if _, err := os.Lstat(dst); errors.Is(err, os.ErrNotExist) {
		a.say("uninstall %s is not there", dst)
		return 0, nil
	}
	if !isImpr(dst) {
		return 0, contract.New(contract.Usage, "%s is not impr; it was left in place", dst)
	}
	if err := os.Remove(dst); err != nil {
		return 0, err
	}
	a.say("uninstall removed %s; your config and state are kept (impr path shows them)", dst)
	return 0, nil
}

// PathInfo is `impr path --json`.
type PathInfo struct {
	Contract   int    `json:"contract"`
	Config     string `json:"config"`
	State      string `json:"state"`
	System     string `json:"system,omitempty"`
	InstallDir string `json:"installDir"`
	Installed  bool   `json:"installed"`
	OnPath     bool   `json:"onPath"`
}

func cmdPath(_ context.Context, a *App, args []string) (int, error) {
	p, err := parse(args, installFlags)
	if err != nil {
		return 0, err
	}
	if err := needNoArgs(p, "impr path"); err != nil {
		return 0, err
	}
	d, err := a.dirs()
	if err != nil {
		return 0, contract.Wrap(contract.Unavailable, err, "locate the imprimatur config")
	}
	dir := a.installDir(p)
	_, statErr := os.Stat(filepath.Join(dir, a.binName()))
	info := PathInfo{Contract: contract.Version, Config: d.Config, State: d.State, System: systemDir(a), InstallDir: dir,
		Installed: statErr == nil, OnPath: a.onPath(dir)}
	if p.on("json") {
		a.json(info)
		return 0, nil
	}
	for _, kv := range [][2]string{{"config", info.Config}, {"state", info.State}, {"system", info.System}, {"install", info.InstallDir}} {
		if kv[1] != "" {
			a.say("%-8s %s", kv[0], kv[1])
		}
	}
	if !info.OnPath {
		a.say("PATH     %s is not on PATH", dir)
	}
	return 0, nil
}

// aliases are the PowerShell toolkit's short command names that still have
// a command to run.
var aliases = map[string]string{"s": "sign", "v": "verify", "d": "doctor", "h": "help", "b": "build", "r": "release"}

func resolveAlias(cmd string) string {
	if full, ok := aliases[cmd]; ok && !slices.Contains(commandNames(), cmd) {
		return full
	}
	return cmd
}
