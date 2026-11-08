// Package cli is impr's command line: a small flag parser over the standard
// library, the command table, and the contract's output rules (one JSON
// document on stdout with --json, human text on stderr, exit codes 0 to 5).
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/sangehq/imprimatur/src/internal/backend"
	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/execx"
	"github.com/sangehq/imprimatur/src/internal/paths"
	"github.com/sangehq/imprimatur/src/internal/profile"
	"github.com/sangehq/imprimatur/src/internal/secrets"
	"github.com/sangehq/imprimatur/src/internal/signing"
)

// Build metadata, stamped with -ldflags -X.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// Version is the version impr reports.
func Version() string { return version }

// App is one run of impr, with everything it touches from the host.
type App struct {
	Stdout, Stderr io.Writer
	Getenv         func(string) string
	GOOS           string
	Home           string
	User           string
	Runner         execx.Runner
	Now            func() time.Time
}

// Main runs impr with the real host and returns the exit code.
func Main(args []string) int {
	home, _ := os.UserHomeDir()
	name := os.Getenv("USER")
	if name == "" {
		name = os.Getenv("USERNAME")
	}
	if u, err := user.Current(); err == nil && name == "" {
		name = u.Username
	}
	a := &App{Stdout: os.Stdout, Stderr: os.Stderr, Getenv: os.Getenv, GOOS: runtime.GOOS, Home: home, User: name,
		Runner: execx.OS{}, Now: time.Now}
	return a.Run(context.Background(), args)
}

// ---- argument parsing ----------------------------------------------------------

type kind int

const (
	boolFlag kind = iota
	stringFlag
	listFlag   // repeatable, and comma-separated values split
	repeatFlag // repeatable, each value kept whole (it may contain commas)
)

type flagSpec map[string]kind

type parsed struct {
	pos   []string
	bools map[string]bool
	strs  map[string]string
	lists map[string][]string
	seen  map[string]bool
}

func (p parsed) str(n string) string    { return p.strs[n] }
func (p parsed) list(n string) []string { return p.lists[n] }
func (p parsed) on(n string) bool       { return p.bools[n] }
func (p parsed) has(n string) bool      { return p.seen[n] }

// parse reads flags anywhere among positionals: --name value, --name=value,
// and -- ending the flags.
func parse(args []string, spec flagSpec) (parsed, error) {
	p := parsed{bools: map[string]bool{}, strs: map[string]string{}, lists: map[string][]string{}, seen: map[string]bool{}}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			p.pos = append(p.pos, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "--") || a == "--" {
			if strings.HasPrefix(a, "-") && len(a) > 1 && a != "-h" {
				return p, contract.New(contract.Usage, "unknown option %s (options are --long)", a)
			}
			if a == "-h" {
				p.bools["help"], p.seen["help"] = true, true
				continue
			}
			p.pos = append(p.pos, a)
			continue
		}
		name, val, hasVal := strings.Cut(a[2:], "=")
		k, ok := spec[name]
		if !ok && name != "help" {
			return p, contract.New(contract.Usage, "unknown option --%s", name).WithFix(suggest(name, spec))
		}
		p.seen[name] = true
		if name == "help" || k == boolFlag {
			if hasVal {
				return p, contract.New(contract.Usage, "--%s takes no value", name)
			}
			p.bools[name] = true
			continue
		}
		if !hasVal {
			if i+1 >= len(args) {
				return p, contract.New(contract.Usage, "--%s needs a value", name)
			}
			val = args[i+1] //nolint:gosec // G602: i+1 < len(args) is checked just above
			i++
		}
		switch k {
		case repeatFlag:
			p.lists[name] = append(p.lists[name], val)
		case listFlag:
			for _, v := range strings.Split(val, ",") {
				if v = strings.TrimSpace(v); v != "" {
					p.lists[name] = append(p.lists[name], v)
				}
			}
		default:
			p.strs[name] = val
		}
	}
	return p, nil
}

func suggest(name string, spec flagSpec) string {
	var names []string
	for n := range spec {
		names = append(names, "--"+n)
	}
	sort.Strings(names)
	return "options here: " + strings.Join(names, " ")
}

// ---- output ------------------------------------------------------------------

func (a *App) json(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		_, _ = fmt.Fprintln(a.Stderr, "impr: encode JSON:", err)
		return
	}
	_, _ = fmt.Fprintln(a.Stdout, string(b))
}

func (a *App) say(format string, args ...any) { _, _ = fmt.Fprintf(a.Stderr, format+"\n", args...) }

// fail prints err (an error document on stdout with --json, the message on
// stderr always) and returns its exit code.
func (a *App) fail(err error, asJSON bool) int {
	_, _ = io.WriteString(a.Stderr, contract.Text(err))
	if asJSON {
		a.json(contract.DocOf(err))
	}
	return int(contract.CodeOf(err))
}

// ---- wiring --------------------------------------------------------------------

func (a *App) dirs() (paths.Dirs, error) {
	return paths.Resolve(paths.Env{GOOS: a.GOOS, Getenv: a.Getenv, Home: a.Home})
}

func (a *App) store() (profile.Store, error) {
	d, err := a.dirs()
	if err != nil {
		return profile.Store{}, contract.Wrap(contract.Unavailable, err, "locate the imprimatur config")
	}
	s := profile.Store{Dir: d.Config}
	a.migrateOnce(s, d)
	return s, nil
}

// migrateOnce imports the PowerShell line's configuration the first time impr
// runs on a machine that has one and no profiles index yet.
func (a *App) migrateOnce(s profile.Store, d paths.Dirs) {
	if _, exists, err := s.LoadIndex(); err != nil || exists {
		return
	}
	env := a.legacyEnv(d)
	src := profile.FindLegacy(env)
	if src == "" {
		return
	}
	rep, err := profile.ImportLegacy(s, src, env)
	if err != nil {
		a.say("profiles  could not import the PowerShell settings from %s: %v (run impr profile import-legacy)", src, err)
		return
	}
	a.say("profiles  imported the PowerShell line's settings from %s: %s", src, strings.Join(rep.Imported, ", "))
	for n, ps := range rep.Problems {
		a.say("profiles  %s has %d thing(s) to finish: impr profile validate %s", n, len(ps), n)
	}
}

func (a *App) legacyEnv(d paths.Dirs) profile.LegacyEnv {
	return profile.LegacyEnv{GOOS: a.GOOS, Home: a.Home, User: a.User, ConfigDir: d.Config, Getenv: a.Getenv, Now: a.Now}
}

func (a *App) host() backend.Host {
	return backend.Host{GOOS: a.GOOS, Runner: a.Runner, Now: a.Now,
		Secrets: secrets.Resolver{Runner: a.Runner, Getenv: a.Getenv, GOOS: a.GOOS}}
}

func (a *App) service() (*signing.Service, error) {
	s, err := a.store()
	if err != nil {
		return nil, err
	}
	return &signing.Service{Host: a.host(), Store: s, Version: version, Log: a.Stderr}, nil
}

// ---- dispatch ------------------------------------------------------------------

// Run runs one command line and returns the exit code.
func (a *App) Run(ctx context.Context, args []string) int {
	asJSON := false
	for _, x := range args {
		asJSON = asJSON || x == "--json"
	}
	if len(args) == 0 {
		a.usage()
		return int(contract.Usage)
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "-h", "--help", "help":
		a.usage()
		return 0
	case "-V", "--version", "version":
		_, _ = fmt.Fprintf(a.Stdout, "impr %s (%s, %s)\n", version, commit, date)
		return 0
	}
	h, ok := commands[cmd]
	if !ok {
		return a.fail(contract.New(contract.Usage, "unknown command %q", cmd).WithFix("impr help"), asJSON)
	}
	code, err := h(ctx, a, rest)
	if err != nil {
		return a.fail(err, asJSON)
	}
	return code
}

type handler func(ctx context.Context, a *App, args []string) (int, error)

var commands map[string]handler

func init() {
	commands = map[string]handler{
		"companion": cmdCompanion,
		"doctor":    cmdDoctor,
		"profile":   cmdProfile,
		"cert":      cmdCert,
		"sign":      cmdSign,
		"verify":    cmdVerify,
		"rules":     cmdRules,
	}
}

// ContractCommands are the commands that speak contract v1 (companion info
// lists them; sange requires the first six).
var ContractCommands = []string{"companion info", "profile list", "profile show", "cert list", "sign", "verify",
	"doctor", "profile validate", "profile capabilities", "rules"}

const usageText = `impr: sign and verify release artifacts with signing profiles.

Usage:
  impr companion info [--json]
  impr doctor [--json]
  impr profile list|show|add|edit|rm|import|export|validate|default|capabilities|import-legacy ... [--json]
  impr cert list [--json]
  impr sign --manifest FILE --commit SHA --tree ID --profile NAME --purpose release|test|internal
            [--platforms windows,macos,checksums,containers] [--root DIR] [--repo URL] [--json] [--strict]
  impr verify (FILE... | --signed impr-manifest.json [--manifest FILE]) --profile NAME [--root DIR] [--json] [--strict]
  impr rules --request FILE [--json] [--strict] [--out-dir DIR]
  impr version

Exit codes: 0 ok, 1 usage, 2 skipped (without --strict), 3 signing failed,
4 verification failed, 5 unavailable.`

func (a *App) usage() { _, _ = fmt.Fprintln(a.Stderr, usageText) }

func needNoArgs(p parsed, what string) error {
	if len(p.pos) > 0 {
		return contract.New(contract.Usage, "%s takes no arguments (got %s)", what, strings.Join(p.pos, " "))
	}
	return nil
}
