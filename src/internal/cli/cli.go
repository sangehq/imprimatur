// Package cli is impr's command line: a small flag parser over the standard
// library, the command table, and the contract's output rules (one JSON
// document on stdout with --json, human text on stderr, exit codes 0 to 5).
package cli

import (
	"os/signal"
	"syscall"

	notifykit "github.com/simtabi/go-notifykit/src"

	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/sangehq/imprimatur/src/internal/backend"
	"github.com/sangehq/imprimatur/src/internal/bundle"
	"github.com/sangehq/imprimatur/src/internal/config"
	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/events"
	"github.com/sangehq/imprimatur/src/internal/execx"
	"github.com/sangehq/imprimatur/src/internal/hooks"
	"github.com/sangehq/imprimatur/src/internal/notify"
	"github.com/sangehq/imprimatur/src/internal/paths"
	"github.com/sangehq/imprimatur/src/internal/profile"
	"github.com/sangehq/imprimatur/src/internal/redact"
	"github.com/sangehq/imprimatur/src/internal/secrets"
	"github.com/sangehq/imprimatur/src/internal/signing"
	"github.com/sangehq/imprimatur/src/internal/webhook"
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
	// Stdin feeds the interactive menu; Interactive reports whether a person
	// is at a terminal. Both nil means no menu: impr with no arguments prints
	// its usage, as scripts and sange expect.
	Stdin       io.Reader
	Interactive func() bool
	// Notifier replaces the desktop notifier; tests give it a recorder.
	Notifier *notifykit.Notifier
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
		Runner: execx.OS{}, Now: time.Now, Stdin: os.Stdin, Interactive: stdinIsTerminal}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return a.RunInterruptible(ctx, stop, args)
}

// InterruptedExit is the exit code after Ctrl-C or SIGTERM, by convention.
const InterruptedExit = 130

// RunInterruptible runs a command line on a context the first interrupt
// cancels. The running tool is stopped (execx starts every tool with the
// context), the command returns, and its deferred cleanup runs: temporary
// keychains, credential files and decrypted keys are removed rather than
// left behind by a killed process. restore puts the default signal handling
// back, so a second interrupt ends impr at once.
func (a *App) RunInterruptible(ctx context.Context, restore func(), args []string) int {
	go func() {
		<-ctx.Done()
		restore()
	}()
	code := a.Run(ctx, args)
	if ctx.Err() != nil {
		a.say("impr: interrupted; temporary files and keychains were removed")
		return InterruptedExit
	}
	return code
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

// say writes one log line to stderr, with secret shapes redacted.
func (a *App) say(format string, args ...any) {
	_, _ = fmt.Fprintln(a.Stderr, redact.String(fmt.Sprintf(format, args...)))
}

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

// effective is the merged configuration: system < user < active profile.
func (a *App) effective(d paths.Dirs) (config.Effective, error) {
	sys := paths.SystemConfig(paths.Env{GOOS: a.GOOS, Getenv: a.Getenv, Home: a.Home})
	return config.LoadEffective(config.Sources{SystemDir: sys, UserDir: d.Config, Profile: a.Getenv("IMPR_CONFIG_PROFILE")})
}

func (a *App) dirs() (paths.Dirs, error) {
	return paths.Resolve(paths.Env{GOOS: a.GOOS, Getenv: a.Getenv, Home: a.Home})
}

func (a *App) store() (profile.Store, error) {
	d, err := a.dirs()
	if err != nil {
		return profile.Store{}, contract.Wrap(contract.Unavailable, err, "locate the imprimatur config")
	}
	if copied, err := paths.MigrateLegacy(d, a.Now()); err != nil {
		a.say("config    could not copy the old Windows config: %v", err)
	} else if len(copied) > 0 {
		a.say("config    copied %s into %s; the old folder is kept", strings.Join(copied, ", "), d.Config)
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
		// Write the index anyway, naming the source, so the import is not
		// retried, and its warning not repeated, on every command (audit
		// N-B18). impr profile import-legacy still runs it on request.
		_ = s.SaveIndex(profile.Index{MigratedFrom: src + " (failed: run impr profile import-legacy)", MigratedAt: a.Now().UTC().Format(time.RFC3339)})
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
	r := a.runner()
	return backend.Host{GOOS: a.GOOS, Runner: r, Now: a.Now,
		Secrets: secrets.Resolver{Runner: r, Getenv: a.Getenv, GOOS: a.GOOS}}
}

// runner is the tool runner with the config's tool pins applied. A config
// that does not load leaves the pins off here; every command that signs or
// verifies loads the config itself and fails on it first.
func (a *App) runner() execx.Runner {
	o, ok := a.Runner.(execx.OS)
	if !ok {
		return a.Runner
	}
	if d, err := a.dirs(); err == nil {
		if eff, err := a.effective(d); err == nil && len(eff.Config.Tools) > 0 {
			o.Pins = eff.Config.Tools
		}
	}
	return o
}

func (a *App) service() (*signing.Service, error) {
	s, err := a.store()
	if err != nil {
		return nil, err
	}
	d, err := a.dirs()
	if err != nil {
		return nil, contract.Wrap(contract.Unavailable, err, "locate the imprimatur config")
	}
	eff, err := a.effective(d)
	cfg := eff.Config
	if err != nil {
		// config.json decides which gates run; a broken one never means "no gates".
		return nil, contract.Wrap(contract.Unavailable, err, "the imprimatur config cannot be read").
			WithFix("impr hooks list", "fix or remove "+filepath.Join(d.Config, config.File))
	}
	hk := &hooks.Runner{Hooks: cfg.Hooks, Warn: a.say}
	bus := a.bus()
	if bus != nil {
		bus.Sinks = append(bus.Sinks, hk)
		if subs, err := a.subscriptions(ctxBackground(), cfg); err != nil {
			a.say("webhooks  not sending: %v", err)
		} else if len(subs) > 0 {
			bus.Sinks = append(bus.Sinks, webhook.Sink{Outbox: a.outbox(d), Subs: subs})
		}
	}
	host := a.host()
	trusted := cfg.Bundles.TrustedKeys
	check := func(p profile.Profile) error {
		return bundle.Check(context.Background(), host.Runner, d.Config, p, trusted)
	}
	return &signing.Service{Host: host, Store: s, Version: version, Log: a.Stderr, Events: bus, Hooks: hk,
		RequireFullGPG: cfg.Policy.RequireFullGPG(), Strict: cfg.Policy.Strict, ManagedCheck: check, Approvals: cfg.Approvals, Confirm: a.confirm()}, nil
}

// confirm asks the person at the terminal to type a value, or is nil when no
// person is there (a pipe, CI, the REST server), so confirm-mode approval is
// refused rather than answered by a script.
func (a *App) confirm() func(prompt, want string) bool {
	if a.Interactive == nil || !a.Interactive() || a.Stdin == nil {
		return nil
	}
	return func(prompt, want string) bool {
		_, _ = fmt.Fprintf(a.Stderr, "%s: ", prompt)
		var got string
		_, _ = fmt.Fscanln(a.Stdin, &got)
		return got == want
	}
}

// bus is the event bus for this run: the hash-chained log in the state dir.
// An unusable state dir costs the events, never the command (a warning says
// so), so signing still works on a read-only home.
func (a *App) bus() *events.Bus {
	d, err := a.dirs()
	if err != nil {
		return nil
	}
	id, err := events.InstallID(d.State)
	if err != nil {
		a.say("events    not recorded: %v", err)
		return nil
	}
	sinks := []events.Sink{events.Log{Dir: filepath.Join(d.State, "events")}}
	if n := a.notifier(); n != nil {
		sinks = append(sinks, notify.Sink{N: n})
	}
	return &events.Bus{Env: events.Env{Now: a.Now, NewID: events.NewID, InstallID: id}, Sinks: sinks, Warn: a.say}
}

// notifier is the desktop notifier, or nil when the config turns it off or it
// cannot be built. go-notifykit itself stays silent under go test and in CI.
func (a *App) notifier() *notifykit.Notifier {
	d, err := a.dirs()
	if err != nil {
		return nil
	}
	cfg := config.Config{}
	if eff, err := a.effective(d); err == nil {
		cfg = eff.Config
	}
	if a.Notifier != nil {
		return a.Notifier
	}
	n, err := notifykit.New(notify.Config(filepath.Join(d.State, "notify"), !cfg.Notify.DesktopOn(), a.Stderr, a.Getenv))
	if err != nil {
		a.say("notify    off: %v", err)
		return nil
	}
	return n
}

// ---- dispatch ------------------------------------------------------------------

// Run runs one command line and returns the exit code.
func (a *App) Run(ctx context.Context, args []string) int {
	asJSON, wantHelp := scanGlobal(args)
	if len(args) == 0 {
		if a.Interactive != nil && a.Interactive() && a.Stdin != nil {
			return a.menu(ctx)
		}
		a.usage()
		return int(contract.Usage)
	}
	cmd, rest := resolveAlias(args[0]), args[1:]
	if cmd == "help" && len(rest) > 0 {
		return a.helpFor(resolveAlias(rest[0]))
	}
	if wantHelp && cmd != "-h" && cmd != "--help" {
		return a.helpFor(cmd)
	}
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
	start := a.Now()
	code, err := h(ctx, a, rest)
	if err != nil {
		code = a.fail(err, asJSON)
	}
	a.audit(ctx, cmd, rest, code, start)
	a.dailyExpiryCheck(ctx, cmd)
	return code
}

type handler func(ctx context.Context, a *App, args []string) (int, error)

var commands map[string]handler

func init() {
	commands = map[string]handler{
		"companion":  cmdCompanion,
		"doctor":     cmdDoctor,
		"profile":    cmdProfile,
		"cert":       cmdCert,
		"sign":       cmdSign,
		"approve":    cmdApprove,
		"verify":     cmdVerify,
		"rules":      cmdRules,
		"events":     cmdEvents,
		"hooks":      cmdHooks,
		"webhooks":   cmdWebhooks,
		"serve":      cmdServe,
		"server":     cmdServer,
		"config":     cmdConfig,
		"completion": cmdCompletion,
		"install":    cmdInstall,
		"uninstall":  cmdUninstall,
		"path":       cmdPath,
		"menu":       cmdMenu,
		"build":      cmdBuild,
		"release":    cmdRelease,
		"tools":      cmdTools,
		"audit":      cmdAudit,
		"notify":     cmdNotify,
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
  impr profile bundle install BUNDLE.json [--sig FILE] | list [--json] | verify [--json]
  impr cert list [--json]
  impr cert create [--name NAME] [--subject CN] [--days N] [--json]
  impr cert install-check --print [--for systemd|launchd|task] [--exe PATH]
  impr sign (FILE... | --manifest FILE --commit SHA --tree ID) --profile NAME --purpose release|test|internal
            [--platforms windows,macos,checksums,containers,attestations] [--root DIR] [--repo URL] [--json] [--strict]
            [--approval FILE]...
  impr approve --manifest FILE --profile NAME --purpose P --approver NAME --key SSH-KEY [--expires 24h] [--out FILE] [--json]
  impr notify send|ping|doctor ...
  impr verify (FILE... | --signed impr-manifest.json [--manifest FILE]) --profile NAME [--root DIR] [--json] [--strict]
  impr rules test --policy applocker.xml [--user Everyone] FILE... [--json]   (Windows)
  impr rules (--request FILE | FILE... [--scope publisher|product|version] [--product NAME] [--file-version a.b.c.d]
            [--base-policy {GUID}] [--eku OID] [--applocker] [--wdac] [--enforce] [--sid SID]) [--out-dir DIR] [--json] [--strict]
  impr build [--main ./cmd/NAME] [--module DIR] [--repo-root DIR] [--binary NAME] [--version vX.Y.Z --version-var PKG.VAR]
            [--targets os/arch,...] [--clean] [--allow-dirty] [--json]
  impr release --profile NAME --purpose release|test|internal [--repo URL] [--platforms ...] [build options] [--json]
  impr events tail [--type GLOB] [--limit N] [--json] | verify [--json] | types [--json]
  impr hooks list [--json] | pin FILE | test NAME
  impr webhooks list [--json] | secret | retry [--all] | deliveries [--json]
  impr config path|show|validate [--json] | get KEY | set KEY VALUE [--profile NAME] | unset KEY [--profile NAME]
  impr config profile list [--json] | create NAME | use NAME | use --none | rm NAME
  impr tools list [--json] | pin NAME
  impr events replay --to WEBHOOK [--since 24h|TIME] [--type GLOB]... [--limit N] [--dry-run] [--force] [--json]
  impr audit tail [--limit N] [--json] | verify [--against ANCHOR] [--json] | anchor [--json]
  impr serve [--listen unix|HOST:PORT] [--check-config] [--yes]
  impr serve install-unit --print [--for systemd|launchd|task] [--exe PATH]
  impr server token add --scopes read,verify,sign,events | list [--json] | revoke ID
  impr completion bash|zsh|fish|powershell | install bash|zsh|fish | uninstall bash|zsh|fish
  impr install [--dir DIR] [--force]
  impr uninstall [--dir DIR]
  impr path [--json]
  impr menu
  impr version

Aliases: s sign, v verify, d doctor, h help, b build, r release.

Exit codes: 0 ok, 1 usage, 2 skipped (without --strict), 3 signing failed,
4 verification failed, 5 unavailable.`

func (a *App) usage() { _, _ = fmt.Fprintln(a.Stderr, usageText) }

func needNoArgs(p parsed, what string) error {
	if len(p.pos) > 0 {
		return contract.New(contract.Usage, "%s takes no arguments (got %s)", what, strings.Join(p.pos, " "))
	}
	return nil
}

// boolOptions are the options that take no value, across every command; any
// other --option consumes the next word as its value.
var boolOptions = map[string]bool{"--json": true, "--strict": true, "--force": true, "--requires-approval": true,
	"--check-config": true, "--none": true, "--all": true, "--help": true, "-h": true}

// scanGlobal finds --json and --help before "--", skipping a word that is
// the value of the option before it, so `--notes --json` or a file named
// --json after "--" does not switch modes (audit N-B19).
func scanGlobal(args []string) (asJSON, help bool) {
	for i := 0; i < len(args); i++ {
		x := args[i]
		if x == "--" {
			break
		}
		if i > 0 {
			prev := args[i-1]
			if strings.HasPrefix(prev, "--") && !strings.Contains(prev, "=") && !boolOptions[prev] {
				continue // x is prev's value
			}
		}
		switch x {
		case "--json":
			asJSON = true
		case "--help", "-h":
			help = true
		}
	}
	return asJSON, help
}

// helpFor prints the usage lines of one command (audit N-B20), or the whole
// usage for an unknown one.
func (a *App) helpFor(cmd string) int {
	var out []string
	keep := false
	for _, line := range strings.Split(usageText, "\n") {
		switch {
		case strings.HasPrefix(line, "  impr "+cmd+" ") || line == "  impr "+cmd:
			keep = true
			out = append(out, line)
		case keep && strings.HasPrefix(line, "            "):
			out = append(out, line) // a continuation of the line above
		default:
			keep = false
		}
	}
	if len(out) == 0 {
		a.usage()
		return int(contract.Usage)
	}
	_, _ = fmt.Fprintln(a.Stderr, "Usage:\n"+strings.Join(out, "\n")+"\n\nExit codes: 0 ok, 1 usage, 2 skipped, 3 signing failed, 4 verification failed, 5 unavailable.")
	return 0
}

func systemDir(a *App) string {
	return paths.SystemConfig(paths.Env{GOOS: a.GOOS, Getenv: a.Getenv, Home: a.Home})
}

// stdinIsTerminal reports whether stdin is a terminal, not a pipe or file.
func stdinIsTerminal() bool {
	st, err := os.Stdin.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0 && os.Getenv("CI") == ""
}

func cmdMenu(ctx context.Context, a *App, args []string) (int, error) {
	if len(args) > 0 {
		return 0, contract.New(contract.Usage, "impr menu takes no arguments")
	}
	if a.Stdin == nil {
		return 0, contract.New(contract.Usage, "the menu needs a terminal")
	}
	return a.menu(ctx), nil
}
