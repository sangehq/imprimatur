package cli

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/sangehq/imprimatur/src/internal/contract"
)

var unitFlags = flagSpec{"print": boolFlag, "for": stringFlag, "exe": stringFlag}

// Unit is what a generated service unit needs.
type Unit struct {
	Exe    string   // the impr binary, absolute
	Config string   // impr's config dir
	State  string   // impr's state dir: logs, the socket, the event log
	Roots  []string // server.roots: where signing writes impr-manifest.json
}

// check refuses a path holding a control character: a line break printed
// into a unit starts a new directive (security review).
func (u Unit) check() error {
	for _, p := range append([]string{u.Exe, u.Config, u.State}, u.Roots...) {
		if strings.ContainsFunc(p, unicode.IsControl) {
			return contract.New(contract.Usage, "%q holds a control character, which a unit file cannot carry safely", p)
		}
	}
	return nil
}

// cmdServeUnit prints a unit that keeps impr serve running for this user.
// It never installs one: where and how a service runs is the owner's
// decision, so impr prints the file and the commands, and changes nothing.
func cmdServeUnit(_ context.Context, a *App, args []string) (int, error) {
	p, err := parse(args, unitFlags)
	if err != nil {
		return 0, err
	}
	if !p.on("print") {
		return 0, contract.New(contract.Usage, "impr never installs a service; --print shows the unit and how to install it").
			WithFix("impr serve install-unit --print")
	}
	kind := p.str("for")
	if kind == "" {
		kind = map[string]string{"darwin": "launchd", "windows": "task"}[a.GOOS]
		if kind == "" {
			kind = "systemd"
		}
	}
	d, err := a.dirs()
	if err != nil {
		return 0, contract.Wrap(contract.Unavailable, err, "locate the imprimatur config")
	}
	eff, err := a.effective(d)
	if err != nil {
		return 0, contract.Wrap(contract.Usage, err, "the imprimatur config cannot be read")
	}
	cfg := eff.Config
	if ps := cfg.Validate(); len(ps) > 0 {
		return 0, contract.New(contract.Usage, "the server config is not valid; a unit would start a server that refuses to run").WithDetails(ps...)
	}
	if len(cfg.Server.Tokens) == 0 && len(cfg.Server.Inbound) == 0 {
		return 0, contract.New(contract.Usage, "no API token or inbound endpoint is configured, so the service would not start").
			WithFix("impr server token add --scopes read,verify")
	}
	exe, err := unitExe(p.str("exe"))
	if err != nil {
		return 0, err
	}
	u := Unit{Exe: exe, Config: d.Config, State: d.State, Roots: cfg.Server.Roots}
	if err := u.check(); err != nil {
		return 0, err
	}
	var text, where, how string
	switch kind {
	case "systemd":
		text, where = SystemdUnit(u), "~/.config/systemd/user/impr.service"
		how = "systemctl --user daemon-reload && systemctl --user enable --now impr.service"
	case "launchd":
		text, where = LaunchdPlist(u), "~/Library/LaunchAgents/"+launchdLabel+".plist"
		how = a.launchdHow(launchdLabel, legacyLaunchdLabel)
	case "task":
		text, where = TaskXML(u), "impr-serve.xml"
		how = `schtasks /Create /TN "imprimatur\impr serve" /XML impr-serve.xml`
	default:
		return 0, contract.New(contract.Usage, "--for is systemd, launchd or task")
	}
	_, _ = fmt.Fprint(a.Stdout, text)
	a.say("unit      save it as %s, then: %s", where, how)
	a.say("unit      impr installed nothing; check the config first with impr serve --check-config")
	return 0, nil
}

// unitExe is the binary a unit runs: --exe, or this impr with symlinks
// resolved. It must be absolute.
func unitExe(exe string) (string, error) {
	if exe == "" {
		var err error
		if exe, err = os.Executable(); err != nil {
			return "", contract.Wrap(contract.Unavailable, err, "find this impr binary")
		}
		if r, err := filepath.EvalSymlinks(exe); err == nil {
			exe = r
		}
	}
	if !filepath.IsAbs(exe) {
		return "", contract.New(contract.Usage, "--exe must be an absolute path")
	}
	return exe, nil
}

// launchdLabel names the impr serve launch agent, in Simtabi LLC's
// reverse-DNS namespace (owner decision, 2026-11-17).
const launchdLabel = "com.simtabi.sange.imprimatur.serve"

// The launch agent labels impr printed before 2026-11-17. impr installs no
// agent itself, so it never removes one either: it recognises a plist under
// an old label and prints the steps that replace it (install-unit,
// install-check), reports it (doctor) and names it (uninstall).
//
// Deprecated: recognising these labels may be removed no earlier than v0.2.0.
const (
	legacyLaunchdLabel = "sh.sange.imprimatur.serve"
	legacyCheckLabel   = "sh.sange.imprimatur.cert-check"
)

// launchAgentPlist is where a per-user launch agent's plist lives.
func (a *App) launchAgentPlist(label string) string {
	return filepath.Join(a.Home, "Library", "LaunchAgents", label+".plist")
}

// hasLaunchAgent reports whether a plist for label is in the user's
// LaunchAgents folder.
func (a *App) hasLaunchAgent(label string) bool {
	_, err := os.Lstat(a.launchAgentPlist(label))
	return err == nil
}

// removeAgentSteps are the shell commands that stop a launch agent and remove
// its plist. Each is safe to run again: bootout of an agent that is not
// loaded fails harmlessly, and rm -f of a missing file does nothing.
func removeAgentSteps(label string) string {
	return "launchctl bootout gui/$(id -u)/" + label + "; rm -f ~/Library/LaunchAgents/" + label + ".plist"
}

// launchdHow is how to install the agent for label: when an agent under the
// old label is in place, its removal comes first, so the two never run side
// by side. With no old agent it is the bootstrap alone, so printing it again
// after migrating prints the same thing.
func (a *App) launchdHow(label, legacy string) string {
	how := "launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/" + label + ".plist"
	if a.hasLaunchAgent(legacy) {
		a.say("unit      ~/Library/LaunchAgents/%s.plist uses the label impr used before 2026-11-17; these steps replace it", legacy)
		how = removeAgentSteps(legacy) + "; " + how
	}
	return how
}

// legacyAgentProblems are doctor's findings for agents under old labels.
func (a *App) legacyAgentProblems() []string {
	var ps []string
	for _, c := range [][2]string{{legacyLaunchdLabel, "impr serve install-unit --print"}, {legacyCheckLabel, "impr cert install-check --print"}} {
		if a.hasLaunchAgent(c[0]) {
			ps = append(ps, "launch agent "+c[0]+" uses the label impr used before 2026-11-17; replace it: "+c[1]+" prints the steps ("+removeAgentSteps(c[0])+", then install the new one)")
		}
	}
	return ps
}

// systemdQuote quotes a path for a systemd directive.
func systemdQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%", "$", "$$").Replace(s) + `"`
}

// SystemdUnit is a user service: sandboxed, writing only impr's state dir
// and the signing roots.
func SystemdUnit(u Unit) string {
	rw := []string{systemdQuote(u.State)}
	for _, r := range u.Roots {
		rw = append(rw, systemdQuote(r))
	}
	return `# impr serve as a systemd user service. Generated by impr serve install-unit --print.
[Unit]
Description=imprimatur signing API (impr serve)
After=network.target

[Service]
Type=simple
ExecStart=` + systemdQuote(u.Exe) + ` serve --no-open
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=` + strings.Join(rw, " ") + `
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictRealtime=yes
SystemCallArchitectures=native

[Install]
WantedBy=default.target
`
}

func xmlText(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// LaunchdPlist is a per-user launch agent that keeps impr serve running.
func LaunchdPlist(u Unit) string {
	log := filepath.Join(u.State, "server", "serve.log")
	return `<?xml version="1.0" encoding="UTF-8"?>
<!-- impr serve as a launchd agent, generated by impr serve install-unit. -->
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>` + launchdLabel + `</string>
  <key>ProgramArguments</key>
  <array>
    <string>` + xmlText(u.Exe) + `</string>
    <string>serve</string>
    <string>--no-open</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ProcessType</key><string>Background</string>
  <key>Umask</key><integer>63</integer>
  <key>StandardOutPath</key><string>` + xmlText(log) + `</string>
  <key>StandardErrorPath</key><string>` + xmlText(log) + `</string>
</dict>
</plist>
`
}

// TaskXML is a Windows Task Scheduler task that starts impr serve at logon
// for this user and restarts it on failure. impr is not a Windows service
// (that needs a service control handler), so a logon task is how it keeps
// running.
func TaskXML(u Unit) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!-- impr serve as a logon task, generated by impr serve install-unit. -->
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>imprimatur signing API (impr serve)</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure><Interval>PT1M</Interval><Count>10</Count></RestartOnFailure>
    <Hidden>true</Hidden>
  </Settings>
  <Actions Context="Author">
    <Exec><Command>` + xmlText(u.Exe) + `</Command><Arguments>serve --no-open</Arguments></Exec>
  </Actions>
</Task>
`
}
