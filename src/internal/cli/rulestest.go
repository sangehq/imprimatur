package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/execx"
)

var rulesTestFlags = flagSpec{"json": boolFlag, "policy": stringFlag, "user": stringFlag}

// RuleDecision is one file's answer from Test-AppLockerPolicy.
type RuleDecision struct {
	Path     string `json:"path"`
	Decision string `json:"decision"` // Allowed, Denied, DeniedByDefault, AllowedByDefault
	Rule     string `json:"rule,omitempty"`
}

// RulesTestResult is `impr rules test --json`.
type RulesTestResult struct {
	Contract int            `json:"contract"`
	OK       bool           `json:"ok"`
	Policy   string         `json:"policy"`
	User     string         `json:"user"`
	Results  []RuleDecision `json:"results"`
}

// cmdRulesTest asks Windows whether an AppLocker policy would allow each
// file, for one user, without deploying it: Test-AppLockerPolicy, through the
// one PowerShell script execx allows. Exit 4 when any file would be denied.
func cmdRulesTest(ctx context.Context, a *App, args []string) (int, error) {
	p, err := parse(args, rulesTestFlags)
	if err != nil {
		return 0, err
	}
	if p.str("policy") == "" || len(p.pos) == 0 {
		return 0, contract.New(contract.Usage, "impr rules test --policy applocker.xml [--user Everyone] FILE...")
	}
	if a.GOOS != "windows" {
		return 0, contract.New(contract.Unavailable, "Test-AppLockerPolicy runs on Windows only").
			WithFix("run impr rules test on the Windows machine the policy is for")
	}
	user := orDefault(p.str("user"), "Everyone")
	policy, err := filepath.Abs(p.str("policy"))
	if err != nil {
		return 0, err
	}
	if _, err := os.Stat(policy); err != nil {
		return 0, contract.Wrap(contract.Usage, err, "the policy file cannot be read")
	}
	var files []string
	for _, f := range p.pos {
		abs, err := filepath.Abs(f)
		if err != nil {
			return 0, err
		}
		files = append(files, abs)
	}
	env, err := execx.PowerShellEnv(policy, user, files)
	if err != nil {
		return 0, err
	}
	res, err := a.host().Runner.Run(ctx, execx.Cmd{Tool: "powershell", Args: execx.PowerShellArgs(), Env: env})
	if err != nil {
		return 0, contract.Wrap(contract.Unavailable, err, "PowerShell could not run")
	}
	if res.ExitCode != 0 {
		return 0, contract.New(contract.Unavailable, "Test-AppLockerPolicy failed").WithDetails(strings.TrimSpace(res.Output()))
	}
	var ds []RuleDecision
	if err := json.Unmarshal(bytes.TrimSpace(res.Stdout), &ds); err != nil {
		return 0, contract.Wrap(contract.Unavailable, err, "Test-AppLockerPolicy's answer is not JSON")
	}
	// Every file must have its decision: a missing one was never tested, and
	// is never read as allowed (fail closed).
	if len(ds) != len(files) {
		return 0, contract.New(contract.Unavailable, "Test-AppLockerPolicy answered for %d of %d file(s); nothing is reported as allowed", len(ds), len(files)).
			WithDetails(strings.TrimSpace(res.Output()))
	}
	out := RulesTestResult{Contract: contract.Version, OK: true, Policy: policy, User: user, Results: ds}
	for _, d := range ds {
		if !strings.HasPrefix(d.Decision, "Allowed") {
			out.OK = false
		}
	}
	if p.on("json") {
		a.json(out)
	} else {
		for _, d := range ds {
			a.say("%-16s %s %s", d.Decision, d.Path, d.Rule)
		}
	}
	if !out.OK {
		// One JSON document on stdout, the error on stderr, the exit code 4.
		_, _ = a.Stderr.Write([]byte(contract.Text(contract.New(contract.VerifyFailed, "the policy would deny at least one file for %s", user))))
		return int(contract.VerifyFailed), nil
	}
	return 0, nil
}
