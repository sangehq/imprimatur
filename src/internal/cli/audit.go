package cli

import (
	"context"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/events"
	"github.com/sangehq/imprimatur/src/internal/redact"
)

// audited are the commands the audit trail records: everything that signs,
// verifies, builds, or changes configuration, profiles, tokens or the
// installed binary. Read-only commands are not recorded.
var audited = map[string]map[string]bool{
	"sign": nil, "approve": nil, "verify": nil, "build": nil, "release": nil, "install": nil, "uninstall": nil,
	"profile":    {"add": true, "edit": true, "rm": true, "import": true, "default": true, "import-legacy": true},
	"config":     {"set": true, "unset": true, "profile": true},
	"server":     {"token": true},
	"webhooks":   {"secret": true},
	"secret":     {"set": true},
	"completion": {"install": true, "uninstall": true},
}

// secretLike are argument shapes never written to the audit trail.
var secretLike = regexp.MustCompile(`whsec_|whsk_|impr_[A-Za-z0-9_-]{20,}|PRIVATE KEY|(?i)password=`)

func isAudited(cmd string, rest []string) bool {
	subs, ok := audited[cmd]
	if !ok {
		return false
	}
	if subs == nil {
		return true
	}
	return len(rest) > 0 && subs[rest[0]]
}

// audit appends one record to <state>/audit/YYYY-MM.jsonl, hash-chained like
// the event log: who ran which command with which arguments, when, for how
// long, and how it ended (audit N-B25). A trail that cannot be written is a
// warning; the command has already run.
func (a *App) audit(_ context.Context, cmd string, rest []string, code int, start interface{ UnixMilli() int64 }) {
	if !isAudited(cmd, rest) {
		return
	}
	d, err := a.dirs()
	if err != nil {
		return
	}
	id, err := events.InstallID(d.State)
	if err != nil {
		a.say("audit     not recorded: %v", err)
		return
	}
	args := make([]string, len(rest))
	for i, x := range rest {
		args[i] = x
		if secretLike.MatchString(x) || redact.Found(x) {
			args[i] = "[redacted]"
		}
	}
	env := a.eventEnv(id)
	ev, err := env.New("audit.command.completed", cmd, map[string]any{"user": a.User, "command": cmd, "args": args,
		"exitCode": code, "durationMs": a.Now().UnixMilli() - start.UnixMilli()})
	if err != nil {
		return
	}
	if err := (events.Log{Dir: filepath.Join(d.State, "audit")}).Write(context.Background(), ev); err != nil {
		a.say("audit     not recorded: %v", err)
		return
	}
	if _, err := a.anchor(context.Background(), false); err != nil {
		a.say("audit     not anchored: %v", err)
	}
}

var auditFlags = flagSpec{"json": boolFlag, "strict": boolFlag, "limit": stringFlag, "against": stringFlag}

func cmdAudit(_ context.Context, a *App, args []string) (int, error) {
	p, err := parse(args, auditFlags)
	if err != nil {
		return 0, err
	}
	d, err := a.dirs()
	if err != nil {
		return 0, contract.Wrap(contract.Unavailable, err, "locate the imprimatur state directory")
	}
	log := events.Log{Dir: filepath.Join(d.State, "audit")}
	sub := "tail"
	if len(p.pos) > 0 {
		sub = p.pos[0]
	}
	switch sub {
	case "tail":
		limit := 50
		if v := p.str("limit"); v != "" {
			if limit, err = strconv.Atoi(v); err != nil || limit < 1 {
				return 0, contract.New(contract.Usage, "--limit must be a positive number")
			}
		}
		out := []events.Event{}
		if err := log.Each(func(ev events.Event, _ []byte) error { out = append(out, ev); return nil }); err != nil {
			return 0, contract.Wrap(contract.Unavailable, err, "read the audit trail")
		}
		if len(out) > limit {
			out = out[len(out)-limit:]
		}
		if p.on("json") {
			a.json(map[string]any{"contract": contract.Version, "records": out})
			return 0, nil
		}
		for _, ev := range out {
			a.say("%s  %s", ev.Time.Format("2006-01-02T15:04:05Z"), string(ev.Data))
		}
		return 0, nil
	case "verify":
		n, err := log.Verify()
		if err == nil && p.str("against") != "" {
			err = a.verifyAnchor(d.State, p.str("against"))
		}
		if p.on("json") {
			r := map[string]any{"contract": contract.Version, "ok": err == nil, "checked": n}
			if err != nil {
				r["problem"] = err.Error()
			}
			a.json(r)
		} else if err == nil {
			a.say("audit     %d record(s), chain intact", n)
			if p.str("against") != "" {
				a.say("audit     matches the anchor in %s", p.str("against"))
			}
		}
		if err != nil {
			// One JSON document on stdout, the error on stderr, the exit code 4.
			_, _ = a.Stderr.Write([]byte(contract.Text(contract.Wrap(contract.VerifyFailed, err, "the audit trail does not verify"))))
			return int(contract.VerifyFailed), nil
		}
		return 0, nil
	case "anchor":
		h, err := a.anchor(context.Background(), true)
		if err != nil {
			return 0, contract.Wrap(contract.Unavailable, err, "read the logs")
		}
		if p.on("json") {
			a.json(map[string]any{"contract": contract.Version, "audit": h.Audit, "events": h.Events})
		} else {
			a.say("anchor    audit %d %s, events %d %s", h.Audit.Count, h.Audit.Hash, h.Events.Count, h.Events.Hash)
		}
		return 0, nil
	}
	return 0, contract.New(contract.Usage, "unknown audit subcommand %q", sub).WithFix("impr audit tail", "impr audit verify [--against ANCHOR]", "impr audit anchor")
}
