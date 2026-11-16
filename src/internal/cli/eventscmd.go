package cli

import (
	"context"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/events"
)

var eventsFlags = flagSpec{"json": boolFlag, "strict": boolFlag, "type": listFlag, "limit": stringFlag, "follow": boolFlag}

// followEvery is how often `impr events tail --follow` reads the log again.
var followEvery = 500 * time.Millisecond

// EventsList is `impr events tail --json`.
type EventsList struct {
	Contract int            `json:"contract"`
	Events   []events.Event `json:"events"`
}

// EventsVerify is `impr events verify --json`.
type EventsVerify struct {
	Contract int    `json:"contract"`
	OK       bool   `json:"ok"`
	Checked  int    `json:"checked"`
	Problem  string `json:"problem,omitempty"`
}

// EventTypes is `impr events types --json`.
type EventTypes struct {
	Contract int              `json:"contract"`
	Types    []EventTypeEntry `json:"types"`
}

// EventTypeEntry is one catalogued type.
type EventTypeEntry struct {
	Type   string `json:"type"`
	Class  string `json:"class"`
	Schema string `json:"dataschema"`
}

func cmdEvents(ctx context.Context, a *App, args []string) (int, error) {
	if len(args) > 0 && args[0] == "replay" {
		return cmdEventsReplay(ctx, a, args[1:])
	}
	p, err := parse(args, eventsFlags)
	if err != nil {
		return 0, err
	}
	sub := "tail"
	if len(p.pos) > 0 {
		sub = p.pos[0]
	}
	d, err := a.dirs()
	if err != nil {
		return 0, contract.Wrap(contract.Unavailable, err, "locate the imprimatur state directory")
	}
	log := events.Log{Dir: filepath.Join(d.State, "events")}
	switch sub {
	case "tail":
		limit := 50
		if v := p.str("limit"); v != "" {
			if limit, err = strconv.Atoi(v); err != nil || limit < 1 {
				return 0, contract.New(contract.Usage, "--limit must be a positive number")
			}
		}
		follow := p.on("follow")
		if follow && p.on("json") {
			return 0, contract.New(contract.Usage, "--follow prints lines as events arrive; --json prints one document").
				WithFix("impr events tail --follow", "GET /v1/events/stream on impr serve, for a machine-readable stream")
		}
		// Take the end before reading, so an event written in between is
		// printed by the follow loop rather than lost.
		end, err := log.End()
		if err != nil {
			return 0, contract.Wrap(contract.Unavailable, err, "read the event log")
		}
		var out []events.Event
		err = log.Each(func(ev events.Event, _ []byte) error {
			if matchesAny(p.list("type"), ev.Type) {
				out = append(out, ev)
			}
			return nil
		})
		if err != nil {
			return 0, contract.Wrap(contract.Unavailable, err, "read the event log")
		}
		if len(out) > limit {
			out = out[len(out)-limit:]
		}
		if out == nil {
			out = []events.Event{}
		}
		if p.on("json") {
			a.json(EventsList{Contract: contract.Version, Events: out})
			return 0, nil
		}
		for _, ev := range out {
			a.say("%s  %-30s %s", ev.Time.Format("2006-01-02T15:04:05Z"), ev.Short(), ev.Subject)
		}
		if follow {
			return a.followEvents(ctx, log, end, p.list("type"))
		}
		return 0, nil
	case "verify":
		n, err := log.Verify()
		r := EventsVerify{Contract: contract.Version, OK: err == nil, Checked: n}
		if err != nil {
			r.Problem = err.Error()
		}
		if p.on("json") {
			a.json(r)
		} else if err == nil {
			a.say("events    %d event(s), chain intact", n)
		}
		if err != nil {
			// One JSON document on stdout, the error on stderr, the exit code 4.
			_, _ = a.Stderr.Write([]byte(contract.Text(contract.Wrap(contract.VerifyFailed, err, "the event log does not verify"))))
			return int(contract.VerifyFailed), nil
		}
		return 0, nil
	case "types":
		var ts []EventTypeEntry
		for short, class := range events.Catalogue {
			ts = append(ts, EventTypeEntry{Type: events.TypePrefix + short, Class: class, Schema: events.SchemaURL(short)})
		}
		sort.Slice(ts, func(i, j int) bool { return ts[i].Type < ts[j].Type })
		if p.on("json") {
			a.json(EventTypes{Contract: contract.Version, Types: ts})
			return 0, nil
		}
		for _, t := range ts {
			a.say("%-50s %s", t.Type, t.Class)
		}
		return 0, nil
	}
	return 0, contract.New(contract.Usage, "unknown events subcommand %q", sub).WithFix("impr events tail", "impr events verify", "impr events types")
}

func matchesAny(globs []string, typ string) bool {
	if len(globs) == 0 {
		return true
	}
	for _, g := range globs {
		if events.Matches(strings.TrimSpace(g), typ) {
			return true
		}
	}
	return false
}

// followEvents prints each event written after c until ctx ends (Ctrl-C).
func (a *App) followEvents(ctx context.Context, log events.Log, c events.Cursor, types []string) (int, error) {
	t := time.NewTicker(followEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return 0, nil
		case <-t.C:
		}
		evs, _, next, err := log.Read(c)
		if err != nil {
			return 0, contract.Wrap(contract.Unavailable, err, "read the event log")
		}
		c = next
		for _, ev := range evs {
			if matchesAny(types, ev.Type) {
				a.say("%s  %-30s %s", ev.Time.Format("2006-01-02T15:04:05Z"), ev.Short(), ev.Subject)
			}
		}
	}
}
