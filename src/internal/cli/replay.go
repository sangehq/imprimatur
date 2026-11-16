package cli

import (
	"context"
	"path/filepath"
	"strconv"
	"time"

	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/events"
	"github.com/sangehq/imprimatur/src/internal/webhook"
)

var replayFlags = flagSpec{"json": boolFlag, "to": stringFlag, "since": stringFlag, "type": listFlag, "limit": stringFlag,
	"dry-run": boolFlag, "force": boolFlag}

// ReplayResult is `impr events replay --json`.
type ReplayResult struct {
	Contract     int    `json:"contract"`
	OK           bool   `json:"ok"`
	Subscription string `json:"subscription"`
	Since        string `json:"since,omitempty"`
	Matched      int    `json:"matched"`
	Sent         int    `json:"sent"`
	Pending      int    `json:"pending"`
	Delivered    int    `json:"alreadyDelivered"`
	DryRun       bool   `json:"dryRun,omitempty"`
}

// cmdEventsReplay resends logged events to one outbound webhook: a receiver
// that was down, or one added after the events happened. It sends only what
// the subscription would have received (local-class events never leave),
// skips events that receiver already acknowledged unless --force, and stops
// at --limit (default 1000) so a mistake cannot flood a receiver.
func cmdEventsReplay(ctx context.Context, a *App, args []string) (int, error) {
	p, err := parse(args, replayFlags)
	if err != nil {
		return 0, err
	}
	name := p.str("to")
	if name == "" {
		return 0, contract.New(contract.Usage, "--to names the outbound webhook to replay to").WithFix("impr webhooks list")
	}
	var since time.Time
	if v := p.str("since"); v != "" {
		if dur, err := time.ParseDuration(v); err == nil {
			since = a.Now().Add(-dur)
		} else if since, err = time.Parse(time.RFC3339, v); err != nil {
			return 0, contract.New(contract.Usage, "--since is a duration (24h) or a time (2026-11-16T00:00:00Z)")
		}
	}
	limit := 1000
	if v := p.str("limit"); v != "" {
		if limit, err = strconv.Atoi(v); err != nil || limit < 1 {
			return 0, contract.New(contract.Usage, "--limit is a positive number")
		}
	}
	for _, g := range p.list("type") {
		if !events.KnownGlob(g) {
			return 0, contract.New(contract.Usage, "--type %s matches no event type", g)
		}
	}
	d, err := a.dirs()
	if err != nil {
		return 0, contract.Wrap(contract.Unavailable, err, "locate the imprimatur state directory")
	}
	eff, err := a.effective(d)
	if err != nil {
		return 0, contract.Wrap(contract.Usage, err, "the imprimatur config cannot be read")
	}
	subs, err := a.subscriptions(ctx, eff.Config)
	if err != nil {
		return 0, contract.Wrap(contract.Unavailable, err, "the webhook's secret cannot be read")
	}
	var sub *webhook.Subscription
	for i := range subs {
		if subs[i].Name == name {
			sub = &subs[i]
		}
	}
	if sub == nil {
		return 0, contract.New(contract.Usage, "no outbound webhook named %s", name).WithFix("impr webhooks list")
	}
	box := a.outbox(d)
	res := ReplayResult{Contract: contract.Version, OK: true, Subscription: name, DryRun: p.on("dry-run")}
	if !since.IsZero() {
		res.Since = since.UTC().Format(time.RFC3339)
	}
	var todo []events.Event
	err = (events.Log{Dir: filepath.Join(d.State, "events")}).Each(func(ev events.Event, _ []byte) error {
		if ev.Time.Before(since) || !sub.Wants(ev) || !matchesAny(p.list("type"), ev.Type) {
			return nil
		}
		res.Matched++
		if !p.on("force") && box.Delivered(name, ev.ID) {
			res.Delivered++
			return nil
		}
		if len(todo) < limit {
			todo = append(todo, ev)
		}
		return nil
	})
	if err != nil {
		return 0, contract.Wrap(contract.Unavailable, err, "read the event log")
	}
	for _, ev := range todo {
		if ctx.Err() != nil {
			break
		}
		if res.DryRun {
			res.Sent++
			continue
		}
		if err := box.Enqueue(ctx, *sub, ev); err != nil {
			res.Pending++ // kept in the outbox and retried on its schedule
			continue
		}
		res.Sent++
	}
	verb := "sent"
	if res.DryRun {
		verb = "would send"
	}
	if p.on("json") {
		a.json(res)
	} else {
		a.say("replay    %s: %d matched, %d %s, %d already delivered, %d pending retry", name, res.Matched, res.Sent, verb, res.Delivered, res.Pending)
		if res.Matched-res.Delivered > limit {
			a.say("replay    stopped at --limit %d; run it again for the rest", limit)
		}
	}
	return 0, nil
}
