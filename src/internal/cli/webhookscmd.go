package cli

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/sangehq/imprimatur/src/internal/config"
	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/paths"
	"github.com/sangehq/imprimatur/src/internal/webhook"
)

func ctxBackground() context.Context { return context.Background() }

func (a *App) outbox(d paths.Dirs) webhook.Outbox {
	return webhook.Outbox{Dir: filepath.Join(d.State, "outbox"), Now: a.Now, Client: webhook.Client, Warn: a.say,
		Dead: func(x webhook.Delivery) {
			a.logOnly("webhook.delivery.dead", x.Subscription, map[string]any{"subscription": x.Subscription,
				"eventId": x.EventID, "eventType": x.EventType, "attempts": x.Attempts, "lastStatus": x.LastStatus, "lastError": x.LastError})
		}}
}

// subscriptions resolves each outbound subscription's secrets. A secret that
// cannot be read stops webhooks for this run with a warning, never the
// command.
func (a *App) subscriptions(ctx context.Context, cfg config.Config) ([]webhook.Subscription, error) {
	res := a.host().Secrets
	var out []webhook.Subscription
	for _, w := range cfg.Webhooks.Outbound {
		var keys [][]byte
		var signing []ed25519.PrivateKey
		for _, ref := range []string{w.SecretRef, w.PreviousSecretRef} {
			if ref == "" {
				continue
			}
			v, err := res.Resolve(ctx, ref)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", w.Name, err)
			}
			// The key's prefix picks the scheme: whsk_ signs v1a, whsec_ v1.
			if strings.HasPrefix(strings.TrimSpace(v), webhook.SigningKeyPrefix) {
				k, err := webhook.DecodeSigningKey(v)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", w.Name, err)
				}
				signing = append(signing, k)
				continue
			}
			k, err := webhook.DecodeSecret(v)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", w.Name, err)
			}
			keys = append(keys, k)
		}
		out = append(out, webhook.Subscription{Name: w.Name, URL: w.URL, Types: w.Types, Keys: keys, SigningKeys: signing, AllowPrivate: w.AllowPrivate})
	}
	return out, nil
}

var webhooksFlags = flagSpec{"json": boolFlag, "strict": boolFlag, "all": boolFlag, "url": stringFlag, "secret-ref": stringFlag,
	"types": listFlag, "allow-private": boolFlag, "finish": boolFlag, "profile": stringFlag, "ed25519": boolFlag}

// webhookSub is a resolved outbound subscription.
type webhookSub = webhook.Subscription

// WebhooksList is `impr webhooks list --json`. It names key ids, never keys.
type WebhooksList struct {
	Contract      int               `json:"contract"`
	Subscriptions []config.Outbound `json:"subscriptions"`
	Pending       int               `json:"pending"`
	Dead          int               `json:"dead"`
}

func cmdWebhooks(ctx context.Context, a *App, args []string) (int, error) {
	p, err := parse(args, webhooksFlags)
	if err != nil {
		return 0, err
	}
	sub := "list"
	if len(p.pos) > 0 {
		sub = p.pos[0]
	}
	if sub == "secret" && p.on("ed25519") {
		sk, pk, err := webhook.NewSigningKey()
		if err != nil {
			return 0, err
		}
		// The signing key goes to stdout once, like a whsec_ secret; the
		// public key is not secret, and is what the receiver configures.
		_, _ = fmt.Fprintln(a.Stdout, sk)
		a.say("webhooks  store this signing key, set secretRef to it, and give the receiver its public key: %s", pk)
		return 0, nil
	}
	if sub == "secret" {
		s, err := webhook.NewSecret()
		if err != nil {
			return 0, err
		}
		// Printed once, to stdout only, for the owner to store (secret store
		// or CI secret) and give to the receiver. impr never writes it to disk.
		_, _ = fmt.Fprintln(a.Stdout, s)
		a.say("webhooks  store this secret (e.g. security add-generic-password -s imprimatur -a webhooks/NAME -w), give it to the receiver, and set secretRef")
		return 0, nil
	}
	d, err := a.dirs()
	if err != nil {
		return 0, contract.Wrap(contract.Unavailable, err, "locate the imprimatur config")
	}
	eff, err := a.effective(d)
	cfg := eff.Config
	if err != nil {
		return 0, contract.Wrap(contract.Usage, err, "the imprimatur config cannot be read")
	}
	ob := a.outbox(d)
	switch sub {
	case "add", "rm", "rotate", "test":
		return a.webhooksManage(ctx, d, p, cfg, sub)
	case "list":
		pend, _ := ob.List("pending")
		dead, _ := ob.List("dead")
		out := WebhooksList{Contract: contract.Version, Subscriptions: cfg.Webhooks.Outbound, Pending: len(pend), Dead: len(dead)}
		if out.Subscriptions == nil {
			out.Subscriptions = []config.Outbound{}
		}
		if p.on("json") {
			a.json(out)
			return 0, nil
		}
		for _, s := range out.Subscriptions {
			a.say("%-20s %s  %v", s.Name, s.URL, s.Types)
		}
		a.say("webhooks  %d pending, %d dead", out.Pending, out.Dead)
		return 0, nil
	case "retry":
		subs, err := a.subscriptions(ctx, cfg)
		if err != nil {
			return 0, contract.Wrap(contract.Unavailable, err, "a webhook secret cannot be read")
		}
		m := map[string]webhook.Subscription{}
		for _, s := range subs {
			m[s.Name] = s
		}
		tried, ok, err := ob.Retry(ctx, m, p.on("all"))
		if err != nil {
			return 0, err
		}
		a.say("webhooks  %d sent, %d delivered", tried, ok)
		if p.on("json") {
			a.json(map[string]any{"contract": contract.Version, "tried": tried, "delivered": ok})
		}
		return 0, nil
	case "deliveries":
		all := map[string][]webhook.Delivery{}
		for _, st := range []string{"pending", "dead", "done"} {
			ds, err := ob.List(st)
			if err != nil {
				return 0, err
			}
			for i := range ds {
				ds[i].Body = nil // the event is in the event log; keep this listing small
			}
			if ds == nil {
				ds = []webhook.Delivery{}
			}
			all[st] = ds
		}
		if p.on("json") {
			a.json(map[string]any{"contract": contract.Version, "pending": all["pending"], "dead": all["dead"], "done": all["done"]})
			return 0, nil
		}
		for _, st := range []string{"pending", "dead"} {
			for _, x := range all[st] {
				a.say("%-8s %-16s %s  attempts %d  %s", st, x.Subscription, x.EventType, x.Attempts, x.LastError)
			}
		}
		return 0, nil
	}
	return 0, contract.New(contract.Usage, "unknown webhooks subcommand %q", sub).
		WithFix("impr webhooks list", "impr webhooks add NAME --url URL --secret-ref REF", "impr webhooks rm NAME",
			"impr webhooks rotate NAME --secret-ref NEW", "impr webhooks test NAME", "impr webhooks secret", "impr webhooks retry", "impr webhooks deliveries")
}
