package cli

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/sangehq/imprimatur/src/internal/config"
	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/events"
	"github.com/sangehq/imprimatur/src/internal/paths"
)

// webhooksEdit changes webhooks.outbound in the user config (or a
// configuration profile) through configEdit, so locked keys, validation,
// rollback and the config.changed event apply exactly as for impr config set.
//
// It starts from the subscriptions of the layer being edited, not the merged
// configuration, so a webhook from the system config is never copied into
// the user's.
func (a *App) webhooksEdit(ctx context.Context, d paths.Dirs, p parsed, _ config.Config, change func([]config.Outbound) ([]config.Outbound, error)) (int, error) {
	path, err := layerPath(d, p.str("profile"))
	if err != nil {
		return 0, err
	}
	m, _, err := config.ReadLayer(path)
	if err != nil {
		return 0, contract.Wrap(contract.Usage, err, "cannot read %s", path)
	}
	var layer struct {
		Webhooks struct {
			Outbound []config.Outbound `json:"outbound"`
		} `json:"webhooks"`
	}
	if b, err := json.Marshal(m); err == nil {
		_ = json.Unmarshal(b, &layer)
	}
	subs, err := change(slices.Clone(layer.Webhooks.Outbound))
	if err != nil {
		return 0, err
	}
	if subs == nil {
		subs = []config.Outbound{}
	}
	b, err := json.Marshal(subs)
	if err != nil {
		return 0, err
	}
	set := parsed{pos: []string{"set", "webhooks.outbound", string(b)}, strs: map[string]string{"profile": p.str("profile")},
		bools: map[string]bool{}, lists: map[string][]string{}, seen: map[string]bool{}}
	return a.configEdit(ctx, d, "set", set)
}

func findSub(subs []config.Outbound, name string) int {
	return slices.IndexFunc(subs, func(o config.Outbound) bool { return o.Name == name })
}

// webhooksManage is impr webhooks add|rm|rotate|test.
func (a *App) webhooksManage(ctx context.Context, d paths.Dirs, p parsed, cfg config.Config, sub string) (int, error) {
	if len(p.pos) != 2 {
		return 0, contract.New(contract.Usage, "impr webhooks %s NAME", sub)
	}
	name := p.pos[1]
	switch sub {
	case "add":
		if p.str("url") == "" || p.str("secret-ref") == "" {
			return 0, contract.New(contract.Usage, "impr webhooks add NAME --url URL --secret-ref secret://… [--types GLOB,…] [--allow-private]").
				WithFix("impr webhooks secret   (make the secret first, and store it)")
		}
		return a.webhooksEdit(ctx, d, p, cfg, func(subs []config.Outbound) ([]config.Outbound, error) {
			if findSub(subs, name) >= 0 {
				return nil, contract.New(contract.Usage, "a webhook named %s exists", name).WithFix("impr webhooks rm " + name + " first")
			}
			return append(subs, config.Outbound{Name: name, URL: p.str("url"), Types: p.list("types"),
				SecretRef: p.str("secret-ref"), AllowPrivate: p.on("allow-private")}), nil
		})
	case "rm":
		return a.webhooksEdit(ctx, d, p, cfg, func(subs []config.Outbound) ([]config.Outbound, error) {
			i := findSub(subs, name)
			if i < 0 {
				return nil, contract.New(contract.Usage, "no webhook named %s", name)
			}
			return slices.Delete(subs, i, i+1), nil
		})
	case "rotate":
		// Two steps: rotate --secret-ref NEW signs with both keys while the
		// receiver switches; rotate --finish then drops the old one.
		rotated := false
		code, err := a.webhooksEdit(ctx, d, p, cfg, func(subs []config.Outbound) ([]config.Outbound, error) {
			i := findSub(subs, name)
			if i < 0 {
				return nil, contract.New(contract.Usage, "no webhook named %s", name)
			}
			switch {
			case p.on("finish"):
				if subs[i].PreviousSecretRef == "" {
					return nil, contract.New(contract.Usage, "%s has no rotation to finish", name)
				}
				subs[i].PreviousSecretRef = ""
			case p.str("secret-ref") != "":
				if p.str("secret-ref") == subs[i].SecretRef {
					return nil, contract.New(contract.Usage, "--secret-ref is the secret %s already signs with", name)
				}
				subs[i].PreviousSecretRef, subs[i].SecretRef = subs[i].SecretRef, p.str("secret-ref")
				rotated = true
			default:
				return nil, contract.New(contract.Usage, "impr webhooks rotate NAME --secret-ref NEW, then rotate NAME --finish")
			}
			return subs, nil
		})
		if err == nil && code == 0 {
			step := "finished"
			if rotated {
				step = "started"
			}
			a.bus().Emit(ctx, "webhook.secret.rotated", name, map[string]any{"subscription": name, "step": step})
		}
		return code, err
	case "test":
		subs, err := a.subscriptions(ctx, cfg)
		if err != nil {
			return 0, contract.Wrap(contract.Unavailable, err, "the webhook's secret cannot be read")
		}
		i := slices.IndexFunc(subs, func(s webhookSub) bool { return s.Name == name })
		if i < 0 {
			return 0, contract.New(contract.Usage, "no webhook named %s", name)
		}
		id, err := events.InstallID(d.State)
		if err != nil {
			return 0, err
		}
		ev, err := events.Env{Now: a.Now, NewID: events.NewID, InstallID: id}.New("webhook.test", name, map[string]any{"subscription": name})
		if err != nil {
			return 0, err
		}
		// A test delivery skips the subscription's type filter and the
		// event log: it exists only to prove the receiver and its secret.
		err = a.outbox(d).Enqueue(ctx, subs[i], ev)
		ok := err == nil
		if p.on("json") {
			a.json(map[string]any{"contract": contract.Version, "ok": ok, "subscription": name, "eventId": ev.ID})
		} else if ok {
			a.say("webhooks  %s accepted the test delivery %s", name, ev.ID)
		}
		if !ok {
			_, _ = a.Stderr.Write([]byte(contract.Text(contract.Wrap(contract.Unavailable, err, "%s did not accept the test delivery", name))))
			return int(contract.Unavailable), nil
		}
		return 0, nil
	}
	return 0, contract.New(contract.Usage, "unknown webhooks subcommand %q", sub)
}
