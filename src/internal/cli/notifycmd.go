package cli

import (
	"context"
	"path/filepath"

	notifykit "github.com/simtabi/go-notifykit/src"

	"github.com/sangehq/imprimatur/src/internal/backend"
	"github.com/sangehq/imprimatur/src/internal/config"
	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/events"
	"github.com/sangehq/imprimatur/src/internal/notify"
)

// cmdNotify is go-notifykit's shared command: impr notify send|ping|doctor.
func cmdNotify(ctx context.Context, a *App, args []string) (int, error) {
	n := a.notifier()
	if n == nil {
		return 0, contract.New(contract.Unavailable, "desktop notifications cannot be set up here")
	}
	return notifykit.RunCLI(ctx, n, args, a.Stdin, a.Stdout, a.Stderr), nil
}

// expiryEvents raises cert.expiring at each configured threshold and
// cert.expired once, per certificate, from what impr cert list read. The
// events reach the log, hooks, webhooks and desktop notifications.
func (a *App) expiryEvents(ctx context.Context, bus *events.Bus, certs []backend.CertEntry) {
	if bus == nil {
		return
	}
	d, err := a.dirs()
	if err != nil {
		return
	}
	cfg := config.Config{}
	if eff, err := a.effective(d); err == nil {
		cfg = eff.Config
	}
	var cs []notify.Cert
	for _, c := range certs {
		if c.NotAfter != nil {
			cs = append(cs, notify.Cert{Profile: c.Profile, Platform: c.Platform, Signer: c.Signer, NotAfter: *c.NotAfter})
		}
	}
	x := notify.Expiry{StateFile: filepath.Join(d.State, "notify", "expiry.json"), Days: cfg.Notify.CertExpiryDays, Now: a.Now}
	due, err := x.Due(cs)
	if err != nil {
		a.say("notify    expiry state not saved: %v", err)
	}
	for _, e := range due {
		bus.Emit(ctx, e.Type(), e.Cert.Profile, e.Data())
	}
}
