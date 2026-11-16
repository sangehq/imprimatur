// Package notify shows impr's events as desktop notifications through
// go-notifykit (the estate rule for Go programs): under impr's own name and
// icon, silent under go test and in CI, one banner per event, and repeats of
// one group within 30 seconds suppressed. Only what a person should act on is
// shown: a failed run, a veto, a certificate expiring or expired.
package notify

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	notifykit "github.com/simtabi/go-notifykit/src"

	"github.com/sangehq/imprimatur/src/internal/events"
)

// Identity: the binary's name, and an id from the product's own domain.
const (
	AppName     = "impr"
	AppID       = "sh.sange.imprimatur"
	EnvPrefix   = "IMPR"
	MinInterval = 30 * time.Second
)

// Icon is impr's mark at 1024 px.
//
//go:embed icon.png
var Icon []byte

// Config builds the go-notifykit configuration. disabled comes from impr's
// own config (notify.desktop false); stateDir holds the macOS helper app.
func Config(stateDir string, disabled bool, log io.Writer, getenv func(string) string) notifykit.Config {
	return notifykit.Config{AppName: AppName, AppID: AppID, BundleID: AppID + ".notifier", Icon: Icon, EnvPrefix: EnvPrefix,
		Disabled: disabled, StateDir: stateDir, MinInterval: MinInterval, Log: log, Getenv: getenv}
}

// Sink is an events.Sink that shows the events a person should act on.
type Sink struct {
	N *notifykit.Notifier
}

// Write shows ev when it is one of the shown types; others pass silently.
// A notification that cannot be shown is never the caller's failure.
func (s Sink) Write(ctx context.Context, ev events.Event) error {
	nt, ok := Banner(ev)
	if !ok || s.N == nil {
		return nil
	}
	_, _ = s.N.Send(ctx, nt)
	return nil
}

// Banner maps an event to a notification, and reports whether it is shown.
func Banner(ev events.Event) (notifykit.Notification, bool) {
	var d map[string]any
	_ = json.Unmarshal(ev.Data, &d)
	str := func(k string) string {
		v, _ := d[k].(string)
		return clean(v)
	}
	subject := short(ev.Subject)
	nt := notifykit.Notification{Group: ev.Short() + ":" + subject, Subtitle: subject}
	switch ev.Short() {
	case "signing.run.failed":
		nt.Title, nt.Level, nt.Sound = "Signing failed", notifykit.Alert, true
		nt.Body = firstLine(str("reason")) + "\nimpr events tail --type signing.*"
	case "verification.run.failed":
		nt.Title, nt.Level, nt.Sound = "Verification failed", notifykit.Alert, true
		nt.Body = firstLine(str("reason")) + "\nimpr events tail --type verification.*"
	case "hook.vetoed":
		nt.Title, nt.Level = "A hook refused a run", notifykit.Warn
		nt.Body = str("phase") + ": " + firstLine(str("reason")) + "\nimpr hooks list"
	case "cert.expiring":
		days, _ := d["days"].(float64)
		nt.Title, nt.Level = fmt.Sprintf("Certificate expires in %d days", int(days)), notifykit.Warn
		nt.Body = str("profile") + " " + str("platform") + " " + str("signer") + ", until " + str("notAfter") + "\nimpr cert list"
	case "cert.expired":
		nt.Title, nt.Level, nt.Sound = "Certificate expired", notifykit.Alert, true
		nt.Body = str("profile") + " " + str("platform") + " " + str("signer") + ", on " + str("notAfter") + "\nimpr cert list"
	default:
		return notifykit.Notification{}, false
	}
	return nt, true
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	if len(s) > 160 {
		s = s[:157] + "..."
	}
	return s
}

func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\n' {
			return -1
		}
		return r
	}, s)
}

// short names a subject by its last path element: a repository's name, not
// its URL.
func short(s string) string {
	s = strings.TrimSuffix(strings.TrimRight(s, "/"), ".git")
	if i := strings.LastIndexAny(s, "/:"); i >= 0 {
		s = s[i+1:]
	}
	return clean(s)
}

// DefaultExpiryDays are the warning thresholds when the config names none.
var DefaultExpiryDays = []int{30, 14, 7}

// Cert is one certificate the expiry check looks at.
type Cert struct {
	Profile, Platform, Signer string
	NotAfter                  time.Time
}

// Key names a certificate across runs; a renewed one (a new notAfter) is a
// new key, so its warnings start again.
func (c Cert) Key() string {
	return c.Profile + "|" + c.Platform + "|" + c.Signer + "|" + c.NotAfter.UTC().Format(time.RFC3339)
}

// Expiry decides which cert.expiring and cert.expired events to raise,
// once per threshold per certificate: the state file remembers the lowest
// threshold already raised, so running impr cert list every hour does not
// repeat a warning.
type Expiry struct {
	StateFile string
	Days      []int
	Now       func() time.Time
}

// Due returns the events to raise now and records them.
func (x Expiry) Due(certs []Cert) ([]ExpiryEvent, error) {
	days := x.Days
	if len(days) == 0 {
		days = DefaultExpiryDays
	}
	seen := map[string]int{}
	if b, err := os.ReadFile(x.StateFile); err == nil {
		_ = json.Unmarshal(b, &seen)
	}
	now := x.Now()
	var out []ExpiryEvent
	for _, c := range certs {
		if c.NotAfter.IsZero() {
			continue
		}
		left := int(c.NotAfter.Sub(now).Hours() / 24)
		k := c.Key()
		last, raised := seen[k]
		switch {
		case !now.Before(c.NotAfter):
			if !raised || last != -1 {
				out = append(out, ExpiryEvent{Cert: c, Expired: true})
				seen[k] = -1
			}
		default:
			// The smallest threshold the certificate is within.
			hit := 0
			for _, d := range days {
				if left <= d && (hit == 0 || d < hit) {
					hit = d
				}
			}
			if hit > 0 && (!raised || (last > 0 && hit < last)) {
				out = append(out, ExpiryEvent{Cert: c, Days: left, Threshold: hit})
				seen[k] = hit
			}
		}
	}
	if len(out) > 0 {
		if err := os.MkdirAll(filepath.Dir(x.StateFile), 0o700); err != nil {
			return out, err
		}
		b, _ := json.Marshal(seen)
		if err := os.WriteFile(x.StateFile, b, 0o600); err != nil {
			return out, err
		}
	}
	return out, nil
}

// ExpiryEvent is one warning to raise.
type ExpiryEvent struct {
	Cert      Cert
	Expired   bool
	Days      int
	Threshold int
}

// Type is the event's short type.
func (e ExpiryEvent) Type() string {
	if e.Expired {
		return "cert.expired"
	}
	return "cert.expiring"
}

// Data is the event's data.
func (e ExpiryEvent) Data() map[string]any {
	d := map[string]any{"profile": e.Cert.Profile, "platform": e.Cert.Platform, "notAfter": e.Cert.NotAfter.UTC().Format(time.RFC3339)}
	if e.Cert.Signer != "" {
		d["signer"] = e.Cert.Signer
	}
	if !e.Expired {
		d["days"], d["threshold"] = e.Days, e.Threshold
	}
	return d
}
