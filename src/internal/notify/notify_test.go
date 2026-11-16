package notify

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	notifykit "github.com/simtabi/go-notifykit/src"

	"github.com/sangehq/imprimatur/src/internal/events"
)

func event(t *testing.T, short, subject string, data map[string]any) events.Event {
	t.Helper()
	env := events.Env{InstallID: "test", Now: time.Now, NewID: events.NewID}
	ev, err := env.New(short, subject, data)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func TestBannersForWhatAPersonShouldActOn(t *testing.T) {
	for short, want := range map[string]string{
		"signing.run.failed":      "Signing failed",
		"verification.run.failed": "Verification failed",
		"hook.vetoed":             "A hook refused a run",
		"cert.expiring":           "Certificate expires in 12 days",
		"cert.expired":            "Certificate expired",
	} {
		nt, ok := Banner(event(t, short, "git@github.com:acme/tool.git", map[string]any{"reason": "boom\nsecond line", "days": 12,
			"profile": "acme-release", "platform": "checksums", "notAfter": "2026-12-01T00:00:00Z", "phase": "pre-sign"}))
		if !ok || nt.Title != want || nt.Subtitle != "tool" || nt.Group != short+":tool" || strings.Contains(nt.Body, "second line") {
			t.Errorf("%s: %+v %v", short, nt, ok)
		}
		if !strings.Contains(nt.Body, "impr ") {
			t.Errorf("%s: the body must end with the command that shows more: %q", short, nt.Body)
		}
	}
	for _, short := range []string{"signing.run.completed", "server.started", "config.changed"} {
		if _, ok := Banner(event(t, short, "x", map[string]any{})); ok {
			t.Errorf("%s must not show a banner", short)
		}
	}
}

func TestSinkSendsThroughNotifykit(t *testing.T) {
	rec := &notifykit.Recorder{}
	cfg := Config(t.TempDir(), false, nil, func(string) string { return "" })
	cfg.Backend = rec
	n, err := notifykit.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := Sink{N: n}
	_ = s.Write(context.Background(), event(t, "signing.run.completed", "x", map[string]any{}))
	_ = s.Write(context.Background(), event(t, "signing.run.failed", "acme/tool", map[string]any{"reason": "no key"}))
	if sent := rec.Sent(); len(sent) != 1 || sent[0].Title != "Signing failed" {
		t.Fatalf("sent %+v", sent)
	}
}

func TestExpiryRaisesEachThresholdOnce(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	x := Expiry{StateFile: filepath.Join(t.TempDir(), "expiry.json"), Now: func() time.Time { return now }}
	c := Cert{Profile: "acme-release", Platform: "windows", Signer: "ev-2026", NotAfter: now.Add(40 * 24 * time.Hour)}
	step := func(days float64, want string) {
		t.Helper()
		now = c.NotAfter.Add(-time.Duration(days * 24 * float64(time.Hour)))
		due, err := x.Due([]Cert{c})
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, e := range due {
			d, _ := json.Marshal(e.Data())
			got = append(got, e.Type()+string(d))
		}
		joined := strings.Join(got, ",")
		if (want == "" && joined != "") || (want != "" && !strings.Contains(joined, want)) {
			t.Fatalf("%.1f days left: got %q, want %q", days, joined, want)
		}
	}
	step(40, "")                                      // outside every threshold
	step(29.5, `"threshold":30`)                      // crosses 30
	step(20, "")                                      // still 30: not again
	step(13.5, `"threshold":14`)                      // crosses 14
	step(6.5, `"threshold":7`)                        // crosses 7
	step(3, "")                                       // nothing lower
	step(-0.1, "cert.expired")                        // expired
	step(-5, "")                                      // expired once
	c.NotAfter = c.NotAfter.Add(365 * 24 * time.Hour) // renewed: a new certificate
	step(25, `"threshold":30`)
}
