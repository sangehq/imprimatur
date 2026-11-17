package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sangehq/imprimatur/src/internal/config"
)

// W2: Main runs impr on the real host; version is the build's.
func TestMainAndVersion(t *testing.T) {
	t.Setenv("IMPR_CONFIG_DIR", t.TempDir())
	t.Setenv("IMPR_STATE_DIR", t.TempDir())
	t.Setenv("IMPR_LEGACY_CONFIG", "off")
	if code := Main([]string{"version"}); code != 0 {
		t.Fatalf("Main version: %d", code)
	}
	if Version() != version {
		t.Fatal("Version")
	}
	_ = stdinIsTerminal() // a pipe or a terminal; under go test, never panics
}

// W2: a running impr serve anchors every audit.anchor.everyHours, else 6h.
func TestAnchorEvery(t *testing.T) {
	var c config.Config
	if anchorEvery(c) != 6*time.Hour {
		t.Error("default")
	}
	c.Audit.Anchor.EveryHours = 2
	if anchorEvery(c) != 2*time.Hour {
		t.Error("configured")
	}
}

// W2: logOnly writes the event log directly.
func TestLogOnlyWritesTheEventLog(t *testing.T) {
	h := newHarness(t)
	a := &App{Stderr: os.Stderr, Getenv: func(k string) string { return h.env[k] }, GOOS: h.os, Home: t.TempDir(), Now: time.Now}
	a.logOnly("webhook.delivery.dead", "x", map[string]any{"subscription": "x"})
	files, _ := filepath.Glob(filepath.Join(h.env["IMPR_STATE_DIR"], "events", "*"))
	if len(files) == 0 {
		t.Fatal("no event log written")
	}
}
