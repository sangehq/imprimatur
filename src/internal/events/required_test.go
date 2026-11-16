package events

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type failingSink struct{}

func (failingSink) Write(context.Context, Event) error { return errors.New("down") }

func TestRequiredRecordsOnlyEventLogFailures(t *testing.T) {
	blocked := filepath.Join(t.TempDir(), "events")
	if err := os.WriteFile(blocked, nil, 0o600); err != nil { // a file where the log's folder should be
		t.Fatal(err)
	}
	env := Env{Now: time.Now, NewID: NewID, InstallID: "0123456789abcdef"}

	// Another sink failing is never the log failing.
	b := &Bus{Env: env, Required: true, Sinks: []Sink{Log{Dir: t.TempDir()}, failingSink{}}}
	b.Emit(context.Background(), "config.changed", "s", map[string]any{})
	if b.Err() != nil {
		t.Fatalf("a webhook-style failure counted: %v", b.Err())
	}

	// Without Required, a log failure is a warning only.
	b = &Bus{Env: env, Sinks: []Sink{Log{Dir: blocked}}}
	b.Emit(context.Background(), "config.changed", "s", map[string]any{})
	if b.Err() != nil {
		t.Fatalf("not required, but: %v", b.Err())
	}

	b = &Bus{Env: env, Required: true, Sinks: []Sink{Log{Dir: blocked}}}
	b.Emit(context.Background(), "config.changed", "s", map[string]any{})
	if b.Err() == nil {
		t.Fatal("a log failure under Required was not recorded")
	}
	if (*Bus)(nil).Err() != nil {
		t.Fatal("a nil bus has an error")
	}
}
