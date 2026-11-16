package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sangehq/imprimatur/src/internal/events"
)

// lockedBuffer lets the test read what a running command has written.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func TestEventsTailFollowPrintsNewMatchingEvents(t *testing.T) {
	h := newHarness(t)
	if code, _, stderr := h.impr("events", "tail", "--follow", "--json"); code != 1 || !strings.Contains(stderr, "one document") {
		t.Fatalf("--follow --json: exit %d, %s", code, stderr)
	}

	log := events.Log{Dir: filepath.Join(h.env["IMPR_STATE_DIR"], "events")}
	env := events.Env{Now: time.Now, NewID: events.NewID, InstallID: "0123456789abcdef"}
	write := func(short, subject string) {
		ev, err := env.New(short, subject, map[string]any{})
		if err != nil {
			t.Fatal(err)
		}
		if err := log.Write(context.Background(), ev); err != nil {
			t.Fatal(err)
		}
	}
	write("profile.created", "before")

	old := followEvery
	followEvery = 10 * time.Millisecond
	defer func() { followEvery = old }()
	var errOut lockedBuffer
	a := &App{Stdout: &lockedBuffer{}, Stderr: &errOut, Getenv: func(k string) string { return h.env[k] }, GOOS: h.os,
		Home: t.TempDir(), User: "tester", Runner: h.run, Now: time.Now}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int)
	go func() { done <- a.Run(ctx, []string{"events", "tail", "--follow", "--type", "profile.*"}) }()

	waitFor := func(s string) {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
			if strings.Contains(errOut.String(), s) {
				return
			}
		}
		t.Fatalf("%q never printed:\n%s", s, errOut.String())
	}
	waitFor("before")
	write("config.changed", "not-a-profile")
	write("profile.removed", "after")
	waitFor("after")
	time.Sleep(5 * followEvery) // a cursor that did not advance would print it again
	cancel()
	if code := <-done; code != 0 && code != 130 {
		t.Fatalf("exit %d", code)
	}
	if strings.Contains(errOut.String(), "not-a-profile") || strings.Count(errOut.String(), "before") != 1 || strings.Count(errOut.String(), "after") != 1 {
		t.Fatalf("follow output:\n%s", errOut.String())
	}
}
