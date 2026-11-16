package events

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTailReadsOnlyCompleteNewLines(t *testing.T) {
	l := Log{Dir: t.TempDir()}
	env := Env{InstallID: "test", Now: time.Now, NewID: NewID}
	write := func(at time.Time, short string) Event {
		t.Helper()
		ev, err := env.New(short, "s", map[string]any{})
		if err != nil {
			t.Fatal(err)
		}
		ev.Time = at
		if err := l.Write(context.Background(), ev); err != nil {
			t.Fatal(err)
		}
		return ev
	}
	oct := time.Date(2026, 10, 31, 23, 0, 0, 0, time.UTC)
	nov := time.Date(2026, 11, 1, 1, 0, 0, 0, time.UTC)
	first := write(oct, "server.started")

	end, err := l.End()
	if err != nil || end.File != "2026-10.jsonl" || end.Offset == 0 {
		t.Fatalf("end %+v %v", end, err)
	}
	if evs, _, _, err := l.Read(end); err != nil || len(evs) != 0 {
		t.Fatalf("nothing is new at the end, got %d %v", len(evs), err)
	}
	second := write(oct, "server.stopped")
	third := write(nov, "server.started") // a new month file
	evs, raws, c, err := l.Read(end)
	if err != nil || len(evs) != 2 || evs[0].ID != second.ID || evs[1].ID != third.ID || len(raws) != 2 {
		t.Fatalf("read %d events %v", len(evs), err)
	}
	if c.File != "2026-11.jsonl" {
		t.Fatalf("the cursor must move to the new month, got %+v", c)
	}

	// A half-written line is not returned until it is complete.
	f, err := os.OpenFile(filepath.Join(l.Dir, "2026-11.jsonl"), os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{"specversion":"1.0","id":"partial"`)
	_ = f.Close()
	if evs, _, c2, err := l.Read(c); err != nil || len(evs) != 0 || c2 != c {
		t.Fatalf("a partial line was read: %d %+v %v", len(evs), c2, err)
	}

	after, ok, err := l.After(first.ID)
	if err != nil || !ok {
		t.Fatalf("after %v %v", ok, err)
	}
	if evs, _, _, _ := l.Read(after); len(evs) != 2 || evs[0].ID != second.ID {
		t.Fatalf("resuming after the first event must give the next two, got %d", len(evs))
	}
	if _, ok, _ := l.After("no-such-id"); ok {
		t.Fatal("an unknown id was found")
	}
}
