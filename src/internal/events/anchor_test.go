package events

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAnchorDetectsRewriteBeforeIt(t *testing.T) {
	l := Log{Dir: t.TempDir()}
	env := Env{InstallID: "test", Now: time.Now, NewID: NewID}
	for i := 0; i < 3; i++ {
		ev, _ := env.New("server.started", "s", map[string]any{"i": i})
		if err := l.Write(context.Background(), ev); err != nil {
			t.Fatal(err)
		}
	}
	h, err := l.Head()
	if err != nil || h.Count != 3 || !strings.HasPrefix(h.Hash, "sha256:") {
		t.Fatalf("head %+v %v", h, err)
	}
	ev, _ := env.New("server.stopped", "s", map[string]any{})
	_ = l.Write(context.Background(), ev)
	if err := l.Matches(h); err != nil {
		t.Fatalf("appending after the anchor must still match: %v", err)
	}
	// Rewrite the whole log consistently (a new chain with its own head file):
	// Verify passes, the anchor does not.
	name := filepath.Join(l.Dir, time.Now().UTC().Format("2006-01")+".jsonl")
	if err := os.Remove(name); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(l.Dir, "head"))
	for i := 0; i < 4; i++ {
		ev, _ := env.New("server.started", "s", map[string]any{"forged": i})
		_ = l.Write(context.Background(), ev)
	}
	if _, err := l.Verify(); err != nil {
		t.Fatalf("a consistent rewrite verifies on its own: %v", err)
	}
	if err := l.Matches(h); err == nil || !strings.Contains(err.Error(), "rewritten") {
		t.Fatalf("the anchor must catch a consistent rewrite: %v", err)
	}
	if err := l.Matches(Head{Hash: h.Hash, Count: 99}); err == nil || !strings.Contains(err.Error(), "removed") {
		t.Fatalf("a shorter log must fail: %v", err)
	}
}
