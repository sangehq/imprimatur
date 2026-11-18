package server

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Security review R8 (I-10): the replay ledger fails closed. A delivery it
// cannot record durably, or a ledger it cannot read, is refused, never let
// through as new.
func TestLedgerWriteFailureRefusesTheDelivery(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC) }
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	l := newLedger(filepath.Join(blocker, "server", "replay.json"), now) // a file where a folder must be
	if ok, err := l.claim("a", time.Hour); ok || err == nil {
		t.Fatalf("an unwritable ledger accepted a delivery: %v %v", ok, err)
	}

	corrupt := filepath.Join(t.TempDir(), "replay.json")
	if err := os.WriteFile(corrupt, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	l = newLedger(corrupt, now)
	if ok, err := l.claim("a", time.Hour); ok || err == nil {
		t.Fatalf("a corrupt ledger loaded as empty: %v %v", ok, err)
	}

	good := filepath.Join(t.TempDir(), "replay.json")
	l = newLedger(good, now)
	if ok, err := l.claim("a", time.Hour); !ok || err != nil {
		t.Fatalf("a first delivery: %v %v", ok, err)
	}
	if ok, err := newLedger(good, now).claim("a", time.Hour); ok || err != nil {
		t.Fatalf("a replay after a restart: %v %v", ok, err)
	}
}

// Security review R8 (I-10): GitHub signs no timestamp, so a captured
// delivery must stay refused for far longer than a week.
func TestGitHubReplayAfterWindowIsRefused(t *testing.T) {
	at := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	l := newLedger(filepath.Join(t.TempDir(), "replay.json"), func() time.Time { return at })
	if ok, err := l.claim("gh/1", ghReplayWindow); !ok || err != nil {
		t.Fatal(ok, err)
	}
	at = at.Add(180 * 24 * time.Hour)
	if ok, _ := l.claim("gh/1", ghReplayWindow); ok {
		t.Fatal("a GitHub delivery replayed after 180 days")
	}
}
