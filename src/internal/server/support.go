package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sangehq/imprimatur/src/internal/config"
	"github.com/sangehq/imprimatur/src/internal/webhook"
)

func newID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func readAll(r *http.Request) ([]byte, error) { return io.ReadAll(r.Body) }

func (s *server) keys(ctx context.Context, ep *config.Inbound) ([][]byte, error) {
	var keys [][]byte
	for _, ref := range []string{ep.SecretRef, ep.PreviousSecretRef} {
		if ref == "" {
			continue
		}
		v, err := s.o.Secret(ctx, ref)
		if err != nil {
			return nil, err
		}
		k, err := webhook.DecodeSecret(v)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

func verifySig(h http.Header, body []byte, keys [][]byte, now time.Time, tol time.Duration) (string, error) {
	return webhook.Verify(h, body, keys, now, tol)
}

// ledger records inbound delivery ids already processed, persisted so a
// restart does not reopen the replay window (sange G-10).
type ledger struct {
	path string
	now  func() time.Time
	mu   sync.Mutex
	seen map[string]time.Time // id -> expiry
}

func newLedger(path string, now func() time.Time) *ledger {
	l := &ledger{path: path, now: now, seen: map[string]time.Time{}}
	if b, err := os.ReadFile(path); err == nil { //nolint:gosec // G304: impr's own state file
		_ = json.Unmarshal(b, &l.seen)
	}
	return l
}

// claim records id until now+keep and reports whether it was new.
func (l *ledger) claim(id string, keep time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for k, exp := range l.seen {
		if now.After(exp) {
			delete(l.seen, k)
		}
	}
	if _, dup := l.seen[id]; dup {
		return false
	}
	l.seen[id] = now.Add(keep)
	if b, err := json.Marshal(l.seen); err == nil && l.path != "" {
		if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err == nil {
			tmp := l.path + ".tmp"
			if os.WriteFile(tmp, b, 0o600) == nil {
				_ = os.Rename(tmp, l.path)
			}
		}
	}
	return true
}
