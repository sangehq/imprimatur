package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sangehq/imprimatur/src/internal/capped"
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

// publicKeys decodes an endpoint's v1a public keys; config validation has
// already checked their shape.
func publicKeys(ep *config.Inbound) ([]ed25519.PublicKey, error) {
	var out []ed25519.PublicKey
	for _, s := range []string{ep.PublicKey, ep.PreviousPublicKey} {
		if s == "" {
			continue
		}
		k, err := webhook.DecodePublicKey(s)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, nil
}

func verifySig(h http.Header, body []byte, keys [][]byte, public []ed25519.PublicKey, now time.Time, tol time.Duration) (string, error) {
	return webhook.VerifyWith(h, body, keys, public, now, tol)
}

// ledger records inbound delivery ids already processed, persisted so a
// restart does not reopen the replay window (sange G-10). It fails closed: a
// ledger it cannot read, or a claim it cannot write, refuses the delivery
// (security review R8).
type ledger struct {
	path   string
	now    func() time.Time
	mu     sync.Mutex
	seen   map[string]time.Time // id -> expiry
	broken error                // the ledger on disk could not be read
}

func newLedger(path string, now func() time.Time) *ledger {
	l := &ledger{path: path, now: now, seen: map[string]time.Time{}}
	b, err := capped.ReadFile(path, capped.Manifest)
	switch {
	case err == nil:
		if err := json.Unmarshal(b, &l.seen); err != nil {
			l.broken = fmt.Errorf("the replay ledger %s cannot be read: %w", path, err)
		}
	case !os.IsNotExist(err):
		l.broken = fmt.Errorf("the replay ledger %s cannot be read: %w", path, err)
	}
	return l
}

// claim records id until now+keep and reports whether it was new. An error
// means the delivery must be refused: the ledger cannot say it is new, or
// cannot remember it.
func (l *ledger) claim(id string, keep time.Duration) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.broken != nil {
		return false, l.broken
	}
	now := l.now()
	for k, exp := range l.seen {
		if now.After(exp) {
			delete(l.seen, k)
		}
	}
	if _, dup := l.seen[id]; dup {
		return false, nil
	}
	l.seen[id] = now.Add(keep)
	if l.path == "" {
		return true, nil
	}
	if err := l.persist(); err != nil {
		delete(l.seen, id)
		return false, err
	}
	return true, nil
}

// persist writes the ledger through a temporary file of its own, then renames
// it into place.
func (l *ledger) persist() error {
	b, err := json.Marshal(l.seen)
	if err != nil {
		return err
	}
	dir := filepath.Dir(l.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("the replay ledger cannot be written: %w", err)
	}
	f, err := os.CreateTemp(dir, ".replay-*.tmp")
	if err != nil {
		return fmt.Errorf("the replay ledger cannot be written: %w", err)
	}
	tmp := f.Name()
	_, werr := f.Write(b)
	cerr := f.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("the replay ledger cannot be written: %w", errors.Join(werr, cerr))
	}
	if err := os.Rename(tmp, l.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("the replay ledger cannot be written: %w", err)
	}
	return nil
}
