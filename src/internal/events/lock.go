package events

import (
	"os"
	"path/filepath"
	"sync"
)

// Writers in one process take a mutex per log folder; writers in different
// processes (impr serve and a CLI run) take an exclusive lock on the folder's
// .lock file, so no two of them read the chain's last hash and append at once
// (security review R9).
var dirLocks sync.Map // dir -> *sync.Mutex

// lock holds the log folder's lock until the returned function is called.
func (l Log) lock() (func(), error) {
	m, _ := dirLocks.LoadOrStore(filepath.Clean(l.Dir), &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	f, err := os.OpenFile(filepath.Join(l.Dir, ".lock"), os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // G304: impr's own lock file
	if err != nil {
		mu.Unlock()
		return nil, err
	}
	if err := lockFile(f); err != nil {
		_ = f.Close()
		mu.Unlock()
		return nil, err
	}
	return func() {
		_ = unlockFile(f)
		_ = f.Close()
		mu.Unlock()
	}, nil
}
