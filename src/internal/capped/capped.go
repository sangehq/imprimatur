// Package capped reads the files impr parses, refusing one larger than its
// cap, so a crafted manifest, record or approval cannot exhaust memory
// (security review I-14).
package capped

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// Caps, in bytes.
const (
	Manifest = 16 << 20 // a build manifest, a signed record, the replay ledger
	Approval = 64 << 10 // an approval document or its signature
)

// ErrTooLarge is returned for a file over its cap.
var ErrTooLarge = errors.New("larger than impr reads")

// ReadFile reads path, refusing it when it holds more than max bytes.
func ReadFile(path string, max int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the callers name impr's own inputs
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s: %w (%d bytes at most)", path, ErrTooLarge, max)
	}
	return b, nil
}
