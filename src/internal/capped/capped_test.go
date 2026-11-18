package capped_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/sangehq/imprimatur/src/internal/approval"
	"github.com/sangehq/imprimatur/src/internal/artifact"
	"github.com/sangehq/imprimatur/src/internal/capped"
)

// Security review I-14: a manifest, record or approval larger than its cap is
// refused before it is read into memory. A sparse file costs no disk.
func TestManifestReadsAreSizeCapped(t *testing.T) {
	dir := t.TempDir()
	big := func(name string, size int64) string {
		t.Helper()
		p := filepath.Join(dir, name)
		f, err := os.Create(p) //nolint:gosec // G304: a test file
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(size); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if _, err := capped.ReadFile(big("a", capped.Manifest+1), capped.Manifest); !errors.Is(err, capped.ErrTooLarge) {
		t.Fatalf("over the cap: %v", err)
	}
	if b, err := capped.ReadFile(big("b", 10), capped.Manifest); err != nil || len(b) != 10 {
		t.Fatalf("under the cap: %d %v", len(b), err)
	}
	if _, err := artifact.ReadManifest(big("build-manifest.json", capped.Manifest+1)); !errors.Is(err, capped.ErrTooLarge) {
		t.Fatalf("a huge build manifest: %v", err)
	}
	p := big("approval.json", capped.Approval+1)
	big("approval.json.sig", 10)
	if _, err := approval.Read(p); !errors.Is(err, capped.ErrTooLarge) {
		t.Fatalf("a huge approval: %v", err)
	}
}
