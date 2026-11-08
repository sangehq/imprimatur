// Package guardtest holds repository guard tests: checks on the shape of the
// tree, the build layout, the docs and the CI workflows rather than on any
// feature. Every guard counts what it inspected and fails below a floor, and
// each has a negative control proving it can fail.
package guardtest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const modulePath = "github.com/sangehq/imprimatur/src"

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(root, "src", "go.mod"))
	if err != nil {
		t.Fatalf("repository root not found from the test directory: %v", err)
	}
	if !strings.Contains(string(b), "module "+modulePath) {
		t.Fatalf("src/go.mod does not declare module %s", modulePath)
	}
	return root
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func atLeast(t *testing.T, what string, got, floor int) {
	t.Helper()
	if got < floor {
		t.Fatalf("inspected %d %s, below the floor of %d: the search has stopped matching", got, what, floor)
	}
	t.Logf("inspected %d %s (floor %d)", got, what, floor)
}
