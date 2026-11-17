package guardtest

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"
)

// allowedModules are the only modules impr may depend on, each an owner
// decision: go-notifykit (estate rule, desktop notifications) and
// golang.org/x/sys (2026-11-17: the macOS socket peer check and the Windows
// named pipe). A new dependency is a decision too, so it fails here first.
var allowedModules = []string{"github.com/simtabi/go-notifykit/src", "golang.org/x/sys"}

var requireLine = regexp.MustCompile(`(?m)^\s*(?:require\s+)?([a-z0-9.\-]+\.[a-z]+/[^\s]+)\s+v\S+`)

func requiredModules(gomod string) []string {
	var out []string
	for _, m := range requireLine.FindAllStringSubmatch(gomod, -1) {
		out = append(out, m[1])
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// TestDependenciesAreTheAllowedOnes: go.mod requires exactly allowedModules.
func TestDependenciesAreTheAllowedOnes(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	got := requiredModules(string(b))
	atLeast(t, "required modules", len(got), len(allowedModules))
	want := slices.Clone(allowedModules)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("go.mod requires %v; the allowed set is %v (adding one is an owner decision)", got, want)
	}

	// The matcher must see a dependency it was not told about.
	extra := string(b) + "\nrequire example.com/extra v1.2.3\n"
	if n := len(requiredModules(extra)); n != len(want)+1 {
		t.Fatalf("the guard cannot see an added module: %d", n)
	}
}
