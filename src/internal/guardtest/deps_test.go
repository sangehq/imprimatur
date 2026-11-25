package guardtest

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// allowedModules are the only modules impr may depend on, each an owner
// decision: go-notifykit (estate rule, desktop notifications) and
// golang.org/x/sys (2026-11-17: the macOS socket peer check and the Windows
// named pipe). A new dependency is a decision too, so it fails here first.
//
// Design ID-36 (owner, 2026-11-25: "quill signing + stdlib notary"): macOS
// Developer ID signing off a Mac uses anchore/quill's code-signing packages
// only, never its notary client (the AWS SDK) or its CLI (a TUI); the notary
// API is impr's own standard-library client. Measured 2026-11-25 with
// go list -deps ./cmd/impr: 12 modules compiled in, up from 2, all Apache-2.0,
// MIT, ISC or BSD; the binary (-trimpath -s -w) grew from 13,692,114 to
// 14,593,282 bytes. quill's own modules and what they pull:
var allowedModules = []string{"github.com/simtabi/go-notifykit/src", "golang.org/x/sys",
	"github.com/anchore/quill",           // Apache-2.0: Mach-O code directory, CMS signature, .p12 signing material
	"github.com/anchore/go-macholibre",   // Apache-2.0: split and repack a universal binary
	"github.com/anchore/go-logger",       // Apache-2.0: quill's logging interface
	"github.com/github/smimesign",        // MIT: the CMS (PKCS#7) signature and its RFC 3161 time-stamp
	"software.sslmate.com/src/go-pkcs12", // BSD-3-Clause: reading the .p12
	"golang.org/x/crypto",                // BSD-3-Clause: go-pkcs12's ciphers
	"github.com/go-restruct/restruct",    // ISC: quill's Mach-O structures
	"github.com/google/uuid",             // BSD-3-Clause: via go-logger
	"github.com/pkg/errors",              // BSD-2-Clause: via smimesign
	"github.com/scylladb/go-set",         // Apache-2.0: via quill
}

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
	for _, m := range bannedIn(got) {
		t.Errorf("go.mod requires %s; ID-36 allows quill's signing packages only", m)
	}
	if len(bannedIn([]string{"github.com/aws/aws-sdk-go-v2", "github.com/charmbracelet/bubbletea", "golang.org/x/sys"})) != 2 {
		t.Fatal("the ID-36 check cannot see the AWS SDK or a terminal UI")
	}
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

// bannedIn is what ID-36 keeps out: the AWS SDK quill's notary client needs,
// and the terminal UI its CLI uses.
func bannedIn(mods []string) []string {
	var out []string
	for _, m := range mods {
		for _, banned := range []string{"github.com/aws/", "github.com/charmbracelet/", "github.com/spf13/cobra"} {
			if strings.HasPrefix(m, banned) {
				out = append(out, m)
			}
		}
	}
	return out
}
