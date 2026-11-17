package guardtest

import (
	"fmt"
	"regexp"
	"sort"
	"testing"
)

// shSangeLiteral finds a Go string literal naming the reverse-DNS namespace
// impr used before 2026-11-17. Identifiers moved to com.simtabi.sange.imprimatur
// (owner decision); the old ones survive only as the deprecated constants
// that recognise what an older impr wrote.
var shSangeLiteral = regexp.MustCompile("[\"`]sh\\.sange[^\"`]*[\"`]")

// legacyLiterals is every place an sh.sange literal may stay, each a
// deprecated constant (audits/deprecations.md in the design folder). A new
// identifier must not be added here: use the com.simtabi namespace.
var legacyLiterals = map[string]bool{
	`internal/events/events.go: "sh.sange.imprimatur."`:      true, // LegacyTypePrefix
	`internal/cli/unit.go: "sh.sange.imprimatur.serve"`:      true, // legacyLaunchdLabel
	`internal/cli/unit.go: "sh.sange.imprimatur.cert-check"`: true, // legacyCheckLabel
	`internal/notify/notify.go: "sh.sange.imprimatur"`:       true, // LegacyAppID
}

func shSangeUses(files map[string]string) []string {
	var out []string
	for rel, src := range files {
		for _, m := range shSangeLiteral.FindAllString(src, -1) {
			if k := fmt.Sprintf("%s: %s", rel, m); !legacyLiterals[k] {
				out = append(out, k)
			}
		}
	}
	sort.Strings(out)
	return out
}

// TestNoNewShSangeIdentifiers: the only sh.sange literals in impr's source
// are the deprecated constants that recognise the old names.
func TestNoNewShSangeIdentifiers(t *testing.T) {
	files := sources(t)
	atLeast(t, "Go source files", len(files), 20)
	if got := shSangeUses(files); len(got) > 0 {
		t.Errorf("sh.sange identifiers outside the deprecated constants; use com.simtabi.sange.imprimatur: %v", got)
	}
	// Each allowed literal is still there, so a stale entry fails rather
	// than quietly covering a new use of the same string.
	seen := 0
	for rel, src := range files {
		for _, m := range shSangeLiteral.FindAllString(src, -1) {
			if legacyLiterals[fmt.Sprintf("%s: %s", rel, m)] {
				seen++
			}
		}
	}
	if seen != len(legacyLiterals) {
		t.Errorf("found %d of the %d allowed legacy literals; remove stale entries", seen, len(legacyLiterals))
	}
}

func TestShSangeGuardCanFail(t *testing.T) {
	bad := map[string]string{"internal/x/x.go": "package x\nconst id = \"sh.sange.imprimatur.new\"\n"}
	if got := shSangeUses(bad); len(got) != 1 {
		t.Fatal("the guard missed a new sh.sange identifier")
	}
}
