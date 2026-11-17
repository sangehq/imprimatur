package guardtest

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// requiredFiles are the files the organisation standard requires in every
// repository, by the exact names GitHub's community profile looks up. Each
// carries the text it must contain, so an emptied or wrongly addressed file
// fails as well as a missing one.
var requiredFiles = map[string][]string{
	"README.md":                             {"## <a name=\"documentation\"></a>Documentation"},
	"LICENSE":                               {"MIT License", "Simtabi LLC"},
	"CHANGELOG.md":                          {"## [Unreleased]"},
	"CONTRIBUTING.md":                       {"make check"},
	"SECURITY.md":                           {"security@simtabi.com"},
	"CODE_OF_CONDUCT.md":                    {"Contributor Covenant", "opensource@simtabi.com"},
	".editorconfig":                         {"root = true"},
	".gitignore":                            {".DS_Store"},
	".github/dependabot.yml":                {"package-ecosystem: gomod", "package-ecosystem: github-actions"},
	".github/ISSUE_TEMPLATE/bug_report.yml": {"name: Bug report"},
	".github/ISSUE_TEMPLATE/feature_request.yml": {"name: Feature request"},
	".github/ISSUE_TEMPLATE/config.yml":          {"security@simtabi.com"},
	".github/PULL_REQUEST_TEMPLATE.md":           {"## Summary"},
}

// contains reports whether text holds want. A YAML key: value want matches the
// value bare or quoted, as YAML reads them alike: the Dependabot standard
// writes package-ecosystem: "gomod", which a plain substring check refused.
func contains(text, want string) bool {
	key, val, ok := strings.Cut(want, ": ")
	if !ok || strings.ContainsAny(val, " \t\"'") {
		return strings.Contains(text, want)
	}
	re := regexp.MustCompile(`(?m)^[\t -]*` + regexp.QuoteMeta(key) + `:[ \t]*(?:"` + regexp.QuoteMeta(val) + `"|'` + regexp.QuoteMeta(val) + `'|` + regexp.QuoteMeta(val) + `)[ \t]*(?:#.*)?$`)
	return re.MatchString(text)
}

// communityProblems lists every required file that is missing or lacks its
// expected text under root.
func communityProblems(root string) []string {
	var p []string
	for name, wants := range requiredFiles {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			p = append(p, name+" is missing")
			continue
		}
		for _, w := range wants {
			if !contains(string(b), w) {
				p = append(p, name+" does not contain "+w)
			}
		}
	}
	return p
}

// TestCommunityFiles: the repository carries every file the standard requires.
func TestCommunityFiles(t *testing.T) {
	if len(requiredFiles) < 13 {
		t.Fatalf("only %d required files listed; the list was cut", len(requiredFiles))
	}
	for _, p := range communityProblems(repoRoot(t)) {
		t.Error(p)
	}
}

// TestCommunityGuardCanFail: in a copy with SECURITY.md removed and the code
// of conduct pointing at the wrong address, the guard reports both.
func TestCommunityGuardCanFail(t *testing.T) {
	root := repoRoot(t)
	tmp := t.TempDir()
	for name := range requiredFiles {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(tmp, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
			t.Fatal(err)
		}
		if name == "CODE_OF_CONDUCT.md" {
			b = []byte(strings.ReplaceAll(string(b), "opensource@simtabi.com", "someone@example.invalid"))
		}
		if err := os.WriteFile(dst, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(filepath.Join(tmp, "SECURITY.md")); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(communityProblems(tmp), "\n")
	for _, want := range []string{"SECURITY.md is missing", "CODE_OF_CONDUCT.md does not contain opensource@simtabi.com"} {
		if !strings.Contains(got, want) {
			t.Errorf("guard missed %q; got:\n%s", want, got)
		}
	}
}

// TestContainsReadsYAMLValues: a key: value requirement is met by the value
// bare or quoted, and still refused when the value is another or absent.
func TestContainsReadsYAMLValues(t *testing.T) {
	want := "package-ecosystem: gomod"
	for _, text := range []string{
		"  - package-ecosystem: gomod\n",
		"  - package-ecosystem: \"gomod\"\n",
		"  - package-ecosystem: 'gomod'  # the module\n",
	} {
		if !contains(text, want) {
			t.Errorf("%q refused", text)
		}
	}
	for _, text := range []string{
		"  - package-ecosystem: \"gomodules\"\n",
		"  - package-ecosystem: \"npm\"\n",
		"# package-ecosystem: gomod is not configured\n",
		"",
	} {
		if contains(text, want) {
			t.Errorf("%q accepted", text)
		}
	}
	if !contains("Report it to security@example.invalid", "security@example.invalid") {
		t.Error("a plain substring requirement no longer matches")
	}
}
