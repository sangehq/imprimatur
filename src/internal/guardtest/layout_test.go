package guardtest

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var osFolders = map[string]bool{"macos": true, "linux": true, "windows": true, "freebsd": true, "archives": true}

// buildProblems checks build/ holds only targets.txt, checksums.txt and one
// folder per OS (plus archives/), with no subfolder in an OS folder. It also
// returns how many files it inspected: those at the root and in each OS folder.
func buildProblems(dir string) ([]string, int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []string{err.Error()}, 0
	}
	var p []string
	n := 0
	for _, e := range entries {
		name := e.Name()
		switch {
		case name == ".DS_Store":
		case !e.IsDir() && (name == "targets.txt" || name == "checksums.txt"):
			n++
		case e.IsDir() && osFolders[name]:
			sub, _ := os.ReadDir(filepath.Join(dir, name))
			for _, s := range sub {
				switch {
				case s.IsDir():
					p = append(p, "build/"+name+"/"+s.Name()+" is a folder")
				case s.Name() != ".DS_Store":
					n++
				}
			}
		default:
			p = append(p, "build/"+name+" does not belong in build/")
		}
	}
	return p, n
}

// buildFloor is the fewest files build/ must hold: BUILD_LAYOUT_MIN, which the
// Makefile sets to what the build that just ran wrote, else 1 (targets.txt).
func buildFloor(t *testing.T) int {
	t.Helper()
	raw := os.Getenv("BUILD_LAYOUT_MIN")
	if raw == "" {
		return 1
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		t.Fatalf("BUILD_LAYOUT_MIN=%q is not a positive number", raw)
	}
	return n
}

// `make check-build` runs this after every build, with BUILD_LAYOUT_MIN set to
// what that build wrote.
func TestBuildLayout(t *testing.T) {
	dir := filepath.Join(repoRoot(t), "build")
	if _, err := os.Stat(filepath.Join(dir, "targets.txt")); err != nil {
		t.Fatal("build/targets.txt is missing")
	}
	problems, n := buildProblems(dir)
	for _, p := range problems {
		t.Error(p)
	}
	atLeast(t, "files in build/", n, buildFloor(t))
}

func TestBuildLayoutCanFail(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "targets.txt"), nil, 0o600)
	_ = os.MkdirAll(filepath.Join(dir, "dist"), 0o750)
	_ = os.MkdirAll(filepath.Join(dir, "macos", "impr_macos_arm64"), 0o750)
	if p, _ := buildProblems(dir); len(p) != 2 {
		t.Fatalf("got %v", p)
	}
}

// The count is what the floor stands on, so it has to count what is there.
func TestBuildLayoutCountsWhatItInspected(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"targets.txt", "checksums.txt", ".DS_Store", "macos/impr_macos_arm64", "linux/impr_linux_amd64"} {
		p := filepath.Join(dir, filepath.FromSlash(f))
		_ = os.MkdirAll(filepath.Dir(p), 0o750)
		_ = os.WriteFile(p, nil, 0o600)
	}
	if p, n := buildProblems(dir); len(p) != 0 || n != 4 {
		t.Fatalf("got problems %v and %d files, want none and 4", p, n)
	}
}

var footerRe = regexp.MustCompile(`\[← Docs index\]\((\.\./)+README\.md#documentation\)`)

// docProblems checks one docs page: its title first, and the index footer
// exactly once at the depth its path needs.
func docProblems(rel, text string) []string {
	var p []string
	if !strings.HasPrefix(text, "# ") {
		p = append(p, rel+" does not open with its # title")
	}
	m := footerRe.FindAllString(text, -1)
	want := "../README.md#documentation"
	if strings.Count(rel, "/") == 2 {
		want = "../../README.md#documentation"
	}
	if len(m) != 1 || !strings.Contains(m[0], "("+want+")") {
		p = append(p, rel+": want the footer [← Docs index]("+want+") exactly once")
	}
	return p
}

func TestDocsPages(t *testing.T) {
	root := repoRoot(t)
	n := 0
	err := filepath.Walk(filepath.Join(root, "docs"), func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(p, ".md") {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if rel == "docs/README.md" {
			t.Error("docs/README.md must not exist: the index is the README's Documentation section")
		}
		n++
		for _, x := range docProblems(rel, readFile(t, p)) {
			t.Error(x)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	atLeast(t, "docs pages", n, 12)
	readme := readFile(t, filepath.Join(root, "README.md"))
	for _, h := range []string{"## Quick start guide and usage", "### Getting started", "### Usage", `## <a name="documentation"></a>Documentation`} {
		if !strings.Contains(readme, h) {
			t.Errorf("README.md has no %q", h)
		}
	}
}

func TestDocsGuardCanFail(t *testing.T) {
	if len(docProblems("docs/tools/x.md", "# X\n\n[← Docs index](../README.md#documentation)\n")) == 0 {
		t.Error("a tools page with a top-level footer passed")
	}
	if len(docProblems("docs/x.md", "[← Docs index](../README.md#documentation)\n# X\n[← Docs index](../README.md#documentation)\n")) == 0 {
		t.Error("a page with a breadcrumb and a footer passed")
	}
}
