package guardtest

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var osFolders = map[string]bool{"macos": true, "linux": true, "windows": true, "freebsd": true, "archives": true}

// buildProblems checks build/ holds only targets.txt, checksums.txt and one
// folder per OS (plus archives/), with no subfolder in an OS folder.
func buildProblems(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []string{err.Error()}
	}
	var p []string
	for _, e := range entries {
		n := e.Name()
		switch {
		case !e.IsDir() && (n == "targets.txt" || n == "checksums.txt"):
		case e.IsDir() && osFolders[n]:
			sub, _ := os.ReadDir(filepath.Join(dir, n))
			for _, s := range sub {
				if s.IsDir() {
					p = append(p, "build/"+n+"/"+s.Name()+" is a folder")
				}
			}
		default:
			p = append(p, "build/"+n+" does not belong in build/")
		}
	}
	return p
}

func TestBuildLayout(t *testing.T) {
	dir := filepath.Join(repoRoot(t), "build")
	for _, p := range buildProblems(dir) {
		t.Error(p)
	}
	if _, err := os.Stat(filepath.Join(dir, "targets.txt")); err != nil {
		t.Fatal("build/targets.txt is missing")
	}
}

func TestBuildLayoutCanFail(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "targets.txt"), nil, 0o600)
	_ = os.MkdirAll(filepath.Join(dir, "dist"), 0o750)
	_ = os.MkdirAll(filepath.Join(dir, "macos", "impr_macos_arm64"), 0o750)
	if len(buildProblems(dir)) != 2 {
		t.Fatalf("got %v", buildProblems(dir))
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
