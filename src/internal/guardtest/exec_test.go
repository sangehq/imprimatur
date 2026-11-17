package guardtest

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// execImporters lists the non-test Go files that import os/exec, by
// slash path relative to src/.
func execImporters(t *testing.T, files map[string]string) []string {
	t.Helper()
	var out []string
	for rel, src := range files {
		f, err := parser.ParseFile(token.NewFileSet(), rel, src, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		for _, im := range f.Imports {
			if p, _ := strconv.Unquote(im.Path.Value); p == "os/exec" {
				out = append(out, rel)
			}
		}
	}
	return out
}

func sources(t *testing.T) map[string]string {
	t.Helper()
	src := filepath.Join(repoRoot(t), "src")
	files := map[string]string{}
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(src, p)
		files[filepath.ToSlash(rel)] = readFile(t, p)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// TestOnlyExecxRunsPrograms: every external tool goes through the one
// allow-listed adapter.
func TestOnlyExecxRunsPrograms(t *testing.T) {
	files := sources(t)
	atLeast(t, "Go source files", len(files), 20)
	for _, f := range execImporters(t, files) {
		if !strings.HasPrefix(f, "internal/execx/") {
			t.Errorf("%s imports os/exec; run tools through internal/execx", f)
		}
	}
}

func TestExecGuardCanFail(t *testing.T) {
	bad := map[string]string{"internal/backend/x.go": "package backend\nimport \"os/exec\"\nvar _ = exec.Command\n"}
	if got := execImporters(t, bad); len(got) != 1 {
		t.Fatal("the guard missed an os/exec import outside execx")
	}
}
