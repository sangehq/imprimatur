package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// goModule makes a Go module with the given commands under cmd/, in a git
// work tree (a .git folder) unless noGit.
func goModule(t *testing.T, noGit bool, cmds ...string) string {
	t.Helper()
	root := t.TempDir()
	if !noGit {
		if err := os.MkdirAll(filepath.Join(root, ".git"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/tool\n\ngo 1.23\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range cmds {
		dir := filepath.Join(root, "cmd", c)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// O-36..O-39: impr init sets a project up for impr build, as the PowerShell
// line's init did for GoReleaser: the build targets the old template built
// (build/targets.txt in place of .goreleaser.yaml), the build output kept out
// of git, the program chosen with --main when there are several, and --force
// to start the targets over. It never writes .goreleaser.yaml (ID-09).
func TestInitSetsAProjectUp(t *testing.T) {
	h := newHarness(t)
	root := goModule(t, false, "tool")
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("*.log\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.ok("init", "--repo-root", root)
	targets, err := os.ReadFile(filepath.Join(root, "build", "targets.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"windows amd64", "windows 386", "windows arm64", "linux amd64", "linux arm64", "linux 386", "linux arm 7", "darwin amd64", "darwin arm64"} {
		if !strings.Contains(string(targets), "\n"+want+"\n") {
			t.Errorf("targets.txt lacks %q:\n%s", want, targets)
		}
	}
	gi, _ := os.ReadFile(filepath.Join(root, ".gitignore"))
	for _, want := range []string{"*.log", "# impr build output", "build/*/", "build/build-manifest.json", "zz_impr_winres_windows_*.syso"} {
		if !strings.Contains(string(gi), want) {
			t.Errorf(".gitignore lacks %q:\n%s", want, gi)
		}
	}
	if _, err := os.Stat(filepath.Join(root, ".goreleaser.yaml")); !os.IsNotExist(err) {
		t.Error("init wrote .goreleaser.yaml")
	}
	// Already set up: refused, and the edits kept; --force starts over.
	edited := []byte("# mine\nlinux amd64\n")
	if err := os.WriteFile(filepath.Join(root, "build", "targets.txt"), edited, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := h.impr("init", "--repo-root", root); code != 1 || !strings.Contains(errOut, "already set up") {
		t.Fatalf("a second init: %d %s", code, errOut)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "build", "targets.txt")); string(b) != string(edited) {
		t.Fatal("a refused init changed targets.txt")
	}
	h.ok("init", "--repo-root", root, "--force")
	if b, _ := os.ReadFile(filepath.Join(root, "build", "targets.txt")); !strings.Contains(string(b), "windows arm64") {
		t.Fatal("--force did not start targets.txt over")
	}
	if gi2, _ := os.ReadFile(filepath.Join(root, ".gitignore")); strings.Count(string(gi2), "build/*/") != 1 {
		t.Fatalf(".gitignore lines were added twice:\n%s", gi2)
	}
}

// Several programs need --main, which must name one of them; a module with
// none is refused; a folder that is not a git work tree and has no
// .gitignore gets none.
func TestInitChoosesTheProgram(t *testing.T) {
	h := newHarness(t)
	root := goModule(t, true, "tool", "helper")
	if code, _, errOut := h.impr("init", "--repo-root", root); code != 1 || !strings.Contains(errOut, "--main ./cmd/helper") || !strings.Contains(errOut, "--main ./cmd/tool") {
		t.Fatalf("several programs: %d %s", code, errOut)
	}
	if code, _, _ := h.impr("init", "--repo-root", root, "--main", "./cmd/nope"); code != 1 {
		t.Fatal("an unknown --main was taken")
	}
	_, _, errOut := h.impr("init", "--repo-root", root, "--main", "./cmd/helper")
	if !strings.Contains(errOut, "impr build --main ./cmd/helper") {
		t.Fatalf("the build line does not name the program: %s", errOut)
	}
	if _, err := os.Stat(filepath.Join(root, ".gitignore")); !os.IsNotExist(err) {
		t.Fatal("a .gitignore was made outside a git work tree")
	}
	if code, _, errOut := h.impr("init", "--repo-root", goModule(t, false)); code != 1 || !strings.Contains(errOut, "no program") {
		t.Fatalf("no programs: %d %s", code, errOut)
	}
}

// impr init never writes through a symbolic link: a targets.txt, .gitignore
// or build folder that links outside the project is refused, and the file
// the link points at is left alone, with or without --force.
func TestInitRefusesSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need a privilege on Windows")
	}
	h := newHarness(t)
	outside := filepath.Join(t.TempDir(), "outside.txt")
	const keep = "not impr's\n"
	link := func(t *testing.T, path string) {
		t.Helper()
		if err := os.WriteFile(outside, []byte(keep), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, path); err != nil {
			t.Fatal(err)
		}
	}
	untouched := func(t *testing.T) {
		t.Helper()
		if b, _ := os.ReadFile(outside); string(b) != keep {
			t.Fatalf("the file outside the project was written:\n%s", b)
		}
	}

	t.Run("targets.txt", func(t *testing.T) {
		root := goModule(t, true, "tool")
		link(t, filepath.Join(root, "build", "targets.txt"))
		for _, args := range [][]string{{"init", "--repo-root", root}, {"init", "--repo-root", root, "--force"}} {
			code, _, errOut := h.impr(args...)
			if code != 1 || !strings.Contains(errOut, "symbolic link") {
				t.Fatalf("%v: %d %s", args, code, errOut)
			}
			untouched(t)
		}
	})
	t.Run(".gitignore", func(t *testing.T) {
		root := goModule(t, false, "tool")
		link(t, filepath.Join(root, ".gitignore"))
		code, _, errOut := h.impr("init", "--repo-root", root)
		if code != 1 || !strings.Contains(errOut, "symbolic link") {
			t.Fatalf("%d %s", code, errOut)
		}
		untouched(t)
	})
	t.Run("build folder", func(t *testing.T) {
		root := goModule(t, true, "tool")
		dir := t.TempDir()
		if err := os.Symlink(dir, filepath.Join(root, "build")); err != nil {
			t.Fatal(err)
		}
		code, _, errOut := h.impr("init", "--repo-root", root)
		if code != 1 || !strings.Contains(errOut, "symbolic link") {
			t.Fatalf("%d %s", code, errOut)
		}
		if _, err := os.Stat(filepath.Join(dir, "targets.txt")); !os.IsNotExist(err) {
			t.Fatal("targets.txt was written through the linked build folder")
		}
	})
}
