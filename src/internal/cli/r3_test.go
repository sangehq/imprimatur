package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Security review R3: a committed LICENSE that is a symbolic link would put its
// target (a private key, say) into every release archive. It is refused.
func TestArchiveRefusesSymlinkedExtras(t *testing.T) {
	repo := goRepo(t)
	secret := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(secret, []byte("PRIVATE KEY MATERIAL\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(repo, "LICENSE")); err != nil {
		t.Fatal(err)
	}
	gitIn(t, repo, "add", ".")
	gitIn(t, repo, "commit", "-q", "-m", "license")
	h := newHarness(t)
	code, _, out := h.impr("build", "--repo-root", repo, "--targets", "linux/amd64", "--version", "v1.0.0", "--archives")
	if code != 1 || !strings.Contains(out, "LICENSE") || !strings.Contains(out, "symbolic link") {
		t.Fatalf("a symlinked LICENSE: exit %d %s", code, out)
	}
	if _, err := os.Stat(filepath.Join(repo, "build", "archives", "hello_linux_amd64.tar.gz")); !os.IsNotExist(err) {
		t.Fatalf("an archive was written: %v", err)
	}
}

// Security review R3: a committed build folder that is a symbolic link would
// make the build write, and --clean delete, outside the repository.
func TestBuildRefusesASymlinkedBuildDir(t *testing.T) {
	for _, link := range []string{"build", "build/linux"} {
		t.Run(link, func(t *testing.T) {
			repo := goRepo(t)
			elsewhere := t.TempDir()
			victim := filepath.Join(elsewhere, "hello_linux_amd64")
			if err := os.WriteFile(victim, []byte("keep me"), 0o600); err != nil {
				t.Fatal(err)
			}
			if link == "build" {
				if err := os.RemoveAll(filepath.Join(repo, "build")); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(elsewhere, filepath.Join(repo, filepath.FromSlash(link))); err != nil {
				t.Fatal(err)
			}
			gitIn(t, repo, "add", ".")
			gitIn(t, repo, "commit", "-q", "-m", "build link")
			h := newHarness(t)
			code, _, out := h.impr("build", "--repo-root", repo, "--targets", "linux/amd64", "--version", "v1.0.0", "--clean")
			if code != 1 || !strings.Contains(out, "symbolic link") {
				t.Fatalf("a symlinked %s: exit %d %s", link, code, out)
			}
			if b, err := os.ReadFile(victim); err != nil || string(b) != "keep me" {
				t.Fatalf("a file outside the repository was touched: %q %v", b, err)
			}
		})
	}
}

// Security review R3: --clean never deletes through a linked build/{os} folder
// of an OS the build does not target.
func TestCleanSkipsALinkedFolderOfAnotherOS(t *testing.T) {
	repo := goRepo(t)
	elsewhere := t.TempDir()
	victim := filepath.Join(elsewhere, "hello_windows_amd64.exe")
	if err := os.WriteFile(victim, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(repo, "build", "windows")); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t)
	h.ok("build", "--repo-root", repo, "--targets", "linux/amd64", "--version", "v1.0.0", "--clean", "--allow-dirty")
	if b, err := os.ReadFile(victim); err != nil || string(b) != "keep me" {
		t.Fatalf("--clean deleted through a link: %q %v", b, err)
	}
}
