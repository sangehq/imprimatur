package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sangehq/imprimatur/src/internal/artifact"
)

// Security review R7 (I-01), end to end with real git: a release's --repo must
// be a remote of the checkout and its commit must be there with --tree.
func TestSignReleaseChecksTheCheckout(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("needs ssh-keygen")
	}
	repo := goRepo(t)
	gitIn(t, repo, "remote", "add", "origin", "git@github.com:acme/tool.git")
	h := newHarness(t)
	key := filepath.Join(t.TempDir(), "k")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	fp, _ := exec.Command("ssh-keygen", "-l", "-E", "sha256", "-f", key).Output()
	h.env["IMPR_K"] = key
	h.ok("profile", "add", "rel", "--scope", "personal", "--owner", "me", "--purpose", "release",
		"--allowed-repo", "github.com/acme/*",
		"--set", "platforms.checksums.kind=ssh", "--set", "platforms.checksums.keyRef=env://IMPR_K",
		"--set", "platforms.checksums.fingerprint="+strings.Fields(string(fp))[1])
	h.ok("build", "--repo-root", repo, "--targets", "linux/amd64", "--version", "v1.0.0")
	manifest := filepath.Join(repo, "build", "build-manifest.json")
	bm, err := artifact.ReadManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(want int, repoURL, tree string) string {
		t.Helper()
		return h.exits(want, "sign", "--json", "--root", repo, "--manifest", manifest, "--commit", bm.Commit, "--tree", tree,
			"--profile", "rel", "--purpose", "release", "--platforms", "checksums", "--repo", repoURL)
	}
	sign(3, "https://github.com/acme/other", bm.Tree)
	sign(3, "https://github.com/acme/tool", strings.Repeat("0", 40))
	sign(0, "https://github.com/acme/tool", bm.Tree)
}

// Security review R7: an untracked source file is part of the build, so the
// work tree is not clean and a build refuses it without --allow-dirty. Build
// output under build/ is not source and does not count.
func TestBuildCountsUntrackedFilesAsUncommitted(t *testing.T) {
	repo := goRepo(t)
	h := newHarness(t)
	h.ok("build", "--repo-root", repo, "--targets", "linux/amd64", "--version", "v1.0.0")
	h.ok("build", "--repo-root", repo, "--targets", "linux/amd64", "--version", "v1.0.0") // its own output is not a change
	extra := filepath.Join(repo, "src", "cmd", "hello", "extra.go")
	if err := os.WriteFile(extra, []byte("package main\n\nfunc init() { version = \"swapped\" }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.exits(1, "build", "--repo-root", repo, "--targets", "linux/amd64", "--version", "v1.0.0")
}
