package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// gitIn runs git in a throwaway repository made by goRepo.
func gitIn(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.invalid"}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
}

// hostBinary is the path of the host build of goRepo's hello command.
func hostBinary(repo string) string {
	os := runtime.GOOS
	if os == "darwin" {
		os = "macos"
	}
	bin := filepath.Join(repo, "build", os, "hello_"+os+"_"+runtime.GOARCH)
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	return bin
}

func runHello(t *testing.T, repo string) string {
	t.Helper()
	got, err := exec.Command(hostBinary(repo)).Output()
	if err != nil {
		t.Fatalf("run the built binary: %v", err)
	}
	return strings.TrimSpace(string(got))
}

func buildJSON(t *testing.T, h *harness, args ...string) BuildResult {
	t.Helper()
	var r BuildResult
	out := h.ok(append(args, "--json")...)
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	return r
}

// O-14, O-22, O-40, O-146: `impr build VERSION` stamps VERSION, as the
// PowerShell build did with -X main.version.
func TestBuildPositionalVersionIsStamped(t *testing.T) {
	repo := goRepo(t)
	h := newHarness(t)
	host := runtime.GOOS + "/" + runtime.GOARCH
	r := buildJSON(t, h, "build", "--repo-root", repo, "--targets", host, "v1.2.3")
	if r.Manifest.Version != "v1.2.3" {
		t.Fatalf("manifest version %q", r.Manifest.Version)
	}
	if got := runHello(t, repo); got != "v1.2.3" {
		t.Fatalf("binary says %q, want v1.2.3", got)
	}
	// Two versions, or a positional that disagrees with --version, is a mistake.
	h.exits(1, "build", "--repo-root", repo, "--targets", host, "v1.2.3", "v1.2.4")
	h.exits(1, "build", "--repo-root", repo, "--targets", host, "--version", "v1.2.3", "v1.2.4")
	h.ok("build", "--repo-root", repo, "--targets", host, "--version", "v1.2.3", "v1.2.3")
}

// --version alone stamps main.version, the PowerShell default, instead of
// stamping nothing.
func TestBuildVersionDefaultsToMainVersion(t *testing.T) {
	repo := goRepo(t)
	h := newHarness(t)
	h.ok("build", "--repo-root", repo, "--targets", runtime.GOOS+"/"+runtime.GOARCH, "--version", "v2.0.0")
	if got := runHello(t, repo); got != "v2.0.0" {
		t.Fatalf("binary says %q, want v2.0.0", got)
	}
}

// A version that never reaches the binary is an error, not a silent
// unversioned build.
func TestBuildRefusesAVersionThatIsNotStamped(t *testing.T) {
	repo := goRepo(t)
	h := newHarness(t)
	code, _, e := h.impr("build", "--repo-root", repo, "--targets", runtime.GOOS+"/"+runtime.GOARCH,
		"--version", "v3.0.0", "--version-var", "main.nothere")
	if code != 1 || !strings.Contains(e, "main.nothere") {
		t.Fatalf("the error does not name the variable: %s", e)
	}
}

// O-23: no version gives the latest v* tag plus -snapshot, or
// v0.0.0-snapshot with a warning when there is no tag.
func TestBuildSnapshotVersionDefault(t *testing.T) {
	repo := goRepo(t)
	h := newHarness(t)
	host := runtime.GOOS + "/" + runtime.GOARCH
	code, out, e := h.impr("build", "--repo-root", repo, "--targets", host, "--json")
	if code != 0 {
		t.Fatalf("exit %d %s", code, e)
	}
	var r BuildResult
	if err := json.Unmarshal([]byte(out), &r); err != nil || r.Manifest.Version != "v0.0.0-snapshot" {
		t.Fatalf("version %q %v", r.Manifest.Version, err)
	}
	if !strings.Contains(e, "no v* tag") {
		t.Fatalf("no warning about the missing tag: %s", e)
	}
	if got := runHello(t, repo); got != "v0.0.0-snapshot" {
		t.Fatalf("binary says %q", got)
	}
	// The estate tags vX.Y.Z and src/vX.Y.Z on one commit; the v* one wins.
	gitIn(t, repo, "tag", "v1.4.0")
	gitIn(t, repo, "tag", "src/v1.4.0")
	r = buildJSON(t, h, "build", "--repo-root", repo, "--targets", host)
	if r.Manifest.Version != "v1.4.0-snapshot" {
		t.Fatalf("version %q, want v1.4.0-snapshot", r.Manifest.Version)
	}
}

// O-45: build only builds. The signing options belong to impr release, and
// build refuses them rather than ignoring them.
func TestBuildRefusesReleaseOnlyOptions(t *testing.T) {
	repo := goRepo(t)
	h := newHarness(t)
	for _, extra := range [][]string{{"--profile", "p"}, {"--purpose", "release"}, {"--platforms", "checksums"}, {"--repo", "git@github.com:a/b.git"}} {
		code, _, e := h.impr(append([]string{"build", "--repo-root", repo}, extra...)...)
		if code != 1 || !strings.Contains(e, "impr release") {
			t.Errorf("%v: the error does not point at impr release: %s", extra, e)
		}
	}
}

// O-22: `impr release VERSION` builds that version.
func TestReleasePositionalVersion(t *testing.T) {
	repo := goRepo(t)
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("needs ssh-keygen")
	}
	h := newHarness(t)
	internalSSHProfile(t, h, "p")
	h.ok("release", "--repo-root", repo, "--targets", runtime.GOOS+"/"+runtime.GOARCH, "--profile", "p",
		"--purpose", "internal", "--platforms", "checksums", "--archives", "v1.5.0")
	b, err := os.ReadFile(filepath.Join(repo, "build", "build-manifest.json"))
	if err != nil || !strings.Contains(string(b), `"version": "v1.5.0"`) {
		t.Fatalf("manifest: %s %v", b, err)
	}
	if got := runHello(t, repo); got != "v1.5.0" {
		t.Fatalf("binary says %q", got)
	}
	// --archives on a release packs the files after signing and verifying.
	if runtime.GOOS == "windows" {
		return // a .zip there, checked by TestBuildArchives
	}
	if names := tarNames(t, filepath.Join(repo, "build", "archives", filepath.Base(hostBinary(repo))+".tar.gz")); len(names) == 0 {
		t.Fatal("release --archives wrote no archive")
	}
}

// internalSSHProfile adds an internal profile that signs checksums with a new SSH key.
func internalSSHProfile(t *testing.T, h *harness, name string) {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("needs ssh-keygen")
	}
	key := filepath.Join(t.TempDir(), "k")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	fpOut, _ := exec.Command("ssh-keygen", "-l", "-E", "sha256", "-f", key).Output()
	h.env["IMPR_K"] = key
	h.ok("profile", "add", name, "--scope", "personal", "--owner", "me", "--purpose", "internal",
		"--set", "platforms.checksums.kind=ssh", "--set", "platforms.checksums.keyRef=env://IMPR_K",
		"--set", "platforms.checksums.fingerprint="+strings.Fields(string(fpOut))[1])
}

// O-150, old bug 3: `impr release --json` prints exactly one document, with
// the build, sign and verify results inside it, on success and on failure.
func TestReleaseJSONIsOneDocument(t *testing.T) {
	repo := goRepo(t)
	h := newHarness(t)
	internalSSHProfile(t, h, "p")
	host := runtime.GOOS + "/" + runtime.GOARCH
	out := h.exits(0, "release", "--repo-root", repo, "--targets", host, "--profile", "p", "--purpose", "internal",
		"--platforms", "checksums", "--json")
	var r ReleaseResult
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if r.Contract != 1 || !r.OK || r.Build.Manifest.Schema != "sange.build-manifest/v1" || len(r.Sign) == 0 || len(r.Verify) == 0 {
		t.Fatalf("release result: %s", out)
	}
	// A test-purpose run with an internal profile fails at sign: still one
	// document, naming the step.
	out = h.exits(3, "release", "--repo-root", repo, "--targets", host, "--profile", "p", "--purpose", "release",
		"--platforms", "checksums", "--json")
	var f ReleaseResult
	if err := json.Unmarshal([]byte(out), &f); err != nil || f.OK || f.Step != "sign" || len(f.Sign) == 0 || len(f.Verify) != 0 {
		t.Fatalf("failed release result: %v %s", err, out)
	}
}
