package cli

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func tarNames(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // G304: a test archive
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		names = append(names, h.Name)
	}
	return names
}

// ID-12, O-18, O-145: impr build --archives writes a .tar.gz per non-Windows
// binary and a .zip per Windows one under build/archives/, version-less and
// holding the binary under its flat name plus LICENSE and README, with a
// checksums.txt of bare names, as the estate build layout says.
func TestBuildArchives(t *testing.T) {
	repo := goRepo(t)
	for _, f := range []string{"LICENSE", "README.md"} {
		if err := os.WriteFile(filepath.Join(repo, f), []byte(f+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	gitIn(t, repo, "add", ".")
	gitIn(t, repo, "commit", "-q", "-m", "docs")
	h := newHarness(t)
	h.ok("build", "--repo-root", repo, "--targets", "linux/amd64,windows/amd64", "--version", "v1.0.0", "--archives")
	dir := filepath.Join(repo, "build", "archives")
	if got := tarNames(t, filepath.Join(dir, "hello_linux_amd64.tar.gz")); !slices.Contains(got, "hello_linux_amd64") ||
		!slices.Contains(got, "LICENSE") || !slices.Contains(got, "README.md") {
		t.Fatalf("tar.gz holds %v", got)
	}
	zr, err := zip.OpenReader(filepath.Join(dir, "hello_windows_amd64.zip"))
	if err != nil {
		t.Fatal(err)
	}
	var zn []string
	for _, f := range zr.File {
		zn = append(zn, f.Name)
	}
	_ = zr.Close()
	if !slices.Contains(zn, "hello_windows_amd64.exe") || !slices.Contains(zn, "LICENSE") {
		t.Fatalf("zip holds %v", zn)
	}
	sums, err := os.ReadFile(filepath.Join(dir, "checksums.txt"))
	if err != nil || !strings.Contains(string(sums), "  hello_linux_amd64.tar.gz\n") || !strings.Contains(string(sums), "  hello_windows_amd64.zip\n") {
		t.Fatalf("checksums.txt: %s %v", sums, err)
	}
	// Without --archives, nothing is archived.
	repo2 := goRepo(t)
	h.ok("build", "--repo-root", repo2, "--targets", "linux/amd64")
	if _, err := os.Stat(filepath.Join(repo2, "build", "archives")); !os.IsNotExist(err) {
		t.Fatalf("archives written without --archives: %v", err)
	}
}

// ID-12, O-145: on macOS, --archives with both darwin targets adds a
// universal binary, listed in the build manifest so it is signed too.
func TestBuildUniversalMacOSBinary(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("lipo runs on macOS only")
	}
	if _, err := exec.LookPath("lipo"); err != nil {
		t.Skip("needs lipo")
	}
	repo := goRepo(t)
	h := newHarness(t)
	var r BuildResult
	if err := json.Unmarshal([]byte(h.ok("build", "--repo-root", repo, "--targets", "darwin/amd64,darwin/arm64", "--version", "v1.0.0", "--archives", "--json")), &r); err != nil {
		t.Fatal(err)
	}
	uni := "build/macos/hello_macos_universal"
	found := false
	for _, a := range r.Manifest.Artifacts {
		found = found || a.Path == uni
	}
	if !found {
		t.Fatalf("the universal binary is not in the manifest: %+v", r.Manifest.Artifacts)
	}
	out, err := exec.Command("lipo", "-archs", filepath.Join(repo, filepath.FromSlash(uni))).Output()
	if err != nil || !strings.Contains(string(out), "x86_64") || !strings.Contains(string(out), "arm64") {
		t.Fatalf("lipo -archs: %s %v", out, err)
	}
	if _, err := os.Stat(filepath.Join(repo, "build", "archives", "hello_macos_universal.tar.gz")); err != nil {
		t.Fatalf("no archive of the universal binary: %v", err)
	}
}
