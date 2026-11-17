package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sangehq/imprimatur/src/internal/execx"
	"github.com/sangehq/imprimatur/src/internal/testpe"
	"github.com/sangehq/imprimatur/src/internal/winres"
)

// O-04: -V, --version and version print the same line.
func TestVersionForms(t *testing.T) {
	h := newHarness(t)
	want := h.ok("version")
	if !strings.HasPrefix(want, "impr ") {
		t.Fatalf("version: %q", want)
	}
	for _, f := range []string{"-V", "--version"} {
		if got := h.ok(f); got != want {
			t.Errorf("%s: %q, want %q", f, got, want)
		}
	}
}

// O-16: every one-letter alias runs its command.
func TestEveryAliasResolves(t *testing.T) {
	n := 0
	for a, full := range aliases {
		n++
		if resolveAlias(a) != full {
			t.Errorf("%s resolves to %s, want %s", a, resolveAlias(a), full)
		}
		if _, ok := commands[full]; !ok && full != "help" {
			t.Errorf("alias %s names no command %s", a, full)
		}
	}
	if n < 6 {
		t.Fatalf("inspected %d aliases, want at least 6", n)
	}
	h := newHarness(t)
	if _, _, e := h.impr("h", "release"); !strings.Contains(e, "impr release") {
		t.Fatalf("h release: %s", e)
	}
}

// sshTestProfile adds profile p signing checksums with a generated ssh key.
func sshTestProfile(t *testing.T, h *harness) {
	t.Helper()
	internalSSHProfile(t, h, "p")
}

// O-63, O-66, O-67: edit refuses a rename, validate exits 1 on an invalid
// profile, and default reads and sets the default.
func TestProfileEditValidateDefault(t *testing.T) {
	h := newHarness(t)
	sshTestProfile(t, h)
	if _, _, e := h.impr("profile", "edit", "p", "--set", "name=q"); !strings.Contains(e, "name") {
		t.Fatalf("rename through --set: %s", e)
	}
	h.exits(1, "profile", "edit", "p", "--set", "name=q")
	h.ok("profile", "validate", "p")
	// An invalid profile on disk (as a hand edit leaves one): validate exits 1.
	b, err := os.ReadFile(writeBrokenProfile(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.env["IMPR_CONFIG_DIR"], "profiles", "broken.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	h.exits(1, "profile", "validate", "broken")
	h.exits(1, "profile", "validate")
	// default: the first profile became it; set, read back, refuse unknown.
	if out := strings.TrimSpace(h.ok("profile", "default")); out != "p" {
		t.Fatalf("default %q", out)
	}
	h.exits(1, "profile", "default", "nope")
}

// O-68: companion takes only info, with no stray words.
func TestCompanionRefusesOthers(t *testing.T) {
	h := newHarness(t)
	h.exits(1, "companion", "frob")
	h.exits(1, "companion", "info", "x")
}

// O-75: config unset removes a key once; path lists the layers.
func TestConfigUnsetAndPath(t *testing.T) {
	h := newHarness(t)
	h.ok("config", "set", "server.listen", "unix")
	h.ok("config", "unset", "server.listen")
	h.exits(1, "config", "unset", "server.listen")
	var paths ConfigPaths
	if err := json.Unmarshal([]byte(h.ok("config", "path", "--json")), &paths); err != nil || len(paths.Layers) == 0 {
		t.Fatalf("config path: %+v %v", paths, err)
	}
}

// S-12: build --clean removes only this binary's earlier files.
func TestBuildCleanRemovesOnlyItsOwnFiles(t *testing.T) {
	repo := goRepo(t)
	h := newHarness(t)
	host := runtime.GOOS + "/" + runtime.GOARCH
	h.ok("build", "--repo-root", repo, "--targets", host)
	osDir := filepath.Dir(hostBinary(repo))
	keep := filepath.Join(osDir, "someone-else.txt")
	stale := filepath.Join(osDir, "hello_freebsd_riscv64")
	for _, f := range []string{keep, stale} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	h.ok("build", "--repo-root", repo, "--targets", host, "--clean")
	if _, err := os.Stat(keep); err != nil {
		t.Error("--clean removed a file that is not this binary's")
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Error("--clean left this binary's earlier file")
	}
}

// O-26: without go, impr build is unavailable (5), not a usage error.
func TestBuildWithoutGoIsUnavailable(t *testing.T) {
	repo := goRepo(t)
	h := newHarness(t)
	h.run = noGo{execx.OS{}}
	code, _, e := h.impr("build", "--repo-root", repo, "--targets", "linux/amd64")
	if code != 5 {
		t.Fatalf("exit %d, want 5\n%s", code, e)
	}
}

// noGo is the real runner on a host without go.
type noGo struct{ execx.OS }

func (n noGo) LookPath(tool string) (string, error) {
	if tool == "go" {
		return "", execx.ErrNotFound
	}
	return n.OS.LookPath(tool)
}

func (n noGo) Run(ctx context.Context, c execx.Cmd) (execx.Result, error) {
	if c.Tool == "go" {
		return execx.Result{}, execx.ErrNotFound
	}
	return n.OS.Run(ctx, c)
}

// O-54, B-10, B-2: verify of loose files, a re-pinned profile failing
// verification, and --strict on a platform this host cannot sign.
func TestVerifyLooseFilesAndARepinnedProfile(t *testing.T) {
	repo := goRepo(t)
	h := newHarness(t)
	sshTestProfile(t, h)
	art := filepath.Join(repo, "dist", "tool.tar.gz")
	if err := os.MkdirAll(filepath.Dir(art), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(art, []byte(randHex(t, 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	var res sangeSignResult
	if err := json.Unmarshal([]byte(h.ok("sign", art, "--root", repo, "--profile", "p", "--purpose", "internal", "--platforms", "checksums", "--json")), &res); err != nil {
		t.Fatal(err)
	}
	sums := filepath.Join(filepath.Dir(res.ManifestPath), "SHA256SUMS")
	h.ok("verify", sums, "--profile", "p", "--root", repo, "--strict")
	// B-2: a Windows platform this host cannot sign: --strict fails 5, not 0.
	if _, err := exec.LookPath("osslsigncode"); err != nil && runtime.GOOS != "windows" {
		h.env["IMPR_PFX"] = filepath.Join(t.TempDir(), "x.pfx")
		h.ok("profile", "edit", "p", "--set", "platforms.windows.kind=authenticode", "--set", "platforms.windows.backend=pfx",
			"--set", "platforms.windows.certRef=env://IMPR_PFX", "--set", "platforms.windows.thumbprint="+strings.Repeat("AB", 20))
		exe, _ := testpe.Signed(t, filepath.Join(repo, "dist"), "tool.exe", pkix.Name{CommonName: "Me"}, testpe.NewCA(t, "CA"))
		h.exits(5, "sign", exe, "--root", repo, "--profile", "p", "--purpose", "internal", "--platforms", "windows", "--strict")
		h.ok("profile", "edit", "p", "--unset", "platforms.windows")
	}
	// B-10: a profile re-pinned to another key fails the record.
	h.ok("profile", "edit", "p", "--set", "platforms.checksums.fingerprint=SHA256:"+strings.Repeat("B", 43))
	h.exits(4, "verify", "--signed", res.ManifestPath, "--root", repo, "--profile", "p", "--strict")
	h.exits(4, "verify", sums, "--profile", "p", "--root", repo, "--strict")
}

// O-43: a package that carries its own .syso keeps it: impr adds no
// version information of its own for that target.
func TestBuildKeepsTheProjectsOwnSyso(t *testing.T) {
	repo := goRepo(t)
	own, err := winres.Syso("amd64", winres.Info{ProductName: "Own Product", FileVersion: "9.9.9.9", ProductVersion: "9.9.9"}, winres.CLIManifest, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "src", "cmd", "hello", "rsrc_windows_amd64.syso"), own, 0o600); err != nil {
		t.Fatal(err)
	}
	gitIn(t, repo, "add", ".")
	gitIn(t, repo, "commit", "-q", "-m", "own syso")
	h := newHarness(t)
	_, _, e := h.impr("build", "--repo-root", repo, "--targets", "windows/amd64", "--version", "v1.0.0", "--product", "Acme")
	if !strings.Contains(e, "has its own rsrc_windows_amd64.syso") {
		t.Fatalf("no note about the project's .syso:\n%s", e)
	}
	v, err := winres.ReadVersion(filepath.Join(repo, "build", "windows", "hello_windows_amd64.exe"))
	if err != nil || v["ProductName"] != "Own Product" {
		t.Fatalf("version info %v %v, want the project's own", v, err)
	}
}

// selfSignedPEM is a certificate named cn, valid until notAfter, as PEM.
func selfSignedPEM(t *testing.T, cn string, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// mixRunner runs some tools for real and the rest through a fake.
type mixRunner struct {
	real map[string]bool
	fake *execx.Fake
}

func (m mixRunner) LookPath(tool string) (string, error) {
	if m.real[tool] {
		return execx.OS{}.LookPath(tool)
	}
	return m.fake.LookPath(tool)
}

func (m mixRunner) Run(ctx context.Context, c execx.Cmd) (execx.Result, error) {
	if m.real[c.Tool] {
		return execx.OS{}.Run(ctx, c)
	}
	return m.fake.Run(ctx, c)
}

// O-140: impr release with a macOS profile builds, signs with codesign under
// the pinned identity, notarises, and records the notarisation.
func TestReleaseSignsMacOSWithTheProfile(t *testing.T) {
	repo := goRepo(t)
	h := newHarness(t)
	h.os = "darwin"
	team := "ABCDE12345"
	ident := "Developer ID Application: Acme Ltd (" + team + ")"
	f := execx.NewFake("codesign", "xcrun", "ditto", "spctl", "security")
	certPEM := selfSignedPEM(t, ident, time.Now().Add(365*24*time.Hour))
	f.Handle = func(c execx.Cmd) execx.Result {
		switch {
		case c.Tool == "security" && c.Args[0] == "find-certificate":
			return execx.Result{Stdout: certPEM}
		case c.Tool == "codesign" && c.Args[0] == "-d":
			return execx.Result{Stderr: []byte("Authority=" + ident + "\nTeamIdentifier=" + team + "\n")}
		case c.Tool == "xcrun" && c.Args[0] == "notarytool":
			return execx.Result{Stdout: []byte(`{"id":"sub-140","status":"Accepted"}`)}
		}
		return execx.Result{}
	}
	h.run = mixRunner{real: map[string]bool{"git": true, "go": true}, fake: f}
	h.env["N_KEY"] = "-----BEGIN PRIVATE KEY-----\n" + randHex(t, 16) + "\n-----END PRIVATE KEY-----\n"
	h.env["N_ID"], h.env["N_ISS"] = randHex(t, 5), randHex(t, 8)
	h.ok("profile", "add", "mac", "--scope", "personal", "--owner", "me", "--purpose", "internal",
		"--set", "platforms.macos.kind=developer-id", "--set", "platforms.macos.teamId="+team,
		"--set", "platforms.macos.identity="+ident,
		"--set", "platforms.macos.notary.apiKeyRef=env://N_KEY", "--set", "platforms.macos.notary.keyId=env://N_ID",
		"--set", "platforms.macos.notary.issuer=env://N_ISS")
	out := h.ok("release", "--repo-root", repo, "--targets", "darwin/arm64", "--profile", "mac", "--purpose", "internal",
		"--platforms", "macos", "--json")
	if !f.Called("codesign", "--options runtime --timestamp --sign "+ident) || !f.Called("xcrun", "notarytool submit") {
		t.Fatalf("calls: %+v", f.Calls)
	}
	if !strings.Contains(out, "sub-140") {
		t.Fatalf("the release does not record the notarisation:\n%s", out)
	}
}
