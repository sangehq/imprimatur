// Package e2e runs the built impr binary as a person or sange would, on
// every OS CI runs (O-148, O-191, old bug 17): every other test drives the
// CLI in-process.
package e2e

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/sangehq/imprimatur/src/internal/testpe"
)

var (
	impr string       // the built binary
	ran  atomic.Int32 // e2e tests that started, checked against minRun
)

// minRun is the fewest e2e tests a full run must start, so a rename or a
// skip that hides them fails instead of passing nothing.
const minRun = 10

func TestMain(m *testing.M) {
	flag.Parse()
	dir, err := os.MkdirTemp("", "impr-e2e-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	impr = filepath.Join(dir, "impr")
	if runtime.GOOS == "windows" {
		impr += ".exe"
	}
	build := exec.Command("go", "build", "-o", impr, "../../cmd/impr")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build impr: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	if code == 0 && flag.Lookup("test.run").Value.String() == "" && ran.Load() < minRun {
		fmt.Fprintf(os.Stderr, "e2e: %d tests ran, want at least %d\n", ran.Load(), minRun)
		code = 1
	}
	os.Exit(code)
}

// env is one isolated user: its own config, state and home.
type env struct {
	t    *testing.T
	vars []string
	home string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ran.Add(1)
	home := t.TempDir()
	return &env{t: t, home: home, vars: []string{
		"IMPR_CONFIG_DIR=" + t.TempDir(), "IMPR_STATE_DIR=" + t.TempDir(), "IMPR_LEGACY_CONFIG=off",
		"IMPR_SYSTEM_CONFIG_DIR=off", "HOME=" + home, "USERPROFILE=" + home, "CI=1", "PATH=" + os.Getenv("PATH"),
		"SystemRoot=" + os.Getenv("SystemRoot"), "TMPDIR=" + os.TempDir(), "TEMP=" + os.TempDir(), "TMP=" + os.TempDir(),
	}}
}

// run runs impr with args in dir ("" for the test's own), returning the exit
// code, stdout and stderr.
func (e *env) run(dir string, args ...string) (int, string, string) {
	e.t.Helper()
	cmd := exec.Command(impr, args...)
	cmd.Env, cmd.Dir = e.vars, dir
	var o, er bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &er
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		e.t.Fatalf("run impr: %v", err)
	}
	return code, o.String(), er.String()
}

func (e *env) want(code int, args ...string) string {
	e.t.Helper()
	got, out, errOut := e.run("", args...)
	if got != code {
		e.t.Fatalf("impr %s: exit %d, want %d\n%s%s", strings.Join(args, " "), got, code, out, errOut)
	}
	if code != 0 && !strings.Contains(errOut, "impr:") {
		e.t.Fatalf("impr %s failed without a message: %q", strings.Join(args, " "), errOut)
	}
	return out
}

func need(t *testing.T, tools ...string) {
	t.Helper()
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip("needs " + tool)
		}
	}
}

// sshProfile adds an internal profile that signs checksums with a new key.
func (e *env) sshProfile(name string) {
	e.t.Helper()
	need(e.t, "ssh-keygen")
	key := filepath.Join(e.t.TempDir(), "k")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); err != nil {
		e.t.Fatalf("%v %s", err, out)
	}
	fp, _ := exec.Command("ssh-keygen", "-l", "-E", "sha256", "-f", key).Output()
	e.vars = append(e.vars, "IMPR_E2E_KEY="+key)
	e.want(0, "profile", "add", name, "--scope", "personal", "--owner", "me", "--purpose", "internal",
		"--set", "platforms.checksums.kind=ssh", "--set", "platforms.checksums.keyRef=env://IMPR_E2E_KEY",
		"--set", "platforms.checksums.fingerprint="+strings.Fields(string(fp))[1])
}

func TestE2EVersionAndHelp(t *testing.T) {
	e := newEnv(t)
	if out := e.want(0, "version"); !strings.HasPrefix(out, "impr ") {
		t.Fatalf("version: %q", out)
	}
	for _, h := range []string{"-h", "--help", "-?", "/?"} {
		e.want(0, h)
	}
	if _, _, errOut := e.run("", "help", "release"); !strings.Contains(errOut, "docs/tools/release.md") {
		t.Fatalf("help release: %s", errOut)
	}
	// No arguments and no terminal: the usage text and exit 1, as sange expects.
	e.want(1)
}

func TestE2EUnknownCommandSuggests(t *testing.T) {
	e := newEnv(t)
	if _, _, errOut := e.run("", "relase"); !strings.Contains(errOut, "did you mean: impr release") {
		t.Fatalf("relase: %s", errOut)
	}
	if _, _, errOut := e.run("", "--profile", "p", "sign"); !strings.Contains(errOut, "put the command first") {
		t.Fatalf("option first: %s", errOut)
	}
}

func TestE2ECompanionInfo(t *testing.T) {
	e := newEnv(t)
	var info struct {
		Contract int             `json:"contract"`
		Commands []string        `json:"commands"`
		Caps     map[string]bool `json:"capabilities"`
	}
	if err := json.Unmarshal([]byte(e.want(0, "companion", "info", "--json")), &info); err != nil || info.Contract != 1 || len(info.Commands) < 6 {
		t.Fatalf("companion info: %+v %v", info, err)
	}
}

func TestE2EProfileAndDoctor(t *testing.T) {
	e := newEnv(t)
	// No default profile: not ready, which is 5 (unavailable), never 1.
	e.want(5, "doctor", "--json")
	e.sshProfile("p")
	e.want(0, "profile", "default", "p")
	var rep struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal([]byte(e.want(0, "doctor", "--json")), &rep); err != nil || !rep.OK {
		t.Fatalf("doctor: %+v %v", rep, err)
	}
	e.want(0, "profile", "validate", "p")
}

// goRepo makes a committed git repository holding a tiny Go module.
func goRepo(t *testing.T) string {
	t.Helper()
	need(t, "git", "go")
	dir := t.TempDir()
	for p, body := range map[string]string{
		"src/go.mod":            "module example.com/hello/src\n\ngo 1.23\n",
		"src/cmd/hello/main.go": "package main\n\nimport \"fmt\"\n\nvar version = \"dev\"\n\nfunc main() { fmt.Println(version) }\n",
		"LICENSE":               "MIT\n",
	} {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "."}, {"-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "init"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	return dir
}

// The release pipeline end to end: build (from a folder inside the
// repository, with a version), sign, verify, archive, and verify again.
func TestE2EBuildReleaseVerify(t *testing.T) {
	repo := goRepo(t)
	e := newEnv(t)
	e.sshProfile("p")
	host := runtime.GOOS + "/" + runtime.GOARCH
	code, out, errOut := e.run(filepath.Join(repo, "src", "cmd", "hello"), "release", "v1.2.3", "--targets", host,
		"--profile", "p", "--purpose", "internal", "--platforms", "checksums", "--archives", "--json")
	if code != 0 {
		t.Fatalf("release: %d\n%s%s", code, out, errOut)
	}
	var r struct {
		OK    bool `json:"ok"`
		Build struct {
			Manifest struct {
				Version   string `json:"version"`
				Artifacts []struct {
					Path string `json:"path"`
				} `json:"artifacts"`
			} `json:"manifest"`
		} `json:"build"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil || !r.OK || r.Build.Manifest.Version != "v1.2.3" || len(r.Build.Manifest.Artifacts) != 1 {
		t.Fatalf("release result: %v\n%s", err, out)
	}
	bin := filepath.Join(repo, filepath.FromSlash(r.Build.Manifest.Artifacts[0].Path))
	if got, err := exec.Command(bin).Output(); err != nil || strings.TrimSpace(string(got)) != "v1.2.3" {
		t.Fatalf("the built binary says %q (%v)", got, err)
	}
	if _, err := os.Stat(filepath.Join(repo, "build", "archives", "checksums.txt")); err != nil {
		t.Fatalf("no archives: %v", err)
	}
	e.want(0, "verify", "--signed", filepath.Join(repo, "build", "impr-manifest.json"), "--profile", "p", "--root", repo, "--strict")
	// A changed file fails verification with exit 4.
	if err := os.WriteFile(filepath.Join(repo, "build", "SHA256SUMS"), []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.want(4, "verify", "--signed", filepath.Join(repo, "build", "impr-manifest.json"), "--profile", "p", "--root", repo, "--strict")
}

// Sign fails closed with the contract's exit codes.
func TestE2ESignFailsClosedExitCodes(t *testing.T) {
	repo := goRepo(t)
	e := newEnv(t)
	e.sshProfile("p")
	e.want(0, "build", "--repo-root", repo, "--targets", runtime.GOOS+"/"+runtime.GOARCH)
	manifest := filepath.Join(repo, "build", "build-manifest.json")
	var bm struct{ Commit, Tree string }
	b, _ := os.ReadFile(manifest)
	_ = json.Unmarshal(b, &bm)
	base := []string{"sign", "--manifest", manifest, "--commit", bm.Commit, "--tree", bm.Tree, "--profile", "p", "--root", repo}
	e.want(1, append(base, "--purpose", "nonsense")...)                                  // usage
	e.want(3, append(base, "--purpose", "release", "--strict")...)                       // an internal profile never signs a release
	e.want(1, "sign", "--manifest", manifest, "--profile", "p", "--purpose", "internal") // no commit and tree
}

func TestE2ECompletionParses(t *testing.T) {
	e := newEnv(t)
	for _, sh := range []string{"bash", "zsh", "fish"} {
		if _, err := exec.LookPath(sh); err != nil {
			continue
		}
		f := filepath.Join(t.TempDir(), "impr."+sh)
		if err := os.WriteFile(f, []byte(e.want(0, "completion", sh)), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(sh, "-n", f).CombinedOutput(); err != nil {
			t.Errorf("%s completion does not parse: %v %s", sh, err, out)
		}
	}
	e.want(0, "completion", "pwsh")
}

func TestE2ERulesFromASignedFile(t *testing.T) {
	e := newEnv(t)
	ca := testpe.NewIntermediate(t, "Acme CA", testpe.NewCA(t, "Acme Root"))
	exe, _ := testpe.Signed(t, t.TempDir(), "tool.exe", pkix.Name{CommonName: "Acme Ltd", Organization: []string{"Acme Ltd"}, Country: []string{"GB"}}, ca)
	out := t.TempDir()
	e.want(0, "rules", exe, "--scope", "file", "--product", "Acme Tool", "--base-policy", "{6b2a1c3d-0000-4000-8000-00000000abcd}", "--out-dir", out)
	for _, f := range []string{"applocker.xml", "wdac-supplemental.xml"} {
		b, err := os.ReadFile(filepath.Join(out, f))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if f == "applocker.xml" && !strings.Contains(string(b), `PublisherName="O=ACME LTD, C=GB"`) {
			t.Fatalf("applocker.xml: %s", b)
		}
	}
	// A file changed after signing is refused with exit 4.
	b, _ := os.ReadFile(exe)
	b[10] ^= 1
	if err := os.WriteFile(exe, b, 0o600); err != nil {
		t.Fatal(err)
	}
	e.want(4, "rules", exe, "--scope", "file", "--product", "Acme Tool")
}

func TestE2EImportLegacy(t *testing.T) {
	e := newEnv(t)
	legacy := t.TempDir()
	settings := `{"WINDOWS_SIGNER":"Certum","CERTUM_SUBJECT":"Open Source Developer, Pat Doe","CERTUM_THUMBPRINT":"` + strings.Repeat("AB", 20) + `"}`
	if err := os.WriteFile(filepath.Join(legacy, "imprimatur.settings.json"), []byte(settings), 0o600); err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Imported []string            `json:"imported"`
		Problems map[string][]string `json:"problems"`
	}
	if err := json.Unmarshal([]byte(e.want(0, "profile", "import-legacy", "--from", legacy, "--json")), &rep); err != nil ||
		len(rep.Imported) != 1 || len(rep.Problems) != 0 {
		t.Fatalf("import-legacy: %+v %v", rep, err)
	}
	e.want(0, "profile", "validate", "default")
}
