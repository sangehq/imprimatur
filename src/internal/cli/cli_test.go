package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sangehq/imprimatur/src/internal/config"
	"github.com/sangehq/imprimatur/src/internal/execx"
	"github.com/sangehq/imprimatur/src/internal/paths"
	"github.com/sangehq/imprimatur/src/internal/server"
)

func randHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

type harness struct {
	t   *testing.T
	env map[string]string
	run execx.Runner
	os  string
	now time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	return &harness{t: t, os: runtime.GOOS, run: execx.OS{Timeout: time.Minute}, now: time.Now(),
		env: map[string]string{"IMPR_CONFIG_DIR": t.TempDir(), "IMPR_STATE_DIR": t.TempDir(), "IMPR_LEGACY_CONFIG": "off", "IMPR_SYSTEM_CONFIG_DIR": "off"}}
}

func (h *harness) impr(args ...string) (code int, stdout, stderr string) {
	var o, e bytes.Buffer
	a := &App{Stdout: &o, Stderr: &e, Getenv: func(k string) string { return h.env[k] }, GOOS: h.os, Home: h.t.TempDir(), User: "tester",
		Runner: h.run, Now: func() time.Time { return h.now }}
	code = a.Run(context.Background(), args)
	return code, o.String(), e.String()
}

func (h *harness) ok(args ...string) string {
	h.t.Helper()
	code, out, errOut := h.impr(args...)
	if code != 0 {
		h.t.Fatalf("impr %s: exit %d\n%s%s", strings.Join(args, " "), code, out, errOut)
	}
	return out
}

func (h *harness) exits(want int, args ...string) string {
	h.t.Helper()
	code, out, errOut := h.impr(args...)
	if code != want {
		h.t.Fatalf("impr %s: exit %d, want %d\n%s%s", strings.Join(args, " "), code, want, out, errOut)
	}
	if strings.Contains(strings.Join(args, " "), "--json") && !json.Valid([]byte(out)) {
		h.t.Fatalf("stdout is not one JSON document: %q", out)
	}
	if want != 0 && !strings.Contains(errOut, "impr:") {
		h.t.Fatalf("a failure printed no message on stderr: %q", errOut)
	}
	return out
}

// build writes two artifacts and a build manifest under a new root.
func build(t *testing.T) (root, manifest, commit, tree string) {
	t.Helper()
	root = t.TempDir()
	commit, tree = randHex(t, 20), randHex(t, 20)
	type art struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
	}
	var arts []art
	for _, p := range []string{"build/linux/tool_linux_amd64", "build/linux/tool_linux_arm64"} {
		data := []byte("\x7fELF" + randHex(t, 64))
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, data, 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		arts = append(arts, art{Path: p, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))})
	}
	b, _ := json.Marshal(map[string]any{"schema": "sange.build-manifest/v1", "commit": commit, "tree": tree, "version": "v1.8.0", "artifacts": arts})
	manifest = filepath.Join(root, "build", "build-manifest.json")
	if err := os.WriteFile(manifest, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return root, manifest, commit, tree
}

// ---- sange's side of the contract, field for field (adapters/imprimatur and
// domain/signing): what this test decodes is what sange decodes.

type sangeCompanionInfo struct {
	Contract     int             `json:"contract"`
	Version      string          `json:"version"`
	Commands     []string        `json:"commands"`
	Capabilities map[string]bool `json:"capabilities"`
	Host         string          `json:"host,omitempty"`
}

type sangeSignedArtifact struct {
	Path         string `json:"path"`
	InputSHA256  string `json:"inputSha256"`
	OutputSHA256 string `json:"outputSha256"`
	Platform     string `json:"platform"`
	Kind         string `json:"kind"`
	Signer       string `json:"signer"`
}

type sangeImprManifest struct {
	Schema              string                `json:"schema"`
	Profile             string                `json:"profile"`
	Purpose             string                `json:"purpose"`
	Identity            json.RawMessage       `json:"identity"`
	IdentityDigest      string                `json:"identityDigest"`
	Commit              string                `json:"commit"`
	Tree                string                `json:"tree"`
	BuildManifestDigest string                `json:"buildManifestDigest"`
	Artifacts           []sangeSignedArtifact `json:"artifacts"`
	Outputs             []sangeSignedArtifact `json:"outputs,omitempty"`
	SignedAt            time.Time             `json:"signedAt"`
}

type sangeSignResult struct {
	Contract       int               `json:"contract"`
	OK             bool              `json:"ok"`
	Manifest       sangeImprManifest `json:"manifest"`
	ManifestPath   string            `json:"manifestPath"`
	ManifestSHA256 string            `json:"manifestSha256"`
}

type sangeVerifyResult struct {
	Contract  int    `json:"contract"`
	OK        bool   `json:"ok"`
	Profile   string `json:"profile"`
	Artifacts []struct {
		Path     string   `json:"path"`
		SHA256   string   `json:"sha256"`
		OK       bool     `json:"ok"`
		Problems []string `json:"problems"`
	} `json:"artifacts"`
}

// sangeOutputAllowed is sange's rule for files a run may create.
func sangeOutputAllowed(p string) bool {
	base := path.Base(p)
	return base == "SHA256SUMS" || base == "checksums.txt" || strings.HasSuffix(base, ".sig") || strings.HasSuffix(base, ".minisig") ||
		strings.HasSuffix(base, ".sigstore.json")
}

func TestCompanionInfoIsWhatSangeRequires(t *testing.T) {
	h := newHarness(t)
	var info sangeCompanionInfo
	if err := json.Unmarshal([]byte(h.ok("companion", "info", "--json")), &info); err != nil {
		t.Fatal(err)
	}
	if info.Contract != 1 || !info.Capabilities["rules"] || !slices.Contains(info.Commands, "rules") {
		t.Fatalf("info: %+v", info)
	}
	for _, c := range []string{"companion info", "profile list", "profile show", "cert list", "sign", "verify"} {
		if !slices.Contains(info.Commands, c) {
			t.Errorf("companion info does not list %q, so sange treats imprimatur as absent", c)
		}
	}
}

// TestSignAndVerifyWithRealSSH is the whole chain of custody through the
// command line, with the real ssh-keygen: a profile added by command, a build
// manifest signed, its record read the way sange reads it, and verified.
func TestSignAndVerifyWithRealSSH(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("real ssh-keygen: not installed")
	}
	h := newHarness(t)
	keyDir := t.TempDir()
	key := filepath.Join(keyDir, "release")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "impr-test", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	fpOut, _ := exec.Command("ssh-keygen", "-l", "-E", "sha256", "-f", key).Output()
	fp := strings.Fields(string(fpOut))[1]
	h.env["IMPR_RELEASE_KEY"] = key

	h.ok("profile", "add", "acme-release", "--scope", "company", "--owner", "acme", "--purpose", "release",
		"--allowed-repo", "github.com/acme/**", "--requires-approval",
		"--set", "platforms.checksums.kind=ssh", "--set", "platforms.checksums.keyRef=env://IMPR_RELEASE_KEY",
		"--set", "platforms.checksums.fingerprint="+fp)
	var list struct {
		Contract int    `json:"contract"`
		Default  string `json:"default"`
	}
	_ = json.Unmarshal([]byte(h.ok("profile", "list", "--json")), &list)
	if list.Contract != 1 || list.Default != "acme-release" {
		t.Fatalf("list: %+v", list)
	}

	root, manifest, commit, tree := build(t)
	mb, _ := os.ReadFile(manifest)
	ms := sha256.Sum256(mb)
	out := h.ok("sign", "--json", "--strict", "--root", root, "--manifest", manifest, "--commit", commit, "--tree", tree,
		"--profile", "acme-release", "--purpose", "release", "--platforms", "checksums", "--repo", "git@github.com:acme/tool.git")
	var res sangeSignResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	m := res.Manifest
	if res.Contract != 1 || !res.OK || m.Schema != "imprimatur.manifest/v1" || m.Profile != "acme-release" || m.Purpose != "release" ||
		m.Commit != commit || m.Tree != tree || m.BuildManifestDigest != "sha256:"+hex.EncodeToString(ms[:]) {
		t.Fatalf("sign result: %s", out)
	}
	idSum := sha256.Sum256(m.Identity)
	if m.IdentityDigest != "sha256:"+hex.EncodeToString(idSum[:]) {
		t.Fatalf("identityDigest %s is not the digest of the identity it records", m.IdentityDigest)
	}
	rec, _ := os.ReadFile(res.ManifestPath)
	rs := sha256.Sum256(rec)
	if res.ManifestSHA256 != hex.EncodeToString(rs[:]) {
		t.Fatal("manifestSha256 is not the digest of impr-manifest.json")
	}
	if len(m.Outputs) != 2 {
		t.Fatalf("outputs: %+v", m.Outputs)
	}
	for _, o := range m.Outputs {
		if !sangeOutputAllowed(o.Path) || filepath.IsAbs(o.Path) {
			t.Errorf("sange would refuse output %q", o.Path)
		}
	}

	var v sangeVerifyResult
	vout := h.ok("verify", "--json", "--strict", "--root", root, "--manifest", manifest, "--signed", res.ManifestPath, "--profile", "acme-release")
	if err := json.Unmarshal([]byte(vout), &v); err != nil || !v.OK || len(v.Artifacts) == 0 {
		t.Fatalf("verify: %s %v", vout, err)
	}

	// The run is in the event log, chained, typed and free of key material.
	var evs EventsList
	if err := json.Unmarshal([]byte(h.ok("events", "tail", "--json", "--type", "signing.*")), &evs); err != nil {
		t.Fatal(err)
	}
	var types []string
	for _, ev := range evs.Events {
		types = append(types, ev.Short())
		if ev.Subject != "github.com/acme/tool" || strings.Contains(string(ev.Data), key) {
			t.Errorf("event %s: subject %q, data %s", ev.Type, ev.Subject, ev.Data)
		}
	}
	if strings.Join(types, ",") != "signing.run.started,signing.run.completed" {
		t.Fatalf("events: %v", types)
	}
	if out := h.ok("events", "verify", "--json"); !strings.Contains(out, `"ok":true`) {
		t.Fatalf("events verify: %s", out)
	}

	// A changed artifact fails: the signed checksum file is not enough on its
	// own, every file it lists is re-hashed.
	art := filepath.Join(root, "build", "linux", "tool_linux_amd64")
	orig, _ := os.ReadFile(art)
	if err := os.WriteFile(art, append([]byte{}, append(orig, 'x')...), 0o600); err != nil {
		t.Fatal(err)
	}
	vout = h.exits(4, "verify", "--json", "--strict", "--root", root, "--signed", res.ManifestPath, "--profile", "acme-release")
	if !strings.Contains(vout, "tool_linux_amd64: does not match the signed checksum") {
		t.Fatalf("a tampered artifact was not reported: %s", vout)
	}
	if err := os.WriteFile(art, orig, 0o600); err != nil {
		t.Fatal(err)
	}

	// A forged record that lists nothing never passes.
	var forged map[string]any
	_ = json.Unmarshal(rec, &forged)
	forged["artifacts"], forged["outputs"] = []any{}, []any{}
	fb, _ := json.Marshal(forged)
	forgedPath := filepath.Join(t.TempDir(), "impr-manifest.json")
	if err := os.WriteFile(forgedPath, fb, 0o600); err != nil {
		t.Fatal(err)
	}
	h.exits(4, "verify", "--json", "--strict", "--root", root, "--signed", forgedPath, "--profile", "acme-release")

	// A missing file is a verification failure (4), not "unavailable" (5).
	if err := os.Rename(art, art+".gone"); err != nil {
		t.Fatal(err)
	}
	h.exits(4, "verify", "--json", "--strict", "--root", root, "--signed", res.ManifestPath, "--profile", "acme-release")
	if err := os.Rename(art+".gone", art); err != nil {
		t.Fatal(err)
	}

	// A changed checksum file fails verification, and the report still prints.
	sums := filepath.Join(root, filepath.FromSlash(m.Outputs[0].Path))
	if err := os.WriteFile(sums, []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	vout = h.exits(4, "verify", "--json", "--strict", "--root", root, "--signed", res.ManifestPath, "--profile", "acme-release")
	if err := json.Unmarshal([]byte(vout), &v); err != nil || v.OK || v.Profile != "acme-release" {
		t.Fatalf("failed verify report: %s", vout)
	}
}

// TestSignFailsClosed: each refusal happens before anything is signed, with
// its defined exit code and a fix line.
func TestSignFailsClosed(t *testing.T) {
	fake := execx.NewFake("ssh-keygen")
	h := newHarness(t)
	h.run = fake
	h.env["IMPR_KEY"] = filepath.Join(t.TempDir(), "absent-key")
	fp := "SHA256:" + randHex(t, 16)
	add := func(name, purpose string, extra ...string) {
		args := append([]string{"profile", "add", name, "--scope", "personal", "--owner", "tester", "--purpose", purpose,
			"--set", "platforms.checksums.kind=ssh", "--set", "platforms.checksums.keyRef=env://IMPR_KEY", "--set", "platforms.checksums.fingerprint=" + fp}, extra...)
		h.ok(args...)
	}
	add("me-test", "test")
	add("me-release", "release", "--allowed-repo", "github.com/me/**")
	add("me-old", "internal", "--set", "platforms.checksums.notAfter=2020-01-01T00:00:00Z")
	h.ok("profile", "add", "me-mac", "--scope", "personal", "--owner", "tester", "--purpose", "internal",
		"--set", "platforms.macos.kind=developer-id", "--set", "platforms.macos.teamId=ABCDE12345",
		"--set", "platforms.macos.identity=Developer ID Application: Tester (ABCDE12345)")
	root, manifest, commit, tree := build(t)
	base := []string{"sign", "--json", "--root", root, "--manifest", manifest, "--commit", commit, "--tree", tree}

	cases := []struct {
		name string
		args []string
		code int
		want string
	}{
		{"a missing profile", []string{"--profile", "nope", "--purpose", "test", "--strict"}, 1, "no signing profile"},
		{"no purpose", []string{"--profile", "me-test", "--strict"}, 1, "--purpose"},
		{"a test profile for a release", []string{"--profile", "me-test", "--purpose", "release", "--strict"}, 3, "not release"},
		{"a release with no repository", []string{"--profile", "me-release", "--purpose", "release", "--strict"}, 1, "--repo"},
		{"a repository not allowed", []string{"--profile", "me-release", "--purpose", "release", "--repo", "https://github.com/other/x", "--strict"}, 3, "may not sign"},
		{"another commit", []string{"--profile", "me-test", "--purpose", "test", "--strict", "--commit", randHex(t, 20)}, 3, "not the build manifest"},
		{"an expired key", []string{"--profile", "me-old", "--purpose", "internal", "--strict"}, 3, "expired"},
		{"a key this host does not have", []string{"--profile", "me-test", "--purpose", "test", "--strict"}, 5, "not available"},
		{"a platform the profile lacks", []string{"--profile", "me-test", "--purpose", "test", "--platforms", "windows", "--strict"}, 1, "no windows configuration"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fake.Calls = nil
			out := h.exits(c.code, append(append([]string{}, base...), c.args...)...)
			var doc struct {
				ExitCode int `json:"exitCode"`
				Error    struct {
					Message string   `json:"message"`
					Fix     []string `json:"fix"`
				} `json:"error"`
			}
			_ = json.Unmarshal([]byte(out), &doc)
			if doc.ExitCode != c.code || !strings.Contains(doc.Error.Message, c.want) {
				t.Fatalf("error document: %s", out)
			}
			if c.code != 1 && len(doc.Error.Fix) == 0 && c.name != "another commit" {
				t.Errorf("no fix line: %s", out)
			}
			for _, call := range fake.Calls {
				if slices.Contains(call.Args, "sign") {
					t.Fatal("something was signed")
				}
			}
		})
	}

	// The build files changed after the manifest: nothing is signed.
	f := filepath.Join(root, "build", "linux", "tool_linux_amd64")
	if err := os.WriteFile(f, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.exits(3, append(base, "--profile", "me-test", "--purpose", "test")...)

	// macOS signing on a host that cannot: 5 with --strict, 2 (skipped) without.
	_, manifest2, commit2, tree2 := buildMacho(t, root)
	h.os = "linux"
	mac := []string{"sign", "--json", "--root", root, "--manifest", manifest2, "--commit", commit2, "--tree", tree2, "--profile", "me-mac", "--purpose", "internal"}
	h.exits(5, append(mac, "--strict")...)
	out := h.exits(2, mac...)
	var res struct {
		OK      bool     `json:"ok"`
		Skipped []string `json:"skipped"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil || res.OK || len(res.Skipped) != 1 {
		t.Fatalf("skipped run: %s", out)
	}
}

func buildMacho(t *testing.T, root string) (string, string, string, string) {
	t.Helper()
	commit, tree := randHex(t, 20), randHex(t, 20)
	data := append([]byte{0xcf, 0xfa, 0xed, 0xfe}, []byte(randHex(t, 16))...)
	p := "build/macos/tool_macos_arm64"
	full := filepath.Join(root, filepath.FromSlash(p))
	_ = os.MkdirAll(filepath.Dir(full), 0o750)
	if err := os.WriteFile(full, data, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	b, _ := json.Marshal(map[string]any{"schema": "sange.build-manifest/v1", "commit": commit, "tree": tree, "version": "v1.8.0",
		"artifacts": []map[string]any{{"path": p, "sha256": hex.EncodeToString(sum[:]), "size": len(data)}}})
	manifest := filepath.Join(root, "build", "macos", "build-manifest.json")
	if err := os.WriteFile(manifest, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return root, manifest, commit, tree
}

func TestProfileCommands(t *testing.T) {
	h := newHarness(t)
	fp := "SHA256:" + randHex(t, 16)
	h.ok("profile", "add", "me", "--scope", "personal", "--owner", "tester", "--purpose", "test",
		"--set", "platforms.checksums.kind=ssh", "--set", "platforms.checksums.keyRef=env://K", "--set", "platforms.checksums.fingerprint="+fp)
	// show --json carries the contract version, as sange's call() requires.
	var show map[string]any
	_ = json.Unmarshal([]byte(h.ok("profile", "show", "me", "--json")), &show)
	if show["contract"] != float64(1) || show["name"] != "me" {
		t.Fatalf("show: %v", show)
	}
	h.exits(1, "profile", "edit", "me", "--set", "platforms.checksums.password=x")
	h.exits(1, "profile", "edit", "me", "--set", "platforms.checksums.keyRef=/home/me/key")
	h.exits(1, "profile", "edit", "me", "--purpose", "test,release")
	exported := filepath.Join(t.TempDir(), "me.json")
	h.ok("profile", "export", "me", "--out-file", exported)
	h.exits(1, "profile", "rm", "me")
	h.ok("profile", "rm", "me", "--force")
	h.ok("profile", "import", exported)
	var val struct {
		OK bool `json:"ok"`
	}
	_ = json.Unmarshal([]byte(h.ok("profile", "validate", "--json")), &val)
	if !val.OK {
		t.Fatal("validate")
	}
	var caps struct {
		Profiles []struct {
			Name      string                     `json:"name"`
			Platforms map[string]json.RawMessage `json:"platforms"`
		} `json:"profiles"`
	}
	_ = json.Unmarshal([]byte(h.ok("profile", "capabilities", "--json")), &caps)
	if len(caps.Profiles) != 1 || caps.Profiles[0].Platforms["checksums"] == nil {
		t.Fatalf("capabilities: %+v", caps)
	}
	var certs struct {
		Contract     int `json:"contract"`
		Certificates []struct {
			Profile string `json:"profile"`
			Present bool   `json:"present"`
		} `json:"certificates"`
	}
	_ = json.Unmarshal([]byte(h.ok("cert", "list", "--json")), &certs)
	if certs.Contract != 1 || len(certs.Certificates) != 1 || certs.Certificates[0].Present {
		t.Fatalf("certs: %+v", certs)
	}
	h.exits(1, "profile", "frobnicate")
	h.exits(1, "nosuchcommand", "--json")
	h.exits(1, "sign", "loose.exe", "--json")
}

func TestImportLegacyOnFirstRun(t *testing.T) {
	h := newHarness(t)
	legacy := t.TempDir()
	if err := os.WriteFile(filepath.Join(legacy, "imprimatur.settings.json"), []byte(`{"WINDOWS_SIGNER":"Certum","CERTUM_SUBJECT":"Open Source Developer, Tester"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h.env["IMPR_LEGACY_CONFIG"] = legacy
	_, _, errOut := h.impr("profile", "list")
	if !strings.Contains(errOut, "imported the PowerShell line's settings") {
		t.Fatalf("no automatic import: %s", errOut)
	}
	var list struct {
		Default string `json:"default"`
	}
	_ = json.Unmarshal([]byte(h.ok("profile", "list", "--json")), &list)
	if list.Default != "default" {
		t.Fatalf("default %q", list.Default)
	}
	// Once only: the index now exists.
	if _, _, errOut := h.impr("profile", "list"); strings.Contains(errOut, "imported") {
		t.Fatal("the import ran twice")
	}
}

func TestRulesCommand(t *testing.T) {
	h := newHarness(t)
	req := map[string]any{"contract": 1, "manifestDigest": "sha256:" + randHex(t, 32), "commit": randHex(t, 20), "version": "v1.8.0", "fileVersion": "1.8.0.0",
		"publisher":   map[string]any{"subject": "O=ACME LTD, L=LONDON, C=GB", "leafCn": "Acme Ltd", "issuerName": "Acme CA", "issuerTbs": strings.ToUpper(randHex(t, 32)), "product": "tool"},
		"files":       []map[string]any{{"path": "build/windows/tool.exe", "sha256": randHex(t, 32), "collection": "Exe", "binaryName": "tool.exe"}},
		"options":     map[string]any{"name": "tool", "basePolicyId": "{A244370E-44C9-4C06-B551-F6016E563076}", "appLocker": true, "wdac": true},
		"futureField": "ignored"}
	b, _ := json.Marshal(req)
	f := filepath.Join(t.TempDir(), "req.json")
	_ = os.WriteFile(f, b, 0o600)
	out := h.ok("rules", "--json", "--strict", "--request", f)
	var res struct {
		Contract       int    `json:"contract"`
		ManifestDigest string `json:"manifestDigest"`
		AppLocker      string `json:"appLocker"`
		WDAC           string `json:"wdac"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil || res.ManifestDigest != req["manifestDigest"] ||
		!strings.Contains(res.AppLocker, "<AppLockerPolicy") || !strings.Contains(res.WDAC, "<SiPolicy") {
		t.Fatalf("rules: %s", out)
	}
	if out2 := h.ok("rules", "--json", "--strict", "--request", f); out2 != out {
		t.Fatal("rules are not deterministic")
	}
	h.exits(1, "rules", "--json", "--strict")
}

func TestSetKeepsCommas(t *testing.T) {
	p, err := parse([]string{"--set", "platforms.windows.subject=CN=Acme Ltd, O=Acme Ltd", "--purpose", "test,internal"}, profileFlags)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.list("set"); len(got) != 1 || got[0] != "platforms.windows.subject=CN=Acme Ltd, O=Acme Ltd" {
		t.Fatalf("--set split a value: %q", got)
	}
	if got := p.list("purpose"); len(got) != 2 {
		t.Fatalf("--purpose did not split: %q", got)
	}
}

// TestReadCommandsAcceptStrict: a caller may pass --strict to every call,
// so the read commands accept it, and companion info advertises that with
// the strictReads capability. Proven red by dropping "strict" from
// readFlags: companion info and cert list then exit 1.
func TestReadCommandsAcceptStrict(t *testing.T) {
	h := newHarness(t)
	reads := [][]string{
		{"companion", "info", "--json", "--strict"},
		{"profile", "list", "--json", "--strict"},
		{"cert", "list", "--json", "--strict"},
	}
	for _, args := range reads {
		h.ok(args...)
	}
	out := h.ok("companion", "info", "--json")
	if !strings.Contains(out, `"`+StrictReadsCapability+`":true`) {
		t.Errorf("companion info does not advertise %s:\n%s", StrictReadsCapability, out)
	}
	if len(reads) != 3 {
		t.Fatal("read command list was cut")
	}
}

// TestPreSignHookVetoSignsNothing: a pre-sign hook in the user's config.json
// that exits non-zero with veto stops the run before the first signature.
func TestPreSignHookVetoSignsNothing(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil || runtime.GOOS == "windows" {
		t.Skip("needs ssh-keygen and a Unix shell")
	}
	h := newHarness(t)
	key := filepath.Join(t.TempDir(), "k")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	fpOut, _ := exec.Command("ssh-keygen", "-l", "-E", "sha256", "-f", key).Output()
	h.env["IMPR_K"] = key
	h.ok("profile", "add", "p", "--scope", "personal", "--owner", "me", "--purpose", "internal",
		"--set", "platforms.checksums.kind=ssh", "--set", "platforms.checksums.keyRef=env://IMPR_K",
		"--set", "platforms.checksums.fingerprint="+strings.Fields(string(fpOut))[1])

	hook := filepath.Join(t.TempDir(), "deny.sh")
	body := []byte("#!/bin/sh\necho 'release freeze' >&2\nexit 1\n")
	if err := os.WriteFile(hook, body, 0o700); err != nil { //nolint:gosec // G306: a test hook must be executable
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	cfg := fmt.Sprintf(`{"schema":"imprimatur.config/v1","hooks":[{"name":"freeze","phase":"pre-sign","exec":%q,"sha256":%q,"veto":true}]}`,
		hook, hex.EncodeToString(sum[:]))
	if err := os.WriteFile(filepath.Join(h.env["IMPR_CONFIG_DIR"], "config.json"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if out := h.ok("hooks", "list", "--json"); !strings.Contains(out, `"pinOk":true`) {
		t.Fatalf("hooks list: %s", out)
	}

	root, manifest, commit, tree := build(t)
	out := h.exits(3, "sign", "--json", "--strict", "--root", root, "--manifest", manifest, "--commit", commit, "--tree", tree,
		"--profile", "p", "--purpose", "internal", "--platforms", "checksums")
	if !strings.Contains(out, "release freeze") && !strings.Contains(out, "freeze") {
		t.Fatalf("the refusal does not name the hook: %s", out)
	}
	if _, err := os.Stat(filepath.Join(root, "build", "impr-manifest.json")); err == nil {
		t.Fatal("a vetoed run wrote impr-manifest.json")
	}
	if _, err := os.Stat(filepath.Join(root, "build", "SHA256SUMS")); err == nil {
		t.Fatal("a vetoed run wrote SHA256SUMS")
	}
	if ev := h.ok("events", "tail", "--json"); !strings.Contains(ev, "hook.vetoed") || strings.Contains(ev, "signing.run.started") {
		t.Fatalf("events after a veto: %s", ev)
	}
}

// TestServerAnswersWhatTheCLIPrints: a token made by `impr server token add`
// is stored as a digest only, and GET /v1/profiles over the real command code
// returns the same document `impr profile list --json` prints.
func TestServerAnswersWhatTheCLIPrints(t *testing.T) {
	h := newHarness(t)
	h.ok("profile", "add", "p", "--scope", "personal", "--owner", "me", "--purpose", "internal",
		"--set", "platforms.checksums.kind=ssh", "--set", "platforms.checksums.keyRef=env://K",
		"--set", "platforms.checksums.fingerprint=SHA256:"+strings.Repeat("A", 43))
	tok := strings.TrimSpace(h.ok("server", "token", "add", "--scopes", "read"))
	cfgRaw, _ := os.ReadFile(filepath.Join(h.env["IMPR_CONFIG_DIR"], "config.json"))
	if !strings.HasPrefix(tok, "impr_") || strings.Contains(string(cfgRaw), tok) {
		t.Fatalf("token %q, config %s", tok, cfgRaw)
	}
	h.ok("serve", "--check-config")
	cli := strings.TrimSpace(h.ok("profile", "list", "--json"))

	d, _ := paths.Resolve(paths.Env{GOOS: h.os, Getenv: func(k string) string { return h.env[k] }})
	cfg, err := config.Load(d.Config)
	if err != nil {
		t.Fatal(err)
	}
	a := &App{Stdout: io.Discard, Stderr: io.Discard, Getenv: func(k string) string { return h.env[k] }, GOOS: h.os, Home: t.TempDir(),
		User: "tester", Runner: h.run, Now: func() time.Time { return h.now }}
	srv := server.Handler(server.Options{Config: cfg, Run: a.runCaptured, StateDir: d.State, Now: time.Now})
	req := httptest.NewRequest("GET", "/v1/profiles", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != cli {
		t.Fatalf("API %d\n%s\nCLI\n%s", rec.Code, rec.Body, cli)
	}
	var list struct {
		Tokens []struct {
			ID string `json:"id"`
		} `json:"tokens"`
	}
	if err := json.Unmarshal([]byte(h.ok("server", "token", "list", "--json")), &list); err != nil || len(list.Tokens) != 1 {
		t.Fatalf("token list: %+v %v", list, err)
	}
	h.ok("server", "token", "revoke", list.Tokens[0].ID)
	h.exits(1, "serve", "--check-config") // no token left: nothing could call the server
}

// TestConfigProfiles: create a configuration profile, set a key in it,
// activate it, and read the effective value; a change the system config
// locks is refused and leaves the file as it was.
func TestConfigProfiles(t *testing.T) {
	h := newHarness(t)
	sys := t.TempDir()
	h.env["IMPR_SYSTEM_CONFIG_DIR"] = sys
	if err := os.WriteFile(filepath.Join(sys, "config.json"), []byte(`{"locked":["server.allowSign"],"server":{"roots":["/srv/builds"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h.ok("config", "profile", "create", "ci")
	h.ok("config", "set", "server.listen", "127.0.0.1:8743", "--profile", "ci")
	h.exits(1, "config", "get", "server.listen")
	h.ok("config", "profile", "use", "ci")
	if got := strings.TrimSpace(h.ok("config", "get", "server.listen")); got != `"127.0.0.1:8743"` {
		t.Fatalf("effective listen %s", got)
	}
	if got := strings.TrimSpace(h.ok("config", "get", "server.roots")); got != `["/srv/builds"]` {
		t.Fatalf("system roots not inherited: %s", got)
	}
	// IMPR_CONFIG_PROFILE overrides activeProfile.
	h.ok("config", "profile", "create", "dev")
	h.env["IMPR_CONFIG_PROFILE"] = "dev"
	h.exits(1, "config", "get", "server.listen")
	delete(h.env, "IMPR_CONFIG_PROFILE")

	prof := filepath.Join(h.env["IMPR_CONFIG_DIR"], "config.d", "ci.json")
	before, _ := os.ReadFile(prof)
	h.exits(1, "config", "set", "server.allowSign", "true", "--profile", "ci")
	if after, _ := os.ReadFile(prof); string(after) != string(before) {
		t.Fatalf("a refused change was kept:\n%s", after)
	}
	h.exits(1, "config", "set", "locked", `["hooks"]`)
	h.exits(1, "config", "profile", "rm", "ci") // active
	h.ok("config", "profile", "use", "--none")
	h.ok("config", "profile", "rm", "ci")
	var show struct {
		Contract int `json:"contract"`
		Layers   []struct {
			Name string `json:"name"`
		} `json:"layers"`
		Locked []string `json:"locked"`
	}
	if err := json.Unmarshal([]byte(h.ok("config", "show", "--json")), &show); err != nil || show.Contract != 1 || len(show.Layers) != 2 || len(show.Locked) != 1 {
		t.Fatalf("show: %+v %v", show, err)
	}
	if ev := h.ok("events", "tail", "--json", "--type", "config.*"); strings.Count(ev, "config.changed") < 2 {
		t.Fatalf("config changes were not recorded: %s", ev)
	}
}

// Audit N-B19 and N-B20: --json and --help are read only as options, and
// help is per command.
func TestArgvScanningAndPerCommandHelp(t *testing.T) {
	for args, want := range map[string][2]bool{
		"sign --json":                   {true, false},
		"profile add p --notes --json":  {false, false}, // --json is the notes text
		"verify --profile p -- --json":  {false, false}, // a file named --json
		"profile --help":                {false, true},
		"cert list --strict --json":     {true, false},
		"profile edit p --notes --help": {false, false},
	} {
		j, h := scanGlobal(strings.Fields(args))
		if j != want[0] || h != want[1] {
			t.Errorf("%q: json %v help %v, want %v", args, j, h, want)
		}
	}
	h := newHarness(t)
	for _, args := range [][]string{{"profile", "--help"}, {"help", "profile"}} {
		code, out, e := h.impr(args...)
		if code != 0 || out != "" || !strings.Contains(e, "impr profile list") || strings.Contains(e, "impr sign") {
			t.Fatalf("%v: %d %q %q", args, code, out, e)
		}
	}
	h.exits(1, "profile", "add", "p", "--scope", "personal", "--owner", "me", "--purpose", "internal", "--set", "managed=true")
}

// Audit N-B18: a failed automatic import of the PowerShell settings is
// recorded once, not retried (and re-warned) on every command.
func TestFailedLegacyImportIsNotRetried(t *testing.T) {
	h := newHarness(t)
	legacy := t.TempDir()
	if err := os.WriteFile(filepath.Join(legacy, "imprimatur.settings.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.env["IMPR_LEGACY_CONFIG"] = legacy
	_, _, first := h.impr("profile", "list", "--json")
	_, _, second := h.impr("profile", "list", "--json")
	if !strings.Contains(first, "could not import") {
		t.Skipf("the malformed settings did not fail the import here: %q", first)
	}
	if strings.Contains(second, "could not import") {
		t.Fatalf("the import was retried: %q", second)
	}
}

// Completion is generated from the usage text, so every command the
// dispatcher knows must have a usage line, and each shell's script must
// parse where that shell is installed.
func TestCompletionCoversEveryCommand(t *testing.T) {
	m := completionModel()
	if len(commands) < 15 {
		t.Fatalf("the dispatch table has %d commands; the guard is not looking at it", len(commands))
	}
	for name := range commands {
		if _, ok := m[name]; !ok {
			t.Errorf("command %s has no usage line, so completion cannot offer it", name)
		}
	}
	for _, want := range []string{"--manifest", "--purpose", "--platforms"} {
		if !slices.Contains(m["sign"], want) {
			t.Errorf("sign completion lacks %s", want)
		}
	}
	if !slices.Contains(m["profile"], "import-legacy") || slices.Contains(m["install"], "uninstall") {
		t.Errorf("profile %v, install %v", m["profile"], m["install"])
	}
	for _, sh := range []string{"bash", "zsh", "fish"} {
		script, err := CompletionScript(sh)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := exec.LookPath(sh); err != nil {
			continue
		}
		f := filepath.Join(t.TempDir(), "c")
		if err := os.WriteFile(f, []byte(script), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(sh, "-n", f).CombinedOutput(); err != nil {
			t.Errorf("%s does not parse its completion: %v %s", sh, err, out)
		}
	}
	if _, err := CompletionScript("tcsh"); err == nil {
		t.Error("an unknown shell was accepted")
	}
}

func TestInstallUninstallAndAliases(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	h.ok("install", "--dir", dir)
	bin := filepath.Join(dir, "impr")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if st, err := os.Stat(bin); err != nil || st.Mode().Perm()&0o100 == 0 {
		t.Fatalf("installed binary: %v %v", st, err)
	}
	_, _, e := h.impr("install", "--dir", dir)
	if !strings.Contains(e, "already this impr") {
		t.Fatalf("a second install: %q", e)
	}
	// Something else at the target is never replaced or removed.
	other := t.TempDir()
	if err := os.WriteFile(filepath.Join(other, filepath.Base(bin)), []byte("#!/bin/sh\necho not impr\n"), 0o700); err != nil { //nolint:gosec // G306: an executable stand-in
		t.Fatal(err)
	}
	h.exits(1, "install", "--dir", other)
	h.exits(1, "uninstall", "--dir", other)
	if _, err := os.Stat(filepath.Join(other, filepath.Base(bin))); err != nil {
		t.Fatal("uninstall removed a program that is not impr")
	}
	h.ok("uninstall", "--dir", dir)
	if _, err := os.Stat(bin); err == nil {
		t.Fatal("uninstall left impr")
	}
	var info PathInfo
	if err := json.Unmarshal([]byte(h.ok("path", "--json", "--dir", dir)), &info); err != nil || info.Installed || info.Config == "" {
		t.Fatalf("path: %+v %v", info, err)
	}
	// d is doctor, which exits 1 here only because no default profile exists.
	if code, out, _ := h.impr("d", "--json"); code != 1 || !strings.Contains(out, `"contract":1`) || !strings.Contains(out, `"defaultProfile"`) {
		t.Fatalf("alias d did not run doctor: %d %s", code, out)
	}
}
