package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sangehq/imprimatur/src/internal/signing"
)

// sshProfile adds a release profile signing checksums with a key made for
// this run, with the extra --set options given.
func sshProfile(t *testing.T, h *harness, name string, set ...string) {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("real ssh-keygen: not installed")
	}
	key := filepath.Join(t.TempDir(), "release")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	fp, _ := exec.Command("ssh-keygen", "-l", "-E", "sha256", "-f", key).Output()
	h.env["IMPR_RELEASE_KEY"] = key
	args := []string{"profile", "add", name, "--scope", "company", "--owner", "acme", "--purpose", "release",
		"--allowed-repo", "github.com/acme/**", "--set", "platforms.checksums.kind=ssh",
		"--set", "platforms.checksums.keyRef=env://IMPR_RELEASE_KEY", "--set", "platforms.checksums.fingerprint=" + strings.Fields(string(fp))[1]}
	for _, s := range set {
		args = append(args, "--set", s)
	}
	h.ok(args...)
}

func signArgs(root, manifest, commit, tree, prof string, extra ...string) []string {
	return append([]string{"sign", "--json", "--root", root, "--manifest", manifest, "--commit", commit, "--tree", tree,
		"--profile", prof, "--purpose", "release", "--platforms", "checksums", "--repo", "git@github.com:acme/tool.git"}, extra...)
}

func TestSignedApprovalIsRequiredAndRecorded(t *testing.T) {
	h := newHarness(t)
	sshProfile(t, h, "acme-release", "requiresApproval=true")
	approvers(t, h, "alice", "bob")
	root, manifest, commit, tree := build(t)
	args := signArgs(root, manifest, commit, tree, "acme-release")

	out := h.exits(3, args...)
	if !strings.Contains(out, "needs 1 approval(s) and has 0 valid") {
		t.Fatalf("no approval: %s", out)
	}
	// An approval for another build manifest does not count.
	_, other, _, _ := build(t)
	out = h.exits(3, append(args, "--approval", h.approve("alice", other, "acme-release", "release"))...)
	if !strings.Contains(out, "approves another run") {
		t.Fatalf("another manifest's approval: %s", out)
	}
	// Nor does one for another profile.
	h.exits(3, append(args, "--approval", h.approve("alice", manifest, "other-release", "release"))...)

	// Two required: one is not enough; two distinct are.
	h.ok("config", "set", "approvals.required", "2")
	a1, a2 := h.approve("alice", manifest, "acme-release", "release"), h.approve("bob", manifest, "acme-release", "release")
	h.exits(3, append(args, "--approval", a1)...)
	var res signing.Result
	if err := json.Unmarshal([]byte(h.ok(append(args, "--approval", a1, "--approval", a2)...)), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Manifest.Approvals) != 2 || res.Manifest.Approvals[0].Approver != "alice" || res.Manifest.Approvals[1].Mode != "signed" ||
		len(res.Manifest.Approvals[1].SHA256) != 64 {
		t.Fatalf("approvals recorded: %+v", res.Manifest.Approvals)
	}
	// A profile edit to drop the requirement is a profile change, logged;
	// a profile without it signs without approvals.
	h.ok("profile", "edit", "acme-release", "--set", "requiresApproval=false")
	h.ok(args...)
}

// confirmApp is an App with a person at the terminal who types typed.
func confirmApp(h *harness, typed string) (*App, *bytes.Buffer, *bytes.Buffer) {
	var o, e bytes.Buffer
	return &App{Stdout: &o, Stderr: &e, Getenv: func(k string) string { return h.env[k] }, GOOS: h.os, Home: h.t.TempDir(), User: "tester",
		Runner: h.run, Now: func() time.Time { return h.now }, Stdin: strings.NewReader(typed + "\n"), Interactive: func() bool { return true }}, &o, &e
}

func TestConfirmApprovalNeedsAPersonAtATerminal(t *testing.T) {
	h := newHarness(t)
	h.ok("config", "set", "approvals.enforce", "true")
	sshProfile(t, h, "acme-release", "requiresApproval=true", "approval=confirm")
	root, manifest, commit, tree := build(t)
	args := signArgs(root, manifest, commit, tree, "acme-release")

	// No terminal (scripts, CI): refused, never answered.
	if out := h.exits(3, args...); !strings.Contains(out, "no terminal to ask") {
		t.Fatalf("no terminal: %s", out)
	}
	// The wrong answer.
	a, _, e := confirmApp(h, "wrong")
	if code := a.Run(context.Background(), args); code != 3 || !strings.Contains(e.String(), "not confirmed") {
		t.Fatalf("wrong answer: %d %s", code, e.String())
	}
	// The API never prompts, even when the server was started at a terminal.
	a, _, _ = confirmApp(h, commit[:12])
	if code, _ := a.runCaptured(context.Background(), args); code != 3 {
		t.Fatalf("an API run prompted for confirmation: exit %d", code)
	}
	// The right answer.
	a, o, e := confirmApp(h, commit[:12])
	if code := a.Run(context.Background(), args); code != 0 {
		t.Fatalf("confirmed: %d %s", code, e.String())
	}
	var res signing.Result
	if err := json.Unmarshal(o.Bytes(), &res); err != nil || len(res.Manifest.Approvals) != 1 || res.Manifest.Approvals[0].Mode != "confirm" {
		t.Fatalf("confirm recorded: %+v %v", res.Manifest.Approvals, err)
	}
}

func TestProjectFileCanRequireApproval(t *testing.T) {
	h := newHarness(t)
	sshProfile(t, h, "acme-release")
	approvers(t, h, "alice")
	// The repository's own requirement applies whatever approvals.enforce says.
	h.ok("config", "set", "approvals.enforce", "false")
	root, manifest, commit, tree := build(t)
	if err := os.MkdirAll(filepath.Join(root, ".imprimatur"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".imprimatur", "project.json"), []byte(`{"schema":"imprimatur.project/v1","requireApproval":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	args := signArgs(root, manifest, commit, tree, "acme-release")
	h.exits(3, args...)
	h.ok(append(args, "--approval", h.approve("alice", manifest, "acme-release", "release"))...)
}

// TestApprovalIsTheCallersByDefault: without approvals.enforce, impr signs a
// requiresApproval profile and leaves approval to the caller (sange, APR-11).
func TestApprovalIsTheCallersByDefault(t *testing.T) {
	h := newHarness(t)
	sshProfile(t, h, "acme-release", "requiresApproval=true")
	root, manifest, commit, tree := build(t)
	var res signing.Result
	if err := json.Unmarshal([]byte(h.ok(signArgs(root, manifest, commit, tree, "acme-release")...)), &res); err != nil || len(res.Manifest.Approvals) != 0 {
		t.Fatalf("not enforced: %+v %v", res.Manifest.Approvals, err)
	}
	h.ok("config", "set", "approvals.enforce", "true")
	h.exits(3, signArgs(root, manifest, commit, tree, "acme-release")...)
}

func TestApprovalProfileValidation(t *testing.T) {
	h := newHarness(t)
	sshProfile(t, h, "acme-release")
	h.exits(1, "profile", "edit", "acme-release", "--set", "approval=confirm")                                 // without requiresApproval
	h.exits(1, "profile", "edit", "acme-release", "--set", "requiresApproval=true", "--set", "approval=maybe") // not a mode
	approvers(t, h, "alice")
	h.exits(1, "config", "set", "approvals.required", "3") // more than are listed
}

func TestCertListRaisesExpiryOnce(t *testing.T) {
	h := newHarness(t)
	soon := h.now.Add(10 * 24 * time.Hour).UTC().Format(time.RFC3339)
	sshProfile(t, h, "acme-release", "platforms.checksums.notAfter="+soon)
	h.ok("cert", "list", "--json")
	h.ok("cert", "list", "--json")
	var tail struct {
		Events []struct {
			Type string          `json:"type"`
			Data json.RawMessage `json:"data"`
		} `json:"events"`
	}
	if err := json.Unmarshal([]byte(h.ok("events", "tail", "--json", "--type", "cert.*")), &tail); err != nil {
		t.Fatal(err)
	}
	if len(tail.Events) != 1 || !strings.HasSuffix(tail.Events[0].Type, "cert.expiring") || !strings.Contains(string(tail.Events[0].Data), `"threshold":14`) {
		t.Fatalf("want one cert.expiring at the 14-day threshold: %+v", tail.Events)
	}
}

// TestBundleVerifyPrintsOneDocumentOnFailure: a failed bundle verify with
// --json prints its result once and exits 4 (contract v1).
func TestBundleVerifyPrintsOneDocumentOnFailure(t *testing.T) {
	h := newHarness(t)
	sshProfile(t, h, "acme-release")
	// A managed profile with no installed bundle cannot be verified.
	dir := h.env["IMPR_CONFIG_DIR"]
	raw, err := os.ReadFile(filepath.Join(dir, "profiles", "acme-release.json"))
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	_ = json.Unmarshal(raw, &p)
	p["managed"] = true
	b, _ := json.Marshal(p)
	if err := os.WriteFile(filepath.Join(dir, "profiles", "acme-release.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	out := h.exits(4, "profile", "bundle", "verify", "--json")
	if !strings.Contains(out, `"ok":false`) {
		t.Fatalf("verify: %s", out)
	}
}
