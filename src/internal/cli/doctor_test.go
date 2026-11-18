package cli

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sangehq/imprimatur/src/internal/execx"
)

// O-162, old bug 6: doctor's "not ok" is not the usage code. A host that is
// not ready exits 5 (unavailable), so a caller can tell it from a mistyped
// command, which still exits 1.
func TestDoctorNotOKIsNotUsage(t *testing.T) {
	h := newHarness(t)
	code, out, e := h.impr("doctor", "--json")
	if code != 5 || !strings.Contains(out, `"ok":false`) || !strings.Contains(e, "impr: doctor found 1 problem(s)") {
		t.Fatalf("doctor with no default profile: exit %d, want 5\n%s", code, out)
	}
	if code, _, _ := h.impr("doctor", "extra"); code != 1 {
		t.Fatalf("doctor with a stray word: exit %d, want 1", code)
	}
}

// ID-19, O-163 to O-166: doctor notes what the PowerShell doctor checked,
// without counting any of it as a problem: impr off PATH, no completion for
// the user's shell, go or git missing (impr build needs them), a certificate
// expiring within 30 days, Azure not signed in for an Artifact Signing
// profile, and a gpg profile's secret key missing from the agent.
func TestDoctorNotes(t *testing.T) {
	h := newHarness(t)
	h.home = t.TempDir()
	h.env["SHELL"] = "/bin/zsh"
	h.env["PATH"] = "/usr/bin"
	fpr := strings.ToUpper(randHex(t, 20))
	f := execx.NewFake("az", "gpg")
	f.Handle = func(c execx.Cmd) execx.Result {
		switch c.Tool {
		case "az":
			return execx.Result{ExitCode: 1, Stderr: []byte("Please run 'az login'")}
		case "gpg":
			return execx.Result{ExitCode: 2, Stderr: []byte("gpg: error reading key: No secret key")}
		}
		return execx.Result{}
	}
	h.run = f
	h.ok("cert", "create", "--name", "soon", "--days", "10")
	h.ok("profile", "add", "az", "--scope", "personal", "--owner", "me", "--purpose", "internal",
		"--set", "platforms.windows.kind=authenticode", "--set", "platforms.windows.backend=azure-artifact-signing",
		"--set", "platforms.windows.subject=CN=Me", "--set", `platforms.windows.dlibPath=C:\d\Azure.CodeSigning.Dlib.dll`,
		"--set", `platforms.windows.metadataPath=C:\d\metadata.json`)
	h.ok("profile", "add", "g", "--scope", "personal", "--owner", "me", "--purpose", "internal",
		"--set", "platforms.checksums.kind=gpg", "--set", "platforms.checksums.keyRef=gpg-agent://"+fpr,
		"--set", "platforms.checksums.fingerprint="+fpr)
	h.ok("profile", "default", "g")
	var rep DoctorReport
	code, out, _ := h.impr("doctor", "--json")
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	notes := strings.Join(rep.Notes, "\n")
	for _, want := range []string{"not on PATH", "no shell completion for zsh", "go is not installed", "git is not installed",
		"soon", "expires", "not signed in to Azure", "secret key " + fpr} {
		if !strings.Contains(notes, want) {
			t.Errorf("no note %q in:\n%s", want, notes)
		}
	}
	for _, p := range rep.Problems {
		if strings.Contains(p, "PATH") || strings.Contains(p, "completion") || strings.Contains(p, "Azure") {
			t.Errorf("a note became a problem: %s", p)
		}
	}
	_ = code
}

// ID-26, threat-model residuals 1 and 2: doctor notes, and never fails on, a
// release-purpose profile that can sign while approvals are not enforced,
// and an audit trail that is not anchored off the machine.
func TestDoctorNotesApprovalsAndAnchoring(t *testing.T) {
	h := newHarness(t)
	key := filepath.Join(t.TempDir(), "k")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); err != nil {
		t.Skipf("needs ssh-keygen: %v %s", err, out)
	}
	fp, _ := exec.Command("ssh-keygen", "-l", "-E", "sha256", "-f", key).Output()
	h.env["IMPR_K"] = key
	h.ok("profile", "add", "rel", "--scope", "company", "--owner", "acme", "--purpose", "release",
		"--allowed-repo", "github.com/acme/**",
		"--set", "platforms.checksums.kind=ssh", "--set", "platforms.checksums.keyRef=env://IMPR_K",
		"--set", "platforms.checksums.fingerprint="+strings.Fields(string(fp))[1])
	h.ok("profile", "default", "rel")
	var rep DoctorReport
	if err := json.Unmarshal([]byte(h.ok("doctor", "--json")), &rep); err != nil {
		t.Fatal(err)
	}
	notes := strings.Join(rep.Notes, "\n")
	if !strings.Contains(notes, "approvals.enforce") || !strings.Contains(notes, "audit.anchor") {
		t.Fatalf("notes:\n%s", notes)
	}
	h.ok("config", "set", "approvals.enforce", "true")
	h.ok("config", "set", "audit.anchor.enabled", "true")
	if err := json.Unmarshal([]byte(h.ok("doctor", "--json")), &rep); err != nil {
		t.Fatal(err)
	}
	if n := strings.Join(rep.Notes, "\n"); strings.Contains(n, "approvals.enforce") || strings.Contains(n, "audit.anchor") {
		t.Fatalf("notes after turning both on:\n%s", n)
	}
}
