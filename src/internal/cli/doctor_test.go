package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sangehq/imprimatur/src/internal/execx"
)

// O-162, old bug 6: doctor's "not ok" is not the usage code. A host that is
// not ready exits 5 (unavailable), so a caller can tell it from a mistyped
// command, which still exits 1.
func TestDoctorNotOKIsNotUsage(t *testing.T) {
	h := newHarness(t)
	code, out, _ := h.impr("doctor", "--json")
	if code != 5 || !strings.Contains(out, `"ok":false`) {
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
