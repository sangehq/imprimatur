package backend

import (
	"context"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/execx"
	"github.com/sangehq/imprimatur/src/internal/profile"
)

// devIDP12 makes a Developer ID-shaped code-signing certificate issued by a
// test CA, and puts that CA in place of Apple's through the appleTrust seam
// for the rest of the test.
func devIDP12(t *testing.T, cn, team string) (p12 []byte, password string) {
	t.Helper()
	ca := newDevIDCA(t)
	useTestAppleTrust(t, ca)
	return ca.p12(t, leafOpts{cn: cn, team: team})
}

func tinyMachO(t *testing.T) string {
	t.Helper()
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("needs go to build a Mach-O")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc main() { println(\"hi\") }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module tiny\n\ngo 1.23\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "tiny")
	cmd := exec.Command(gobin, "build", "-o", out, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS=darwin", "GOARCH=arm64", "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build a Mach-O: %v %s", err, b)
	}
	return out
}

// noTimestamp signs without Apple's time-stamp service, which a test cannot
// reach.
func noTimestamp(t *testing.T) {
	t.Helper()
	old := appleTimestampServer
	appleTimestampServer = ""
	t.Cleanup(func() { appleTimestampServer = old })
}

func offMacProfile(spec profile.MacOSSpec) profile.Profile {
	return profile.Profile{Name: "mac", Scope: profile.ScopePersonal, Owner: "me", Purpose: []profile.Purpose{profile.PurposeTest},
		Platforms: profile.Platforms{MacOS: &spec}}
}

// O-140 (ID-36): off a Mac, a Developer ID profile with a .p12 signs a Mach-O
// in Go (anchore/quill's signing packages), with the hardened runtime, as the
// PowerShell line's GoReleaser template did from Windows and Linux. The .p12
// and its password come only through impr's references. On this Mac,
// codesign checks the result and names the pinned identity and team.
func TestAppleSignsOffAMac(t *testing.T) {
	const cn, team = "Developer ID Application: Example (TEAM123456)", "TEAM123456"
	noTimestamp(t)
	p12, pw := devIDP12(t, cn, team)
	bin := tinyMachO(t)
	before, _ := os.ReadFile(bin)
	h := fakeHost("linux", execx.NewFake(), map[string]string{"P12": base64.StdEncoding.EncodeToString(p12), "P12PW": pw})
	a := &Apple{H: h, Spec: profile.MacOSSpec{Kind: "developer-id", TeamID: team, Identity: cn, CertRef: "env://P12", PasswordRef: "env://P12PW"}}
	if c := a.Capability(h); !c.Sign {
		t.Fatalf("off a Mac with a .p12, signing is not offered: %+v", c)
	}
	sig, err := a.Sign(context.Background(), Artifact{Path: bin, Rel: "build/macos/tiny"}, offMacProfile(a.Spec))
	if err != nil {
		t.Fatal(err)
	}
	if sig.Kind != "developer-id" || sig.Signer != cn {
		t.Fatalf("signature %+v", sig)
	}
	after, _ := os.ReadFile(bin)
	if string(after) == string(before) {
		t.Fatal("the binary did not change")
	}
	if strings.Contains(string(after), pw) {
		t.Fatal("the .p12 password reached the binary")
	}
	if runtime.GOOS != "darwin" {
		return
	}
	if _, err := exec.LookPath("codesign"); err != nil {
		return
	}
	// The test identity is self-signed, so codesign's only complaint may be
	// that it does not trust it; the code hashes and the signature must hold.
	if out, err := exec.Command("codesign", "--verify", "--verbose=2", bin).CombinedOutput(); err != nil && !strings.Contains(string(out), "CSSMERR_TP_NOT_TRUSTED") {
		t.Fatalf("codesign -v: %v %s", err, out)
	}
	// codesign evaluates trust before the code hashes (measured 2026-11-25:
	// a changed byte also answers CSSMERR_TP_NOT_TRUSTED), so with a
	// self-signed identity it cannot vouch for the hashes; codesign -d below
	// reads what quill wrote.
	out, _ := exec.Command("codesign", "-d", "--verbose=4", bin).CombinedOutput()
	// Authority is "(unavailable)" for an untrusted identity; the team, the
	// hardened runtime, a CMS signature and a CMS digest equal to the code
	// directory's hash are what codesign reads back.
	for _, want := range []string{"TeamIdentifier=" + team, "flags=0x10000(runtime)", "Identifier=tiny", "Hash type=sha256"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("codesign -d lacks %q:\n%s", want, out)
		}
	}
	cd := regexp.MustCompile(`CandidateCDHashFull sha256=([0-9a-f]{64})`).FindStringSubmatch(string(out))
	cms := regexp.MustCompile(`CMSDigest=([0-9a-f]{64})`).FindStringSubmatch(string(out))
	size := regexp.MustCompile(`Signature size=([1-9][0-9]*)`).FindStringSubmatch(string(out))
	if cd == nil || cms == nil || cd[1] != cms[1] || size == nil {
		t.Errorf("no CMS signature over the code directory:\n%s", out)
	}
}

// A .p12 whose certificate is not the pinned identity or team is refused
// before anything is signed; so is a profile with no .p12 off a Mac.
func TestAppleOffAMacSignsOnlyThePinnedIdentity(t *testing.T) {
	p12, pw := devIDP12(t, "Developer ID Application: Someone Else (OTHER12345)", "OTHER12345")
	bin := tinyMachO(t)
	before, _ := os.ReadFile(bin)
	h := fakeHost("windows", execx.NewFake(), map[string]string{"P12": base64.StdEncoding.EncodeToString(p12), "P12PW": pw})
	a := &Apple{H: h, Spec: profile.MacOSSpec{Kind: "developer-id", TeamID: "TEAM123456", Identity: "Developer ID Application: Example (TEAM123456)",
		CertRef: "env://P12", PasswordRef: "env://P12PW"}}
	_, err := a.Sign(context.Background(), Artifact{Path: bin, Rel: "tiny"}, offMacProfile(a.Spec))
	wantCode(t, err, contract.SignFailed)
	if strings.Contains(err.Error(), pw) {
		t.Fatal("the error names the password")
	}
	if after, _ := os.ReadFile(bin); string(after) != string(before) {
		t.Fatal("a refused signing changed the binary")
	}
	none := &Apple{H: h, Spec: profile.MacOSSpec{Kind: "developer-id", TeamID: "TEAM123456", Identity: "x"}}
	if c := none.Capability(h); c.Sign || !strings.Contains(c.Reason, "certRef") {
		t.Fatalf("off a Mac without a .p12: %+v", c)
	}
}
