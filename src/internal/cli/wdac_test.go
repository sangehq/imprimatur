package cli

import (
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sangehq/imprimatur/src/internal/testpe"
)

const testBasePolicy = "{6b2a1c3d-0000-4000-8000-00000000abcd}"

// O-180: impr rules FILE... pins the certificate below the root, not the CA
// right above the leaf.
func TestRulesPinTheCertificateBelowTheRoot(t *testing.T) {
	h := newHarness(t)
	sub := pkix.Name{CommonName: "Acme Ltd", Organization: []string{"Acme Ltd"}, Country: []string{"GB"}}
	pca := testpe.NewIntermediate(t, "Acme Code Signing PCA", testpe.NewCA(t, "Acme Root"))
	eoc := testpe.NewIntermediate(t, "Acme EOC CA 01", pca)
	exe, _ := testpe.Signed(t, t.TempDir(), "tool.exe", sub, eoc.WithoutRoot())
	out := h.ok("rules", exe, "--product", "Acme Tool", "--base-policy", testBasePolicy, "--json")
	pcaTBS := sha256.Sum256(pca.Cert.RawTBSCertificate)
	eocTBS := sha256.Sum256(eoc.Cert.RawTBSCertificate)
	if !strings.Contains(strings.ToUpper(out), strings.ToUpper(hex.EncodeToString(pcaTBS[:]))) ||
		strings.Contains(strings.ToUpper(out), strings.ToUpper(hex.EncodeToString(eocTBS[:]))) {
		t.Fatalf("WDAC does not pin the PCA:\n%s", out)
	}
}

// O-181 and the design conversation: WDAC rules for Artifact Signing key on
// the CA plus the certificate profile's own EKU, found in the file; the
// generic Artifact Signing EKU, which every customer carries, is refused.
func TestRulesUseTheArtifactSigningProfileEKU(t *testing.T) {
	h := newHarness(t)
	sub := pkix.Name{CommonName: "Acme Ltd", Organization: []string{"Acme Ltd"}, Country: []string{"US"}}
	ca := testpe.NewIntermediate(t, "Microsoft ID Verified CS EOC CA 01", testpe.NewCA(t, "Root"))
	generic := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 97, 1, 0}
	prof := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 97, 990309390, 766961637, 919164696, 192717234}
	exe, _ := testpe.SignedWith(t, t.TempDir(), "tool.exe", sub, ca, testpe.Options{EKUs: []asn1.ObjectIdentifier{generic, prof}})
	code, out, e := h.impr("rules", exe, "--product", "Acme Tool", "--base-policy", testBasePolicy, "--json")
	if code != 0 || !strings.Contains(out, "signer EKU "+prof.String()) || !strings.Contains(e, prof.String()) {
		t.Fatalf("the profile EKU was not pinned: %d\n%s\n%s", code, out, e)
	}
	if code, _, e := h.impr("rules", exe, "--product", "Acme Tool", "--base-policy", testBasePolicy, "--eku", generic.String()); code != 1 || !strings.Contains(e, "every Artifact Signing customer") {
		t.Fatalf("the generic EKU was accepted: %d %s", code, e)
	}
	if code, _, e := h.impr("rules", exe, "--product", "Acme Tool", "--base-policy", testBasePolicy, "--eku", "1.3.6.1.4.1.311.97.1.2.3"); code != 1 || !strings.Contains(e, "does not carry") {
		t.Fatalf("an EKU the file lacks was accepted: %d %s", code, e)
	}
}

// O-173: impr rules checks each file against its own signature first, and
// says when a signature carries no timestamp (it stops being valid when the
// certificate expires, and allow rules then pin a dead signature).
func TestRulesCheckTheSignatureAndTheTimestamp(t *testing.T) {
	h := newHarness(t)
	sub := pkix.Name{CommonName: "Acme Ltd", Organization: []string{"Acme Ltd"}, Country: []string{"GB"}}
	ca := testpe.NewIntermediate(t, "Acme CA", testpe.NewCA(t, "Acme Root"))
	exe, _ := testpe.Signed(t, t.TempDir(), "tool.exe", sub, ca)
	stamped, _ := testpe.SignedWith(t, t.TempDir(), "tool.exe", sub, ca, testpe.Options{Timestamped: true})

	if _, _, e := h.impr("rules", exe, "--product", "Acme Tool"); !strings.Contains(e, "no timestamp") {
		t.Errorf("no warning for an untimestamped signature: %s", e)
	}
	if code, _, e := h.impr("rules", stamped, "--product", "Acme Tool"); code != 0 || strings.Contains(e, "no timestamp") {
		t.Errorf("a timestamped file: %d %s", code, e)
	}

	b, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	b[10] ^= 1 // a byte the signature covers
	if err := os.WriteFile(exe, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, e := h.impr("rules", exe, "--product", "Acme Tool", "--json"); code != 4 || !strings.Contains(e, "changed after it was signed") || strings.Contains(out, "AppLockerPolicy") {
		t.Fatalf("a tampered file: exit %d, want 4\n%s\n%s", code, out, e)
	}
}

// Builds signed on different days under Artifact Signing carry different
// issuing CAs below one PCA. They are one publisher to WDAC, which pins the
// PCA, so impr makes one set of rules from them; a different PCA is refused.
func TestRulesAcceptRotatedIssuingCAsUnderOnePCA(t *testing.T) {
	h := newHarness(t)
	sub := pkix.Name{CommonName: "Acme Ltd", Organization: []string{"Acme Ltd"}, Country: []string{"US"}}
	root := testpe.NewCA(t, "Root")
	pca := testpe.NewIntermediate(t, "Acme Code Signing PCA", root)
	day1, _ := testpe.Signed(t, t.TempDir(), "tool.exe", sub, testpe.NewIntermediate(t, "EOC CA 01", pca).WithoutRoot())
	day2, _ := testpe.Signed(t, t.TempDir(), "tool.exe", sub, testpe.NewIntermediate(t, "EOC CA 02", pca).WithoutRoot())
	code, out, e := h.impr("rules", day1, day2, "--product", "Acme Tool", "--base-policy", testBasePolicy, "--json")
	pcaTBS := sha256.Sum256(pca.Cert.RawTBSCertificate)
	if code != 0 || !strings.Contains(strings.ToUpper(out), strings.ToUpper(hex.EncodeToString(pcaTBS[:]))) {
		t.Fatalf("two issuing CAs under one PCA: %d\n%s\n%s", code, out, e)
	}
	other := testpe.NewIntermediate(t, "Other PCA", root)
	day3, _ := testpe.Signed(t, t.TempDir(), "tool.exe", sub, testpe.NewIntermediate(t, "EOC CA 03", other).WithoutRoot())
	h.exits(1, "rules", day1, day3, "--product", "Acme Tool", "--base-policy", testBasePolicy)
}

// ID-20, O-172, O-175, O-185: with no FILE, impr rules reads the Windows
// files of the build manifest; it names binaries by their OriginalFilename
// (so the amd64 and arm64 builds make one rule, as the PowerShell grouping
// did), takes the version scope's minimum version from the files, and names
// the rules after the product.
func TestRulesDefaultsFromTheBuild(t *testing.T) {
	repo := goRepo(t)
	h := newHarness(t)
	h.ok("build", "--repo-root", repo, "--targets", "windows/amd64,windows/arm64,linux/amd64", "--version", "v1.2.0", "--product", "Acme Tool")
	ca := testpe.NewIntermediate(t, "Acme CA", testpe.NewCA(t, "Root"))
	sub := pkix.Name{CommonName: "Acme Ltd", Organization: []string{"Acme Ltd"}, Country: []string{"GB"}}
	for _, a := range []string{"amd64", "arm64"} {
		testpe.SignFile(t, filepath.Join(repo, "build", "windows", "hello_windows_"+a+".exe"), sub, ca)
	}
	manifest := filepath.Join(repo, "build", "build-manifest.json")
	var res struct {
		AppLocker string `json:"appLocker"`
		Files     []struct {
			Path string `json:"path"`
		} `json:"files"`
	}
	out := h.ok("rules", "--manifest", manifest, "--scope", "version", "--json")
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 2 || strings.Count(res.AppLocker, `BinaryName="HELLO.EXE"`) != 1 ||
		!strings.Contains(res.AppLocker, `LowSection="1.2.0.0"`) || !strings.Contains(res.AppLocker, "Acme Tool") {
		t.Fatalf("rules from the build:\n%s", out)
	}
	// Files and --manifest together are a mistake.
	h.exits(1, "rules", "--manifest", manifest, filepath.Join(repo, "build", "windows", "hello_windows_amd64.exe"))
}
