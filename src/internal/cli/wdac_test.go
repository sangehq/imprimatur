package cli

import (
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
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
	exe, _ := testpe.SignedWithEKUs(t, t.TempDir(), "tool.exe", sub, ca, generic, prof)
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
