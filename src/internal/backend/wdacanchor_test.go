package backend

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/sangehq/imprimatur/src/internal/testpe"
)

// O-180: WDAC's Publisher level pins the highest certificate below the root
// (the PowerShell Get-PcaCertificate), not the CA directly above the leaf,
// which for Artifact Signing rotates often.
func TestReadPESignerPinsTheCertificateBelowTheRoot(t *testing.T) {
	sub := pkix.Name{CommonName: "Acme Ltd", Organization: []string{"Acme Ltd"}}
	root := testpe.NewCA(t, "Acme Root")
	pca := testpe.NewIntermediate(t, "Acme Code Signing PCA", root)
	eoc := testpe.NewIntermediate(t, "Acme EOC CA 01", pca)
	for _, c := range []struct {
		name string
		ca   testpe.CA
		want string
	}{
		{"root, PCA and EOC CA embedded", eoc, "Acme Code Signing PCA"},
		{"root left out", eoc.WithoutRoot(), "Acme Code Signing PCA"},
		{"one intermediate under the root", pca, "Acme Code Signing PCA"},
		// WDAC cannot pin a root, so a leaf issued straight by one pins itself.
		{"leaf issued by the root", root, "Acme Ltd"},
	} {
		path, _ := testpe.Signed(t, t.TempDir(), "tool.exe", sub, c.ca)
		s, err := ReadPESigner(path)
		if err != nil {
			t.Fatal(err)
		}
		if s.PCA == nil || s.PCA.Subject.CommonName != c.want {
			got := "<nil>"
			if s.PCA != nil {
				got = s.PCA.Subject.CommonName
			}
			t.Errorf("%s: WDAC pins %s, want %s", c.name, got, c.want)
		}
	}
}

// O-181: an Artifact Signing certificate carries the generic Artifact Signing
// EKU and its certificate profile's own EKU under 1.3.6.1.4.1.311.97; the
// profile's is the one a WDAC rule must pin.
func TestReadPESignerFindsTheArtifactSigningProfileEKU(t *testing.T) {
	sub := pkix.Name{CommonName: "Acme Ltd", Organization: []string{"Acme Ltd"}}
	ca := testpe.NewIntermediate(t, "Microsoft ID Verified CS EOC CA 01", testpe.NewCA(t, "Root"))
	generic := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 97, 1, 0}
	prof := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 97, 990309390, 766961637, 919164696, 192717234}
	path, _ := testpe.SignedWithEKUs(t, t.TempDir(), "tool.exe", sub, ca, generic, prof)
	s, err := ReadPESigner(path)
	if err != nil {
		t.Fatal(err)
	}
	if !s.ArtifactSigning || s.ProfileEKU != prof.String() {
		t.Fatalf("artifact signing %v, profile EKU %q; want %s", s.ArtifactSigning, s.ProfileEKU, prof)
	}
	plain, _ := testpe.Signed(t, t.TempDir(), "plain.exe", sub, ca)
	if s, _ := ReadPESigner(plain); s.ArtifactSigning || s.ProfileEKU != "" {
		t.Fatalf("a plain code signing certificate read as Artifact Signing: %+v", s.ProfileEKU)
	}
}
