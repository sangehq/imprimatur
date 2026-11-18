package cli

import (
	"crypto/x509/pkix"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sangehq/imprimatur/src/internal/artifact"
	"github.com/sangehq/imprimatur/src/internal/backend"
	"github.com/sangehq/imprimatur/src/internal/signing"
	"github.com/sangehq/imprimatur/src/internal/testpe"
)

func azureProfile(h *harness, name, subject string) {
	h.ok("profile", "add", name, "--scope", "personal", "--owner", "me", "--purpose", "internal",
		"--set", "platforms.windows.kind=authenticode", "--set", "platforms.windows.backend=azure-artifact-signing",
		"--set", "platforms.windows.subject="+subject, "--set", `platforms.windows.dlibPath=C:\d\Azure.CodeSigning.Dlib.dll`,
		"--set", `platforms.windows.metadataPath=C:\d\metadata.json`)
}

// Security review R6 (I-15): impr rules from a build checks the files against
// the signed record beside the build manifest, and the signer against the
// profile, so a committed binary signed by someone else's certificate, or a
// file swapped after signing, gets no allow rules.
func TestRulesFromManifestCheckDigestsAndSigner(t *testing.T) {
	repo := goRepo(t)
	h := newHarness(t)
	h.ok("build", "--repo-root", repo, "--targets", "windows/amd64", "--version", "v1.2.0", "--product", "Acme Tool")
	ca := testpe.NewIntermediate(t, "Acme CA", testpe.NewCA(t, "Root"))
	rel := "build/windows/hello_windows_amd64.exe"
	exe := filepath.Join(repo, filepath.FromSlash(rel))
	testpe.SignFile(t, exe, pkix.Name{CommonName: "Acme Ltd", Organization: []string{"Acme Ltd"}, Country: []string{"GB"}}, ca)
	s, err := backend.ReadPESigner(exe)
	if err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(repo, "build", "build-manifest.json")
	bm, err := artifact.ReadManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	sum, err := artifact.SHA256(exe)
	if err != nil {
		t.Fatal(err)
	}
	writeRecord := func(profileName, digest string) {
		t.Helper()
		raw, err := json.Marshal(signing.Manifest{Schema: signing.ManifestSchema, Profile: profileName, BuildManifestDigest: bm.Digest,
			Artifacts: []signing.SignedArtifact{{Path: rel, OutputSHA256: digest, Platform: "windows"}}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(repo, "build", signing.ManifestFile), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	azureProfile(h, "acme", s.Subject)
	azureProfile(h, "other", "CN=Someone Else")

	writeRecord("acme", sum)
	h.ok("rules", "--manifest", manifest, "--json")
	h.ok("rules", "--manifest", manifest, "--json", "--strict")

	// The record's profile pins another certificate.
	writeRecord("other", sum)
	if out := h.exits(4, "rules", "--manifest", manifest, "--json"); strings.Contains(out, "appLocker\":\"<") {
		t.Fatalf("rules written for a signer the profile does not pin: %s", out)
	}
	// --profile overrides the record's.
	h.ok("rules", "--manifest", manifest, "--profile", "acme", "--json")
	h.exits(4, "rules", exe, "--profile", "other", "--json")

	// The file on disk is not the one the record lists.
	writeRecord("acme", strings.Repeat("0", 64))
	h.exits(4, "rules", "--manifest", manifest, "--json")

	// No record: refused by default (owner decision D-S3, ID-30); the
	// explicit opt-out renders with a note, and --strict still refuses.
	if err := os.Remove(filepath.Join(repo, "build", signing.ManifestFile)); err != nil {
		t.Fatal(err)
	}
	h.exits(4, "rules", "--manifest", manifest, "--json")
	if _, _, errOut := h.impr("rules", "--manifest", manifest, "--json", "--without-signed-record"); !strings.Contains(errOut, "not checked") {
		t.Fatalf("the opt-out says nothing: %s", errOut)
	}
	h.ok("rules", "--manifest", manifest, "--json", "--without-signed-record")
	h.exits(4, "rules", "--manifest", manifest, "--json", "--strict", "--without-signed-record")
}
