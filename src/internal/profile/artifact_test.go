package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// O-109: an Artifact Signing profile names its dlib and metadata.json, so
// validation says what is missing instead of signing failing later with
// "not found at \"\"".
func TestArtifactProfileNeedsDlibAndMetadata(t *testing.T) {
	az := func(dlib, meta string) Profile {
		p := releaseProfile(t)
		p.Platforms.Windows = &WindowsSpec{Kind: "authenticode", Backend: BackendAzure, Subject: "CN=Acme Ltd", DlibPath: dlib, MetadataPath: meta}
		return p
	}
	if ps := az(`C:\dlib\Azure.CodeSigning.Dlib.dll`, `C:\cfg\metadata.json`).Validate(); len(ps) != 0 {
		t.Fatalf("a complete Artifact profile: %v", ps.Strings())
	}
	for _, c := range []struct {
		p    Profile
		code string
	}{
		{az("", `C:\cfg\metadata.json`), "platforms.windows.dlibPath"},
		{az(`C:\dlib\Azure.CodeSigning.Dlib.dll`, ""), "platforms.windows.metadataPath"},
	} {
		if got := codes(c.p.Validate()); !strings.Contains(got, c.code) {
			t.Errorf("want %s, got %s", c.code, got)
		}
	}
	// The same inside signers[].
	p := releaseProfile(t)
	p.Platforms.Windows = &WindowsSpec{Kind: "authenticode", Mode: "select", Signers: []WindowsSigner{
		{ID: "az", Backend: BackendAzure, Subject: "CN=Acme Ltd"}}}
	if got := codes(p.Validate()); !strings.Contains(got, "platforms.windows.signers[0].dlibPath") || !strings.Contains(got, "platforms.windows.signers[0].metadataPath") {
		t.Errorf("signers[]: %s", got)
	}
}

// O-109: the PowerShell line kept Artifact Signing's metadata.json in its
// config folder by default; an import that finds it there uses it.
func TestImportLegacyArtifactUsesTheDefaultMetadata(t *testing.T) {
	legacy := t.TempDir()
	meta := filepath.Join(legacy, "metadata.json")
	if err := os.WriteFile(meta, []byte(`{"Endpoint":"https://weu.codesigning.azure.net"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, filepath.Join(legacy, LegacySettingsFile), map[string]string{"WINDOWS_SIGNER": "Artifact", "ARTIFACT_DLIB": `C:\dlib\Azure.CodeSigning.Dlib.dll`})
	s := Store{Dir: t.TempDir()}
	if _, err := ImportLegacy(s, legacy, legacyEnv(t, s.Dir, nil)); err != nil {
		t.Fatal(err)
	}
	p, err := s.Resolve("default")
	if err != nil {
		t.Fatal(err)
	}
	if p.Platforms.Windows.MetadataPath != meta {
		t.Fatalf("metadataPath %q, want the legacy default %q", p.Platforms.Windows.MetadataPath, meta)
	}
}

// O-193: the Certum thumbprint the PowerShell line read from CERTUM_THUMBPRINT
// comes along, so an imported Certum profile validates without edits.
func TestImportLegacyCertumKeepsItsThumbprint(t *testing.T) {
	thumb := strings.ToUpper(randHex(t, 20))
	for _, c := range []struct {
		name     string
		settings map[string]string
		env      map[string]string
	}{
		{"from the environment", map[string]string{"WINDOWS_SIGNER": "Certum", "CERTUM_SUBJECT": "Open Source Developer, Pat Doe"},
			map[string]string{"CERTUM_THUMBPRINT": strings.ToLower(thumb[:20]) + " " + thumb[20:]}},
		{"from the settings file", map[string]string{"WINDOWS_SIGNER": "Certum", "CERTUM_SUBJECT": "Open Source Developer, Pat Doe", "CERTUM_THUMBPRINT": thumb}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			legacy := t.TempDir()
			writeJSON(t, filepath.Join(legacy, LegacySettingsFile), c.settings)
			s := Store{Dir: t.TempDir()}
			rep, err := ImportLegacy(s, legacy, legacyEnv(t, s.Dir, c.env))
			if err != nil {
				t.Fatal(err)
			}
			p, err := s.Resolve("default")
			if err != nil {
				t.Fatal(err)
			}
			if p.Platforms.Windows.Thumbprint != thumb || len(rep.Problems) != 0 {
				t.Fatalf("thumbprint %q (want %q), problems %v", p.Platforms.Windows.Thumbprint, thumb, rep.Problems)
			}
		})
	}
}
