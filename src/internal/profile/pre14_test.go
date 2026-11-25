package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// toolkit makes a PowerShell toolkit folder (src/impr.ps1 marks one) with
// files at the places impr 1.3 and earlier kept them, in the toolkit root.
func toolkit(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "src", "impr.ps1"), []byte("# impr"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// O-09: before 1.4 the toolkit kept its settings, state and metadata.json in
// its root; the PowerShell line moved them into config/ (Move-LegacyConfig),
// and so does an import from that toolkit, before reading them.
func TestImportLegacyMovesPre14FilesIntoConfig(t *testing.T) {
	root := toolkit(t, map[string]string{
		LegacySettingsFile:      `{"WINDOWS_SIGNER":"Certum","CERTUM_SUBJECT":"Open Source Developer, Pat Doe"}`,
		".imprimatur-state.json": `{}`,
		"metadata.json":          `{"Endpoint":"https://weu.codesigning.azure.net"}`,
	})
	s := Store{Dir: t.TempDir()}
	rep, err := ImportLegacy(s, filepath.Join(root, "config"), legacyEnv(t, s.Dir, nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{LegacySettingsFile, ".imprimatur-state.json", "metadata.json"} {
		if _, err := os.Stat(filepath.Join(root, "config", name)); err != nil {
			t.Errorf("%s was not moved into config/: %v", name, err)
		}
		if _, err := os.Stat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Errorf("%s is still in the toolkit root", name)
		}
	}
	if rep.Default != "default" || !strings.Contains(strings.Join(rep.Notes, "\n"), "moved "+LegacySettingsFile) {
		t.Fatalf("report: %+v", rep)
	}
}

// A file in both places is left where it is, and the one in config/ used,
// as the PowerShell line did; a folder that is not a toolkit is never touched.
func TestPre14MoveKeepsTheNewerAndOnlyTouchesAToolkit(t *testing.T) {
	root := toolkit(t, map[string]string{LegacySettingsFile: `{"WINDOWS_SIGNER":"Artifact"}`})
	if err := os.MkdirAll(filepath.Join(root, "config"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, filepath.Join(root, "config", LegacySettingsFile), map[string]string{"WINDOWS_SIGNER": "Certum", "CERTUM_SUBJECT": "Open Source Developer, Pat Doe"})
	s := Store{Dir: t.TempDir()}
	rep, err := ImportLegacy(s, filepath.Join(root, "config"), legacyEnv(t, s.Dir, nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, LegacySettingsFile)); err != nil || !strings.Contains(strings.Join(rep.Notes, "\n"), "both") {
		t.Fatalf("the root file was moved or not reported: %v %+v", err, rep.Notes)
	}
	if p, _ := s.Resolve(""); p.Platforms.Windows == nil || p.Platforms.Windows.Backend != BackendCertum {
		t.Fatal("the config/ file was not the one used")
	}
	plain := t.TempDir()
	if err := os.WriteFile(filepath.Join(plain, LegacySettingsFile), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ImportLegacy(Store{Dir: t.TempDir()}, filepath.Join(plain, "config"), legacyEnv(t, t.TempDir(), nil)); err == nil {
		t.Fatal("a folder that is not a toolkit was read")
	}
	if _, err := os.Stat(filepath.Join(plain, LegacySettingsFile)); err != nil {
		t.Fatal("a file outside a toolkit was moved")
	}
}
