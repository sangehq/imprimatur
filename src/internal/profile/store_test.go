package profile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sangehq/imprimatur/src/internal/contract"
)

func testProfile(t *testing.T, name string, purpose Purpose) Profile {
	t.Helper()
	return Profile{Name: name, Scope: ScopePersonal, Owner: "me", Purpose: []Purpose{purpose},
		Platforms: Platforms{Checksums: &ChecksumSpec{Kind: "ssh", KeyRef: "env://IMPR_TEST_KEY", Fingerprint: "SHA256:" + randHex(t, 16)}}}
}

func TestStoreSaveAndResolve(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	if _, err := s.Resolve(""); contract.CodeOf(err) != contract.Usage || !strings.Contains(err.Error(), "no signing profile") {
		t.Fatalf("no default must be a usage error, got %v", err)
	}
	if _, err := s.Resolve("nope"); contract.CodeOf(err) != contract.Usage {
		t.Fatalf("a missing profile must be a usage error, got %v", err)
	}
	p := testProfile(t, "me-test", PurposeTest)
	if err := s.Save(p, false); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(p, false); err == nil {
		t.Fatal("saving over an existing profile without replace succeeded")
	}
	bad := p
	bad.Purpose = []Purpose{PurposeTest, PurposeRelease}
	if err := s.Save(bad, true); err == nil || !strings.Contains(strings.Join(err.(*contract.Error).Details, " "), "profile.purpose") {
		t.Fatalf("an invalid profile was saved: %v", err)
	}
	st, err := os.Stat(filepath.Join(s.Dir, "profiles", "me-test.json"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("profile file mode: %v %v", st, err)
	}
	if _, err := s.Resolve(""); err == nil {
		t.Fatal("Resolve fell back to a profile with no default chosen")
	}
	if err := s.SaveIndex(Index{Default: "me-test"}); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Resolve(""); err != nil || got.Name != "me-test" {
		t.Fatalf("default: %v %v", got.Name, err)
	}
	if _, err := s.Path("../escape"); err == nil {
		t.Fatal("a path-like name was accepted")
	}
}

func TestManagedProfilesAreReadOnly(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	p := testProfile(t, "corp", PurposeInternal)
	p.Managed = true
	if err := s.WriteUnchecked(p); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(p, true); err == nil || !strings.Contains(err.Error(), "managed") {
		t.Fatalf("a managed profile was replaced: %v", err)
	}
	if err := s.Remove("corp"); err == nil {
		t.Fatal("a managed profile was removed")
	}
}

func legacyEnv(t *testing.T, cfg string, env map[string]string) LegacyEnv {
	t.Helper()
	return LegacyEnv{GOOS: "linux", Home: t.TempDir(), User: "Pat Doe", ConfigDir: cfg,
		Getenv: func(k string) string { return env[k] }, Now: time.Now}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, _ := json.Marshal(v)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestImportLegacyCertumBecomesTheDefaultButNotARelease(t *testing.T) {
	legacy := t.TempDir()
	writeJSON(t, filepath.Join(legacy, LegacySettingsFile), map[string]string{"WINDOWS_SIGNER": "Certum", "CERTUM_SUBJECT": "Open Source Developer, Pat Doe"})
	s := Store{Dir: t.TempDir()}
	rep, err := ImportLegacy(s, legacy, legacyEnv(t, s.Dir, nil))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Default != "default" || len(rep.Imported) != 1 {
		t.Fatalf("report: %+v", rep)
	}
	p, err := s.Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	if p.Platforms.Windows.Backend != BackendCertum || p.HasPurpose(PurposeRelease) || p.Owner != "pat-doe" {
		t.Fatalf("profile: %+v", p)
	}
	// It runs once: a second import keeps the existing profile.
	writeJSON(t, filepath.Join(legacy, LegacySettingsFile), map[string]string{"WINDOWS_SIGNER": "Artifact"})
	rep, err = ImportLegacy(s, legacy, legacyEnv(t, s.Dir, nil))
	if err != nil || len(rep.Imported) != 0 || len(rep.Skipped) != 1 {
		t.Fatalf("second import: %+v %v", rep, err)
	}
	if p, _ := s.Resolve("default"); p.Platforms.Windows.Backend != BackendCertum {
		t.Fatal("the second import replaced the profile")
	}
}

func TestImportLegacySelfSignedIsATestProfile(t *testing.T) {
	legacy := t.TempDir()
	thumb := randHex(t, 20)
	writeJSON(t, filepath.Join(legacy, LegacySettingsFile), map[string]string{"WINDOWS_SIGNER": "SelfSigned", "WINDOWS_SIGN_THUMBPRINT": thumb, "GPG_FINGERPRINT": randHex(t, 20)})
	s := Store{Dir: t.TempDir()}
	if _, err := ImportLegacy(s, legacy, legacyEnv(t, s.Dir, nil)); err != nil {
		t.Fatal(err)
	}
	p, _ := s.Resolve("default")
	if !p.HasPurpose(PurposeTest) || p.Platforms.Windows.Thumbprint != thumb || p.Platforms.Checksums == nil {
		t.Fatalf("profile: %+v", p)
	}
	if ps := p.Validate(); len(ps) != 0 {
		t.Fatalf("a migrated test profile should be complete: %v", ps.Strings())
	}
}

func TestImportLegacyMacOSVariablesAreReferencesOnly(t *testing.T) {
	secret := randHex(t, 24)
	env := map[string]string{"MACOS_SIGN_P12": secret, "MACOS_NOTARY_KEY": secret, "MACOS_NOTARY_KEY_ID": secret, "MACOS_NOTARY_ISSUER_ID": secret}
	s := Store{Dir: t.TempDir()}
	rep, err := ImportLegacy(s, t.TempDir(), legacyEnv(t, s.Dir, env))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Imported) != 1 || rep.Imported[0] != "default-macos" {
		t.Fatalf("report: %+v", rep)
	}
	b, _ := s.Raw("default-macos")
	if strings.Contains(string(b), secret) {
		t.Fatal("a secret value was written into a profile")
	}
	if !strings.Contains(string(b), "env://MACOS_NOTARY_KEY") {
		t.Fatalf("the notary key reference is missing: %s", b)
	}
}

func TestImportLegacyBringsPowerShellProfiles(t *testing.T) {
	legacy := t.TempDir()
	p := testProfile(t, "ps-profile", PurposeTest)
	writeJSON(t, filepath.Join(legacy, "profiles", "ps-profile.json"), p)
	writeJSON(t, filepath.Join(legacy, "profiles.json"), Index{Default: "ps-profile"})
	s := Store{Dir: t.TempDir()}
	rep, err := ImportLegacy(s, legacy, legacyEnv(t, s.Dir, nil))
	if err != nil || rep.Default != "ps-profile" {
		t.Fatalf("%+v %v", rep, err)
	}
}

func TestFindLegacyFollowsTheInstalledLink(t *testing.T) {
	home, toolkit := t.TempDir(), t.TempDir()
	for _, d := range []string{"bin", "src", "config"} {
		if err := os.MkdirAll(filepath.Join(toolkit, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(toolkit, "src", "impr.ps1"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(toolkit, "bin", "impr"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".local", "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(toolkit, "bin", "impr"), filepath.Join(home, ".local", "bin", "impr")); err != nil {
		t.Fatal(err)
	}
	e := LegacyEnv{Home: home, Getenv: func(string) string { return "" }}
	got := FindLegacy(e)
	want, _ := filepath.EvalSymlinks(filepath.Join(toolkit, "config"))
	if g, _ := filepath.EvalSymlinks(got); g != want {
		t.Fatalf("found %q, want %q", got, want)
	}
	e.Getenv = func(k string) string {
		if k == "IMPR_LEGACY_CONFIG" {
			return "off"
		}
		return ""
	}
	if FindLegacy(e) != "" {
		t.Fatal("IMPR_LEGACY_CONFIG=off did not disable discovery")
	}
}
