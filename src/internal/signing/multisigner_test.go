package signing

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sangehq/imprimatur/src/internal/backend"
	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/profile"
)

// minimalPE is a PE32+ header with the given machine, enough for debug/pe.
func minimalPE(machine uint16, salt string) []byte {
	b := make([]byte, 0x400)
	copy(b, "MZ")
	binary.LittleEndian.PutUint32(b[0x3c:], 0x80)
	copy(b[0x80:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(b[0x84:], machine)
	binary.LittleEndian.PutUint16(b[0x94:], 240)
	binary.LittleEndian.PutUint16(b[0x98:], 0x20b)
	binary.LittleEndian.PutUint32(b[0x98+108:], 16)
	return append(b, salt...)
}

// fakeWin records which certificate signed which file.
type fakeWin struct {
	mu     *sync.Mutex
	signed map[string]string // rel -> thumbprint
	thumb  string
}

func (f *fakeWin) Capability(backend.Host) backend.Capability {
	return backend.Capability{Platform: profile.Windows, Sign: true, Verify: true, Supported: true}
}
func (f *fakeWin) Certificate(context.Context, profile.Profile) backend.CertEntry {
	return backend.CertEntry{Platform: profile.Windows, Thumbprint: f.thumb, Present: true, Source: "declared"}
}
func (f *fakeWin) Sign(_ context.Context, a backend.Artifact, _ profile.Profile) (backend.Signature, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signed[a.Rel] = f.thumb
	return backend.Signature{Kind: "authenticode", Signer: f.thumb}, nil
}
func (f *fakeWin) Verify(_ context.Context, a backend.Artifact, _ profile.Profile) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.signed[a.Rel] != f.thumb {
		return contract.New(contract.VerifyFailed, "not signed by %s", f.thumb)
	}
	return nil
}

const tA, tB = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

func setupMulti(t *testing.T, files map[string]uint16) (*Service, map[string]string, string, string) {
	t.Helper()
	root := t.TempDir()
	type entry struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	}
	var arts []entry
	for rel, machine := range files {
		b := minimalPE(machine, rel)
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, b, 0o600); err != nil {
			t.Fatal(err)
		}
		s := sha256.Sum256(b)
		arts = append(arts, entry{Path: rel, SHA256: hex.EncodeToString(s[:])})
	}
	commit, tree := strings.Repeat("1", 40), strings.Repeat("2", 40)
	mb, _ := json.Marshal(map[string]any{"schema": "sange.build-manifest/v1", "commit": commit, "tree": tree, "version": "v1", "artifacts": arts})
	manifest := filepath.Join(root, "build-manifest.json")
	if err := os.WriteFile(manifest, mb, 0o600); err != nil {
		t.Fatal(err)
	}
	store := profile.Store{Dir: t.TempDir()}
	p := profile.Profile{Name: "acme", Scope: profile.ScopeCompany, Owner: "acme", Purpose: []profile.Purpose{profile.PurposeInternal},
		Platforms: profile.Platforms{Windows: &profile.WindowsSpec{Kind: "authenticode", Signers: []profile.WindowsSigner{
			{ID: "x64", Backend: profile.BackendCertStore, Thumbprint: tA, Select: &profile.Selector{Arch: []string{"amd64"}}},
			{ID: "arm", Backend: profile.BackendCertStore, Thumbprint: tB, Select: &profile.Selector{Arch: []string{"arm64"}}},
		}}}}
	if err := store.Save(p, false); err != nil {
		t.Fatal(err)
	}
	signed := map[string]string{}
	mu := &sync.Mutex{}
	svc := &Service{Host: backend.Host{GOOS: "windows", Now: func() time.Time { return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) }},
		Store: store, Version: "test",
		BackendFor: func(_ backend.Host, p profile.Profile, platform string) (backend.Backend, error) {
			return &fakeWin{mu: mu, signed: signed, thumb: p.Platforms.Windows.Thumbprint}, nil
		}}
	return svc, signed, root, manifest
}

func TestEachWindowsFileIsSignedByItsOwnCertificate(t *testing.T) {
	svc, signed, root, manifest := setupMulti(t, map[string]uint16{
		"build/windows/tool_amd64.exe": 0x8664, "build/windows/tool_arm64.exe": 0xaa64})
	res, err := svc.Sign(context.Background(), SignOptions{Root: root, Manifest: manifest, Commit: strings.Repeat("1", 40),
		Tree: strings.Repeat("2", 40), Profile: "acme", Purpose: "internal", Platforms: []string{"windows"}, Strict: true})
	if err != nil {
		t.Fatal(err)
	}
	if signed["build/windows/tool_amd64.exe"] != tA || signed["build/windows/tool_arm64.exe"] != tB {
		t.Fatalf("signed by: %v", signed)
	}
	ids := map[string]string{}
	for _, a := range res.Manifest.Artifacts {
		ids[a.Path] = a.SignerID
	}
	if ids["build/windows/tool_amd64.exe"] != "x64" || ids["build/windows/tool_arm64.exe"] != "arm" {
		t.Fatalf("record signer ids: %v", ids)
	}
	vr, err := svc.Verify(context.Background(), VerifyOptions{Root: root, Signed: res.ManifestPath, Profile: "acme", Strict: true})
	if err != nil || !vr.OK {
		t.Fatalf("verify: %+v %v", vr, err)
	}
	// The record names its signer: a file re-signed by the other certificate fails.
	signed["build/windows/tool_amd64.exe"] = tB
	if _, err := svc.Verify(context.Background(), VerifyOptions{Root: root, Signed: res.ManifestPath, Profile: "acme"}); contract.CodeOf(err) != contract.VerifyFailed {
		t.Fatalf("a file signed by the wrong signer verified: %v", err)
	}
}

func TestAFileNoSignerCoversSignsNothing(t *testing.T) {
	svc, signed, root, manifest := setupMulti(t, map[string]uint16{
		"build/windows/tool_amd64.exe": 0x8664, "build/windows/tool_386.exe": 0x14c})
	_, err := svc.Sign(context.Background(), SignOptions{Root: root, Manifest: manifest, Commit: strings.Repeat("1", 40),
		Tree: strings.Repeat("2", 40), Profile: "acme", Purpose: "internal", Platforms: []string{"windows"}, Strict: true})
	if contract.CodeOf(err) != contract.SignFailed || !strings.Contains(err.Error(), "tool_386.exe") {
		t.Fatalf("want a sign failure naming the uncovered file: %v", err)
	}
	if len(signed) != 0 {
		t.Fatalf("files were signed before the refusal: %v", signed)
	}
}

// Audit N-B3: an .msi in the manifest stops the run before anything is
// signed, instead of being signed in place and failing the PE check after.
func TestMSIIsRefusedBeforeSigning(t *testing.T) {
	svc, signed, root, manifest := setupMulti(t, map[string]uint16{"build/windows/tool_amd64.exe": 0x8664})
	msi := filepath.Join(root, "build", "windows", "setup.msi")
	if err := os.WriteFile(msi, append([]byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}, "x"...), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(append([]byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}, "x"...))
	var m map[string]any
	b, _ := os.ReadFile(manifest)
	_ = json.Unmarshal(b, &m)
	m["artifacts"] = append(m["artifacts"].([]any), map[string]any{"path": "build/windows/setup.msi", "sha256": hex.EncodeToString(sum[:])})
	b, _ = json.Marshal(m)
	if err := os.WriteFile(manifest, b, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := svc.Sign(context.Background(), SignOptions{Root: root, Manifest: manifest, Commit: strings.Repeat("1", 40),
		Tree: strings.Repeat("2", 40), Profile: "acme", Purpose: "internal", Platforms: []string{"windows"}, Strict: true})
	if contract.CodeOf(err) != contract.SignFailed || !strings.Contains(err.Error(), "setup.msi") || len(signed) != 0 {
		t.Fatalf("err %v, signed %v", err, signed)
	}
}

// Audit N-B12: with policy.gpgFullFingerprint, a short gpg pin is refused
// when a profile is loaded to sign or verify; without it, it still loads.
func TestFullGPGFingerprintPolicy(t *testing.T) {
	store := profile.Store{Dir: t.TempDir()}
	p := profile.Profile{Name: "g", Scope: profile.ScopePersonal, Owner: "me", Purpose: []profile.Purpose{profile.PurposeInternal},
		Platforms: profile.Platforms{Checksums: &profile.ChecksumSpec{Kind: "gpg", KeyRef: "gpg-agent://0123456789ABCDEF", Fingerprint: "0123456789ABCDEF"}}}
	if err := store.Save(p, false); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Service{Store: store}).LoadProfile("g", contract.SignFailed); err != nil {
		t.Fatalf("without the policy: %v", err)
	}
	if _, err := (&Service{Store: store, RequireFullGPG: true}).LoadProfile("g", contract.SignFailed); contract.CodeOf(err) != contract.SignFailed {
		t.Fatalf("with the policy a short pin loaded: %v", err)
	}
}

// A repository's .imprimatur/project.json can only tighten: here it pins
// another profile, so the run is refused before anything is signed.
func TestProjectFileRefusesBeforeSigning(t *testing.T) {
	svc, signed, root, manifest := setupMulti(t, map[string]uint16{"build/windows/tool_amd64.exe": 0x8664})
	if err := os.MkdirAll(filepath.Join(root, ".imprimatur"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".imprimatur", "project.json"), []byte(`{"schema":"imprimatur.project/v1","profile":"acme-release"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := svc.Sign(context.Background(), SignOptions{Root: root, Manifest: manifest, Commit: strings.Repeat("1", 40),
		Tree: strings.Repeat("2", 40), Profile: "acme", Purpose: "internal", Platforms: []string{"windows"}, Strict: true})
	if contract.CodeOf(err) != contract.SignFailed || len(signed) != 0 {
		t.Fatalf("err %v, signed %v", err, signed)
	}
}
