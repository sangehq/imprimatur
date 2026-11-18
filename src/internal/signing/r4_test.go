package signing

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sangehq/imprimatur/src/internal/contract"
)

// Security review R4: a signed record is repository content, so a path in it
// that is absolute must not take verify outside --root, even to a file whose
// hash and signature would pass.
func TestVerifyRefusesAbsolutePathsInTheRecord(t *testing.T) {
	rel := "build/windows/tool_amd64.exe"
	svc, signed, root, manifest := setupMulti(t, map[string]uint16{rel: 0x8664})
	res, err := svc.Sign(context.Background(), SignOptions{Root: root, Manifest: manifest, Commit: strings.Repeat("1", 40),
		Tree: strings.Repeat("2", 40), Profile: "acme", Purpose: "internal", Platforms: []string{"windows"}, Strict: true})
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "tool_amd64.exe")
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, b, 0o600); err != nil {
		t.Fatal(err)
	}
	signed[outside] = tA // the fake would accept it
	var m Manifest
	raw, err := os.ReadFile(res.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m.Artifacts[0].Path = outside
	raw, err = json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(res.ManifestPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	vr, err := svc.Verify(context.Background(), VerifyOptions{Root: root, Signed: res.ManifestPath, Profile: "acme", Strict: true})
	text := ""
	if err != nil {
		text = err.Error()
	}
	for _, a := range vr.Artifacts {
		text += " " + strings.Join(a.Problems, " ")
	}
	if contract.CodeOf(err) != contract.VerifyFailed || !strings.Contains(text, "signing root") {
		t.Fatalf("a record path outside the root: %+v %v", vr, err)
	}
}

// Security review R4: sign never writes a record whose paths would be absolute,
// so a build manifest outside --root is refused before anything is signed.
func TestSignRefusesABuildManifestOutsideTheRoot(t *testing.T) {
	rel := "build/windows/tool_amd64.exe"
	svc, signed, root, manifest := setupMulti(t, map[string]uint16{rel: 0x8664})
	b, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "build-manifest.json")
	if err := os.WriteFile(outside, b, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = svc.Sign(context.Background(), SignOptions{Root: root, Manifest: outside, Commit: strings.Repeat("1", 40),
		Tree: strings.Repeat("2", 40), Profile: "acme", Purpose: "internal", Platforms: []string{"windows"}, Strict: true})
	if contract.CodeOf(err) != contract.SignFailed || !strings.Contains(err.Error(), "outside the signing root") {
		t.Fatalf("a build manifest outside the root: %v", err)
	}
	if len(signed) != 0 {
		t.Fatalf("files were signed: %v", signed)
	}
}
