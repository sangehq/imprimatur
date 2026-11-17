package signing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Old bug 11: a file no requested platform covers (a Linux binary when only
// windows is signed) is named in the result and the signed manifest, never
// left out silently. Checksums cover every file, so with them nothing is.
func TestSignNamesFilesNoPlatformCovers(t *testing.T) {
	svc, _, root, manifest := setupMulti(t, map[string]uint16{"build/windows/tool_amd64.exe": 0x8664})
	elf := []byte("\x7fELF" + strings.Repeat("x", 64))
	rel := "build/linux/tool_linux_amd64"
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, elf, 0o600); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	b, _ := os.ReadFile(manifest)
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(elf)
	m["artifacts"] = append(m["artifacts"].([]any), map[string]any{"path": rel, "sha256": hex.EncodeToString(sum[:])})
	b, _ = json.Marshal(m)
	if err := os.WriteFile(manifest, b, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := svc.Sign(context.Background(), SignOptions{Root: root, Manifest: manifest, Commit: strings.Repeat("1", 40),
		Tree: strings.Repeat("2", 40), Profile: "acme", Purpose: "internal", Platforms: []string{"windows"}, Strict: true})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(res.Uncovered, rel) || !slices.Contains(res.Manifest.Uncovered, rel) {
		t.Fatalf("the Linux binary is not named as uncovered: result %v, manifest %v", res.Uncovered, res.Manifest.Uncovered)
	}
	if slices.Contains(res.Uncovered, "build/windows/tool_amd64.exe") {
		t.Fatalf("a signed file is listed as uncovered: %v", res.Uncovered)
	}
}
