package signing

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/sangehq/imprimatur/src/internal/profile"
)

// W2: the checksum signature's file name follows the kind, and a directory
// is not a file.
func TestChecksumSuffixAndFileExists(t *testing.T) {
	p := profile.Profile{Platforms: profile.Platforms{Checksums: &profile.ChecksumSpec{Kind: "minisign"}}}
	if checksumSuffix(p) != ".minisig" {
		t.Error("minisign signature is not .minisig")
	}
	p.Platforms.Checksums.Kind = "ssh"
	if checksumSuffix(p) != ".sig" || checksumSuffix(profile.Profile{}) != ".sig" {
		t.Error("other signatures are not .sig")
	}
	dir := t.TempDir()
	f := filepath.Join(dir, "f")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if !fileExists(f) || fileExists(dir) || fileExists(filepath.Join(dir, "missing")) {
		t.Error("fileExists")
	}
}

// W2: a multi-certificate Windows profile is ready only when every signer
// can sign here.
func TestWindowsCapabilityOfSeveralSigners(t *testing.T) {
	svc, _, _, _ := setupMulti(t, map[string]uint16{"build/windows/tool_amd64.exe": 0x8664})
	rep, err := svc.Capabilities(context.Background(), "acme")
	if err != nil || len(rep.Profiles) != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
	c := rep.Profiles[0].Platforms[profile.Windows]
	if !c.Sign || !c.Verify || !c.Supported {
		t.Fatalf("windows capability: %+v", c)
	}
}
