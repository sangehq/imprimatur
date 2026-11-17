package execx

import (
	"os"
	"path/filepath"
	"testing"
)

// O-130, O-197: signtool off PATH is found under Windows Kits\10\bin, the
// newest SDK version first by version number (not by string), the host's
// architecture first and then x64, as the PowerShell Find-SignTool did.
func TestSigntoolFoundInWindowsKits(t *testing.T) {
	root := t.TempDir()
	put := func(ver, arch string) string {
		p := filepath.Join(root, ver, arch, "signtool.exe")
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("MZ"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	put("10.0.9600.0", "x64")
	newest := put("10.0.22621.0", "x64")
	arm := put("10.0.19041.0", "arm64")
	put("10.0.26100.0", "x86") // never chosen: not the host's and not x64
	if err := os.MkdirAll(filepath.Join(root, "10.0.30000.0", "x64", "signtool.exe"), 0o750); err != nil {
		t.Fatal(err) // a folder named like the tool is not the tool
	}
	if got := signtoolInKits(root, "amd64"); got != newest {
		t.Errorf("amd64: %q, want %q", got, newest)
	}
	if got := signtoolInKits(root, "arm64"); got != arm {
		t.Errorf("arm64: %q, want the arm64 build %q", got, arm)
	}
	if got := signtoolInKits(root, "riscv64"); got != newest {
		t.Errorf("an architecture with no SDK folder: %q, want x64 %q", got, newest)
	}
	if got := signtoolInKits(t.TempDir(), "amd64"); got != "" {
		t.Errorf("no SDK: %q", got)
	}
}
