package winres

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"image"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

// testICO is a .ico holding one 16x16 PNG image.
func testICO(t *testing.T) []byte {
	t.Helper()
	var p bytes.Buffer
	if err := png.Encode(&p, image.NewRGBA(image.Rect(0, 0, 16, 16))); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, []uint16{0, 1, 1})
	b.Write([]byte{16, 16, 0, 0})
	_ = binary.Write(&b, binary.LittleEndian, []uint16{1, 32})
	_ = binary.Write(&b, binary.LittleEndian, []uint32{uint32(p.Len()), 22}) //nolint:gosec // G115: a 16x16 PNG
	b.Write(p.Bytes())
	return b.Bytes()
}

func rootTypes(t *testing.T, path string) []uint32 {
	t.Helper()
	f, err := pe.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	sec := f.Section(".rsrc")
	if sec == nil {
		t.Fatal("no .rsrc section in the built program")
	}
	b, _ := sec.Data()
	n := int(binary.LittleEndian.Uint16(b[12:])) + int(binary.LittleEndian.Uint16(b[14:]))
	var out []uint32
	for i := 0; i < n; i++ {
		out = append(out, binary.LittleEndian.Uint32(b[16+8*i:]))
	}
	return out
}

// TestTheLinkerEmbedsTheResources builds a real Windows program for each
// architecture with the .syso, and reads the resources back out of it.
func TestTheLinkerEmbedsTheResources(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go: not installed")
	}
	in := Info{ProductName: "Acme Tool", FileDescription: "Signs things", CompanyName: "Acme Ltd", LegalCopyright: "© 2026 Acme Ltd",
		OriginalFilename: "tool.exe", InternalName: "tool", ProductVersion: "v1.2.3-rc.1", FileVersion: "1.2.3"}
	for _, arch := range []string{"amd64", "386", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			dir := t.TempDir()
			for name, body := range map[string]string{"go.mod": "module example.com/tool\n\ngo 1.23\n", "main.go": "package main\n\nfunc main() {}\n"} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			syso, err := Syso(arch, in, CLIManifest, testICO(t))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "zz_impr_winres_windows_"+arch+".syso"), syso, 0o600); err != nil {
				t.Fatal(err)
			}
			exe := filepath.Join(dir, "tool.exe")
			cmd := exec.Command("go", "build", "-trimpath", "-o", exe, ".")
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH="+arch, "CGO_ENABLED=0", "GOFLAGS=-mod=mod", "GOWORK=off")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("go build: %v\n%s", err, out)
			}
			got, err := ReadVersion(exe)
			if err != nil {
				t.Fatal(err)
			}
			for k, want := range map[string]string{"ProductName": "Acme Tool", "CompanyName": "Acme Ltd", "LegalCopyright": "© 2026 Acme Ltd",
				"FileVersion": "1.2.3.0", "ProductVersion": "v1.2.3-rc.1", "OriginalFilename": "tool.exe"} {
				if got[k] != want {
					t.Errorf("%s: %q, want %q (all: %v)", k, got[k], want, got)
				}
			}
			types := rootTypes(t, exe)
			for _, want := range []uint32{rtIcon, rtGroupIcon, rtVersion, rtManifest} {
				if !slices.Contains(types, want) {
					t.Errorf("resource type %d missing from the built program: %v", want, types)
				}
			}
		})
	}
}

func TestFileVersionAndRefusals(t *testing.T) {
	for in, want := range map[string]string{"v1.2.3-rc.1": "1.2.3.0", "1.2": "1.2.0.0", "nightly": "0.0.0.0", "1.2.3.4.5": "1.2.3.4"} {
		if got := FileVersion(in); got != want {
			t.Errorf("FileVersion(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := Syso("riscv64", Info{}, "", nil); err == nil {
		t.Error("an architecture with no PE relocation type was accepted")
	}
	if _, err := VersionInfo(Info{FileVersion: "70000.1"}); err == nil {
		t.Error("a version part above 65535 was accepted")
	}
	for name, ico := range map[string][]byte{"not an icon": []byte("PNG"), "no images": {0, 0, 1, 0, 0, 0}, "out of bounds": {0, 0, 1, 0, 1, 0, 16, 16, 0, 0, 1, 0, 32, 0, 255, 0, 0, 0, 22, 0, 0, 0}} {
		if _, err := Syso("amd64", Info{FileVersion: "1"}, "", ico); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
