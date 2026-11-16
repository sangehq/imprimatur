package artifact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzParseChecksums: no input panics, and a parsed file renders and parses
// back to the same entries.
func FuzzParseChecksums(f *testing.F) {
	f.Add([]byte(strings.Repeat("a", 64) + "  build/tool\n"))
	f.Add([]byte(strings.Repeat("b", 64) + " *build/tool.exe\r\n\n"))
	f.Add([]byte("x  ../escape\n"))
	f.Add([]byte(strings.Repeat("c", 64) + "  **"))
	f.Add([]byte(strings.Repeat("c", 64) + "  **x\n"))
	f.Add([]byte(strings.Repeat("c", 64) + "   x \n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		lines, err := ParseChecksums(b)
		if err != nil {
			return
		}
		again, err := ParseChecksums(Checksums(lines))
		if err != nil || len(again) != len(lines) {
			t.Fatalf("round trip: %v %d != %d", err, len(again), len(lines))
		}
		for i := range lines {
			if again[i] != lines[i] {
				t.Fatalf("round trip changed %q to %q", lines[i], again[i])
			}
		}
	})
}

// FuzzReadManifest: no build manifest panics the reader, and one it accepts
// names only paths that stay under the root.
func FuzzReadManifest(f *testing.F) {
	f.Add([]byte(`{"schema":"sange.build-manifest/v1","commit":"` + strings.Repeat("a", 40) + `","tree":"` + strings.Repeat("b", 40) +
		`","version":"v1","artifacts":[{"path":"build/linux/tool","sha256":"` + strings.Repeat("c", 64) + `","size":1}]}`))
	f.Add([]byte(`{"schema":"sange.build-manifest/v1","artifacts":[{"path":"../x"}]}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		dir := t.TempDir()
		p := filepath.Join(dir, "m.json")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		m, err := ReadManifest(p)
		if err != nil {
			return
		}
		for _, a := range m.Artifacts {
			if filepath.IsAbs(a.Path) || strings.HasPrefix(filepath.ToSlash(filepath.Clean(a.Path)), "../") || filepath.Clean(a.Path) == ".." {
				t.Fatalf("accepted a path outside the root: %q", a.Path)
			}
		}
	})
}
