package artifact

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sangehq/imprimatur/src/internal/contract"
)

func TestResolveRefusesEscapes(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "x"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "x"), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "ok"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"../x", "/etc/passwd", "a/../../x", "link", "missing", ""} {
		if _, err := Resolve(root, rel); contract.CodeOf(err) != contract.SignFailed {
			t.Errorf("%q: want a refusal, got %v", rel, err)
		}
	}
	if _, err := Resolve(root, "ok"); err != nil {
		t.Fatal(err)
	}
}

func TestKindOf(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]struct {
		data []byte
		want Kind
	}{
		"a.exe":    {[]byte("MZ\x90\x00"), KindWindows},
		"a.msi":    {[]byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}, KindWindows},
		"a":        {[]byte{0xcf, 0xfa, 0xed, 0xfe, 0, 0}, KindMacOS},
		"fat":      {[]byte{0xca, 0xfe, 0xba, 0xbe}, KindMacOS},
		"a.dmg":    {[]byte("koly"), KindMacOS},
		"elf":      {[]byte("\x7fELF"), KindOther},
		"tiny":     {[]byte("M"), KindOther},
		"fake.msi": {[]byte("not ole"), KindOther},
	}
	for name, c := range cases {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, c.data, 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := KindOf(p); err != nil || got != c.want {
			t.Errorf("%s: %s %v, want %s", name, got, err, c.want)
		}
	}
}

func TestReadManifestRefuses(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"schema": `{"schema":"other","artifacts":[{"path":"a","sha256":"` + string(make([]byte, 0)) + `"}]}`,
		"empty":  `{"schema":"sange.build-manifest/v1","artifacts":[]}`,
		"digest": `{"schema":"sange.build-manifest/v1","artifacts":[{"path":"a","sha256":"xyz"}]}`,
	} {
		p := filepath.Join(dir, name+".json")
		_ = os.WriteFile(p, []byte(body), 0o600)
		if _, err := ReadManifest(p); contract.CodeOf(err) != contract.Usage {
			t.Errorf("%s: want a usage error, got %v", name, err)
		}
	}
}
