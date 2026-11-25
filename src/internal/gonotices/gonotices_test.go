package gonotices

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func modDir(t *testing.T, files map[string]string) string {
	t.Helper()
	d := t.TempDir()
	for n, body := range files {
		if err := os.WriteFile(filepath.Join(d, n), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func TestParseSortsAndDedupes(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	in := "example.com/b\tv1.0.0\t" + b + "\nexample.com/a\tv0.2.0\t" + a + "\n\nexample.com/b\tv1.0.0\t" + b + "\n"
	mods, err := Parse(strings.NewReader(in), "/goroot")
	if err != nil {
		t.Fatal(err)
	}
	if len(mods) != 3 || mods[0].Dir != "/goroot" || mods[1].Path != "example.com/a" || mods[2].Path != "example.com/b" {
		t.Fatalf("%+v", mods)
	}
	for _, bad := range []string{"example.com/a\t\t" + a, "example.com/a\tv1.0.0\t", "only-a-path"} {
		if _, err := Parse(strings.NewReader(bad), "/goroot"); err == nil {
			t.Errorf("%q was taken", bad)
		}
	}
	if _, err := Parse(strings.NewReader(""), ""); err == nil {
		t.Error("no GOROOT was taken")
	}
}

func TestReadNeedsALicenceAndRenderIsStable(t *testing.T) {
	lic := modDir(t, map[string]string{"LICENSE": "MIT text\n```\nwith a fence\n", "PATENTS": "grant\n", "README.md": "not a licence"})
	mods := []Module{{Path: "Go standard library and runtime", Dir: modDir(t, map[string]string{"LICENSE": "BSD\n"})}, {Path: "example.com/a", Version: "v1.2.3", Dir: lic}}
	ns, err := Read(mods)
	if err != nil {
		t.Fatal(err)
	}
	if len(ns[1].Files) != 2 || ns[1].Files[0].Name != "LICENSE" || ns[1].Files[1].Name != "PATENTS" {
		t.Fatalf("licence files: %+v", ns[1].Files)
	}
	out := string(Render(ns))
	if out != string(Render(ns)) {
		t.Fatal("Render is not deterministic")
	}
	for _, want := range []string{"## example.com/a v1.2.3\n", "the Go standard library and the 1 Go modules", "````text\nMIT text\n```\nwith a fence\n````", "PATENTS:"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered file lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "not a licence") || strings.Contains(out, lic) {
		t.Error("a README or a host path was written")
	}
	if _, err := Read([]Module{{Path: "example.com/none", Version: "v1.0.0", Dir: modDir(t, map[string]string{"README.md": "x"})}}); err == nil {
		t.Fatal("a module with no licence file was taken")
	}
}
