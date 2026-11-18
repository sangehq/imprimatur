package server

import (
	"os"
	"path/filepath"
	"testing"
)

// Security review R4 (I-11): server.roots is checked on the resolved path, so
// a symbolic link inside a root cannot move the root, or a file under it,
// outside every configured root.
func TestServerRootMustResolveInsideRoots(t *testing.T) {
	f := setup(t, false)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(f.root, "escape")); err != nil {
		t.Fatal(err)
	}
	link := filepath.ToSlash(filepath.Join(f.root, "escape"))
	for name, body := range map[string]string{
		"root through a link":   `{"root":"` + link + `","profile":"acme","files":["a.exe"]}`,
		"signed through a link": `{"root":"` + f.root + `","profile":"acme","signed":"escape/impr-manifest.json"}`,
		"file through a link":   `{"root":"` + f.root + `","profile":"acme","files":["escape/a.exe"]}`,
	} {
		if r := do(f.h, "POST", "/v1/verify", f.ver, body, nil); r.Code != 400 {
			t.Errorf("%s: %d, want 400 (%s)", name, r.Code, f.run.last())
		}
	}
}
