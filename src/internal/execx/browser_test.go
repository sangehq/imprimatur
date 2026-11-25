package execx

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestBrowserArgvGivesThePageOnly(t *testing.T) {
	for goos, want := range map[string][]string{
		"darwin":  {"open", "/p/x.html"},
		"windows": {"rundll32", "url.dll,FileProtocolHandler", "/p/x.html"},
		"linux":   {"xdg-open", "/p/x.html"},
		"freebsd": {"xdg-open", "/p/x.html"},
	} {
		if got := BrowserArgv(goos, "/p/x.html"); !slices.Equal(got, want) {
			t.Errorf("%s: %v, want %v", goos, got, want)
		}
	}
}

// OpenPage opens nothing but an existing, absolute, regular .html file: never
// a URL (which would put a sign-in link on a command line) or another file.
func TestOpenPageRefusesAnythingButALocalPage(t *testing.T) {
	dir := t.TempDir()
	txt := filepath.Join(dir, "x.txt")
	_ = os.WriteFile(txt, []byte("x"), 0o600)
	link := filepath.Join(dir, "l.html")
	_ = os.Symlink(txt, link)
	for _, page := range []string{"http://127.0.0.1:7823/?token=x", "x.html", txt, filepath.Join(dir, "missing.html"), link, dir + string(filepath.Separator) + "d.html"} {
		if err := OpenPage("linux", page); err == nil {
			t.Errorf("OpenPage(%q) opened it", page)
		}
	}
}
