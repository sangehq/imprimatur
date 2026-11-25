package web

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// The vendored files are exactly what MANIFEST.sha256 lists, byte for byte:
// a hand edit, a missing file or an extra one fails.
func TestVendoredFilesMatchTheManifest(t *testing.T) {
	man, err := assetFS.ReadFile("assets/vendor/MANIFEST.sha256")
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(man))
	for sc.Scan() {
		sum, name, ok := strings.Cut(sc.Text(), "  ")
		if !ok {
			t.Fatalf("a manifest line is not \"sha256  path\": %q", sc.Text())
		}
		listed[name] = sum
	}
	atLeast(t, "manifest entries", len(listed), 13)
	seen := 0
	err = fs.WalkDir(assetFS, "assets/vendor", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || p == "assets/vendor/MANIFEST.sha256" {
			return err
		}
		seen++
		name := strings.TrimPrefix(p, "assets/vendor/")
		b, err := assetFS.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		want, ok := listed[name]
		switch {
		case !ok:
			t.Errorf("%s is vendored but not in MANIFEST.sha256", name)
		case want != hex.EncodeToString(sum[:]):
			t.Errorf("%s does not match MANIFEST.sha256 (re-vendor with make tabler-vendor; never edit it by hand)", name)
		}
		delete(listed, name)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	atLeast(t, "vendored files", seen, 13)
	for name := range listed {
		t.Errorf("MANIFEST.sha256 lists %s, which is not vendored", name)
	}
}

// An asset URL carries its content hash and is immutable; an old hash is a
// 404, never today's file under yesterday's address.
func TestStaleAssetHashIsNotFound(t *testing.T) {
	s := newTestServer(t, nil, nil)
	good, err := s.assets.url("favicon.svg")
	if err != nil {
		t.Fatal(err)
	}
	r := do(s.Handler(), "GET", good, nil, nil)
	if r.Code != 200 || r.Header().Get("Content-Type") != "image/svg+xml" || !strings.Contains(r.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("%s: %d %q %q", good, r.Code, r.Header().Get("Content-Type"), r.Header().Get("Cache-Control"))
	}
	if r := do(s.Handler(), "GET", "/assets/000000000000/favicon.svg", nil, nil); r.Code != http.StatusNotFound {
		t.Fatalf("a stale hash: %d, want 404", r.Code)
	}
	if r := do(s.Handler(), "GET", strings.Replace(good, "favicon.svg", "no-such.svg", 1), nil, nil); r.Code != http.StatusNotFound {
		t.Fatalf("an unknown asset: %d, want 404", r.Code)
	}
}

// templateFiles reads every template, layout and partials included.
func templateFiles(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := fs.WalkDir(templateFS, "templates", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".html") {
			return err
		}
		b, err := templateFS.ReadFile(p)
		out[p] = string(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// inlineRe finds what the CSP would refuse: an inline style, a style
// attribute, an event-handler attribute, a javascript: URL; scriptRe finds
// every script tag, each of which must load a file and hold nothing.
var (
	inlineRe = regexp.MustCompile(`(?i)<style\b|\sstyle\s*=|\son[a-z]+\s*=|javascript:`)
	scriptRe = regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script>`)
)

func inlineProblems(name, text string) []string {
	var out []string
	for _, m := range inlineRe.FindAllString(text, -1) {
		out = append(out, name+": "+strings.TrimSpace(m))
	}
	for _, m := range scriptRe.FindAllStringSubmatch(text, -1) {
		if !strings.Contains(m[1], "src=") || strings.TrimSpace(m[2]) != "" {
			out = append(out, name+": an inline script")
		}
	}
	return out
}

// Nothing in a template needs 'unsafe-inline': the CSP allows none.
func TestNoTemplateUsesAnInlineStyle(t *testing.T) {
	files := templateFiles(t)
	atLeast(t, "templates", len(files), 6)
	for name, text := range files {
		for _, p := range inlineProblems(name, text) {
			t.Error(p)
		}
	}
}

func TestInlineGuardCanFail(t *testing.T) {
	for _, bad := range []string{`<p style="x">`, `<style>p{}</style>`, `<script>alert(1)</script>`, `<a onclick="x()">`, `<a href="javascript:x()">`} {
		if len(inlineProblems("x.html", bad)) == 0 {
			t.Errorf("the guard missed %s", bad)
		}
	}
	if p := inlineProblems("x.html", `<script src="/assets/a/app.js" type="module"></script>`); len(p) != 0 {
		t.Errorf("an external script was flagged: %v", p)
	}
}
