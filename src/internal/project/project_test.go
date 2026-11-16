package project

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func write(t *testing.T, root, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(Path))
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadIsStrictAndTightenOnly(t *testing.T) {
	root := t.TempDir()
	if _, ok, err := Load(root); ok || err != nil {
		t.Fatalf("no file: %v %v", ok, err)
	}
	for name, body := range map[string]string{
		"a hook":        `{"schema":"imprimatur.project/v1","hooks":[{"exec":"/bin/sh"}]}`,
		"allow sign":    `{"schema":"imprimatur.project/v1","allowSign":true}`,
		"bad purpose":   `{"schema":"imprimatur.project/v1","purposes":["anything"]}`,
		"no schema":     `{"profile":"p"}`,
		"two documents": `{"schema":"imprimatur.project/v1"} {}`,
	} {
		write(t, root, body)
		if _, _, err := Load(root); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	write(t, root, `{"schema":"imprimatur.project/v1","profile":"acme","purposes":["release"],"platforms":["windows"],"strict":true,"requireRepo":true}`)
	pr, ok, err := Load(root)
	if err != nil || !ok {
		t.Fatal(err)
	}
	if why := pr.CheckSign("acme", "release", "git@github.com:acme/tool.git", []string{"windows"}, true); len(why) != 0 {
		t.Fatalf("an allowed run was refused: %v", why)
	}
	for name, why := range map[string][]string{
		"another profile":  pr.CheckSign("other", "release", "r", []string{"windows"}, true),
		"another purpose":  pr.CheckSign("acme", "test", "r", []string{"windows"}, true),
		"another platform": pr.CheckSign("acme", "release", "r", []string{"windows", "macos"}, true),
		"not strict":       pr.CheckSign("acme", "release", "r", []string{"windows"}, false),
		"no repo":          pr.CheckSign("acme", "release", "", []string{"windows"}, true),
		"verify other":     pr.CheckVerify("other", true),
	} {
		if len(why) == 0 {
			t.Errorf("%s was allowed", name)
		}
	}
	if runtime.GOOS != "windows" {
		real := filepath.Join(t.TempDir(), "p.json")
		if err := os.WriteFile(real, []byte(`{"schema":"imprimatur.project/v1"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(root, filepath.FromSlash(Path))
		_ = os.Remove(p)
		if err := os.Symlink(real, p); err != nil {
			t.Fatal(err)
		}
		if _, _, err := Load(root); err == nil {
			t.Error("a symlinked project file was read")
		}
	}
}
