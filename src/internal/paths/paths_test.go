package paths

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestResolve(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	cases := []struct {
		name string
		e    Env
		want Dirs
	}{
		{"macOS uses XDG defaults", Env{GOOS: "darwin", Home: "/h", Getenv: env(nil)},
			Dirs{Config: filepath.Join("/h", ".config", "imprimatur"), State: filepath.Join("/h", ".local", "state", "imprimatur")}},
		{"XDG roots", Env{GOOS: "linux", Home: "/h", Getenv: env(map[string]string{"XDG_CONFIG_HOME": "/c", "XDG_STATE_HOME": "/s"})},
			Dirs{Config: filepath.Join("/c", "imprimatur"), State: filepath.Join("/s", "imprimatur")}},
		{"a relative XDG root is ignored", Env{GOOS: "linux", Home: "/h", Getenv: env(map[string]string{"XDG_CONFIG_HOME": "rel"})},
			Dirs{Config: filepath.Join("/h", ".config", "imprimatur"), State: filepath.Join("/h", ".local", "state", "imprimatur")}},
		{"Windows uses ~/.config too, and reports the old AppData dirs", Env{GOOS: "windows", Home: `C:\U`,
			Getenv: env(map[string]string{"AppData": `C:\A`, "LocalAppData": `C:\L`})},
			Dirs{Config: filepath.Join(`C:\U`, ".config", "imprimatur"), State: filepath.Join(`C:\U`, ".local", "state", "imprimatur"),
				LegacyConfig: filepath.Join(`C:\A`, "imprimatur"), LegacyState: filepath.Join(`C:\L`, "imprimatur")}},
		{"Windows honours an absolute XDG root", Env{GOOS: "windows", Home: `C:\U`,
			Getenv: env(map[string]string{"XDG_CONFIG_HOME": `D:\cfg`, "XDG_STATE_HOME": `D:\st`})},
			Dirs{Config: filepath.Join(`D:\cfg`, "imprimatur"), State: filepath.Join(`D:\st`, "imprimatur")}},
		{"overrides", Env{GOOS: "linux", Getenv: env(map[string]string{"IMPR_CONFIG_DIR": "/x", "IMPR_STATE_DIR": "/y"})}, Dirs{Config: "/x", State: "/y"}},
	}
	for _, c := range cases {
		got, err := Resolve(c.e)
		if err != nil || got != c.want {
			t.Errorf("%s: %+v %v, want %+v", c.name, got, err, c.want)
		}
	}
	if _, err := Resolve(Env{GOOS: "linux", Getenv: env(nil)}); err == nil {
		t.Error("no home and no overrides should fail")
	}
}

func TestMigrateLegacyCopiesOnceAndKeepsTheSource(t *testing.T) {
	base := t.TempDir()
	d := Dirs{Config: filepath.Join(base, "new", "cfg"), State: filepath.Join(base, "new", "st"),
		LegacyConfig: filepath.Join(base, "old", "cfg"), LegacyState: filepath.Join(base, "old", "st")}
	if err := os.MkdirAll(filepath.Join(d.LegacyConfig, "profiles"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d.LegacyConfig, "profiles", "a.json"), []byte(`{"name":"a"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	got, err := MigrateLegacy(d, now)
	if err != nil || len(got) != 1 {
		t.Fatalf("copied %v, %v", got, err)
	}
	if b, err := os.ReadFile(filepath.Join(d.Config, "profiles", "a.json")); err != nil || string(b) != `{"name":"a"}` {
		t.Fatalf("copy: %q %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(d.LegacyConfig, "profiles", "a.json")); err != nil {
		t.Fatal("the legacy file must be kept")
	}
	if _, err := os.Stat(filepath.Join(d.Config, MigratedMarker)); err != nil {
		t.Fatal("no migration marker")
	}
	if got, err := MigrateLegacy(d, now); err != nil || len(got) != 0 {
		t.Fatalf("second run copied %v, %v", got, err)
	}
}
