package paths

import (
	"path/filepath"
	"testing"
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
		{"Windows", Env{GOOS: "windows", Getenv: env(map[string]string{"AppData": `C:\A`, "LocalAppData": `C:\L`})},
			Dirs{Config: filepath.Join(`C:\A`, "imprimatur"), State: filepath.Join(`C:\L`, "imprimatur")}},
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
