package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type dirs struct{ sys, user string }

func newDirs(t *testing.T) dirs {
	t.Helper()
	return dirs{sys: t.TempDir(), user: t.TempDir()}
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (d dirs) load(profile string) (Effective, error) {
	return LoadEffective(Sources{SystemDir: d.sys, UserDir: d.user, Profile: profile})
}

// absDir is an absolute path on every OS, with forward slashes so it can sit
// in JSON as it is.
func absDir(t *testing.T, name string) string {
	t.Helper()
	return filepath.ToSlash(filepath.Join(t.TempDir(), name))
}

func TestLayerOrderSystemUserProfile(t *testing.T) {
	d := newDirs(t)
	srvA, userB, devD := absDir(t, "a"), absDir(t, "builds"), absDir(t, "dev")
	write(t, filepath.Join(d.sys, File), `{"server":{"listen":"unix","roots":["`+srvA+`"],"allowSign":false}}`)
	write(t, filepath.Join(d.user, File), `{"schema":"imprimatur.config/v1","server":{"roots":["`+userB+`"]},"activeProfile":"ci"}`)
	write(t, filepath.Join(d.user, ProfilesDir, "ci.json"), `{"server":{"allowSign":true,"listen":null}}`)
	write(t, filepath.Join(d.user, ProfilesDir, "dev.json"), `{"server":{"roots":["`+devD+`"]}}`)
	eff, err := d.load("")
	if err != nil {
		t.Fatal(err)
	}
	s := eff.Config.Server
	// user replaces the system's array; the profile turns sign on and its null removes listen.
	if strings.Join(s.Roots, ",") != userB || !s.AllowSign || s.Listen != "" || eff.Profile != "ci" || len(eff.Layers) != 3 {
		t.Fatalf("effective: %+v profile %q layers %d", s, eff.Profile, len(eff.Layers))
	}
	// IMPR_CONFIG_PROFILE (Sources.Profile) wins over activeProfile.
	eff, err = d.load("dev")
	if err != nil || strings.Join(eff.Config.Server.Roots, ",") != devD || eff.Config.Server.AllowSign {
		t.Fatalf("dev: %+v %v", eff.Config.Server, err)
	}
	// A selected profile that does not exist is an error, never "no profile".
	if _, err := d.load("prod"); err == nil {
		t.Fatal("a missing profile loaded")
	}
}

func TestLocks(t *testing.T) {
	cases := map[string]struct{ user, profile string }{
		"user sets a locked key":              {user: `{"server":{"allowSign":true}}`},
		"profile sets a locked key":           {profile: `{"server":{"allowSign":true}}`},
		"user replaces the locked parent":     {user: `{"server":null}`},
		"user locks keys itself":              {user: `{"locked":["hooks"]}`},
		"profile sets schema":                 {profile: `{"schema":"x"}`},
		"profile picks another profile":       {profile: `{"activeProfile":"other"}`},
		"user changes a locked activeProfile": {user: `{"activeProfile":"p"}`},
		// Security review R1: Go's JSON decoding matches field names without
		// regard to case (and folds ſ to s), so another spelling of a locked
		// key must not slip past the byte-exact lock check.
		"user spells the locked key in lower case": {user: `{"server":{"allowsign":true}}`},
		"user spells the parent in upper case":     {user: `{"SERVER":{"allowSign":true}}`},
		"profile spells it with a long s":          {profile: "{\"\u017Ferver\":{\"allowSign\":true}}"},
	}
	for name, c := range cases {
		d := newDirs(t)
		write(t, filepath.Join(d.sys, File), `{"locked":["server.allowSign","activeProfile"],"server":{"allowSign":false}}`)
		if c.user != "" {
			write(t, filepath.Join(d.user, File), c.user)
		}
		prof := ""
		if c.profile != "" {
			write(t, filepath.Join(d.user, ProfilesDir, "p.json"), c.profile)
			prof = "p"
			// The lock on activeProfile also refuses IMPR_CONFIG_PROFILE, so
			// drop it here to reach the profile's own refusal.
			write(t, filepath.Join(d.sys, File), `{"locked":["server.allowSign"],"server":{"allowSign":false}}`)
		}
		_, err := d.load(prof)
		if err == nil {
			t.Errorf("%s was accepted", name)
		} else if strings.Contains(err.Error(), "does not exist") {
			t.Errorf("%s failed for the wrong reason: %v", name, err)
		}
	}
	// Locked keys that nothing lower touches load fine, and a user change
	// elsewhere is kept.
	d := newDirs(t)
	write(t, filepath.Join(d.sys, File), `{"locked":["server.allowSign"],"server":{"allowSign":false}}`)
	write(t, filepath.Join(d.user, File), `{"server":{"roots":["`+absDir(t, "r")+`"]}}`)
	if eff, err := d.load(""); err != nil || eff.Config.Server.AllowSign || len(eff.Locked) != 1 {
		t.Fatalf("%+v %v", eff, err)
	}
}

func TestLayerPermissionsAndStrictness(t *testing.T) {
	d := newDirs(t)
	write(t, filepath.Join(d.user, File), `{"servr":{}}`)
	if _, err := d.load(""); err == nil {
		t.Fatal("an unknown key in a layer was accepted")
	}
	if runtime.GOOS == "windows" {
		return
	}
	write(t, filepath.Join(d.user, File), `{}`)
	write(t, filepath.Join(d.sys, File), `{}`)
	if err := os.Chmod(filepath.Join(d.sys, File), 0o666); err != nil { //nolint:gosec // G302: the unsafe mode under test
		t.Fatal(err)
	}
	if _, err := d.load(""); err == nil {
		t.Fatal("a world-writable system config was accepted")
	}
}

// events.source is sange.sh (the default, also when unset) or simtabi.com;
// anything else is refused when the configuration loads.
func TestEventsSourceIsValidated(t *testing.T) {
	for _, ok := range []string{"", "sange.sh", "simtabi.com"} {
		c := Config{Schema: Schema, Events: Events{Source: ok}}
		if ps := c.Validate(); len(ps) != 0 {
			t.Errorf("%q refused: %v", ok, ps)
		}
	}
	for _, bad := range []string{"simtabi", "https://simtabi.com", "Simtabi.com", "sange", "example.com"} {
		c := Config{Schema: Schema, Events: Events{Source: bad}}
		ps := c.Validate()
		if len(ps) != 1 || !strings.Contains(ps[0], "events.source") || !strings.Contains(ps[0], "sange.sh or simtabi.com") {
			t.Errorf("%q: %v", bad, ps)
		}
	}
	d := newDirs(t)
	write(t, filepath.Join(d.user, File), `{"schema":"`+Schema+`","events":{"source":"simtabi.com"}}`)
	eff, err := d.load("")
	if err != nil || eff.Config.Events.Source != "simtabi.com" {
		t.Fatalf("%+v %v", eff.Config.Events, err)
	}
	write(t, filepath.Join(d.user, File), `{"schema":"`+Schema+`","events":{"source":"example.com"}}`)
	if _, err := d.load(""); err == nil || !strings.Contains(err.Error(), "events.source") {
		t.Fatalf("an unknown source loaded: %v", err)
	}
}
