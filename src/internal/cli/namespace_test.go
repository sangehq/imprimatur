package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sangehq/imprimatur/src/internal/notify"
)

// The reverse-DNS identifiers moved from sh.sange.imprimatur to
// com.simtabi.sange.imprimatur on 2026-11-17 (owner decision); the old ones
// are kept only so an existing install can be recognised and migrated.
func TestReverseDNSIdentifiersArePinned(t *testing.T) {
	for _, c := range [][2]string{
		{launchdLabel, "com.simtabi.sange.imprimatur.serve"},
		{checkLabel, "com.simtabi.sange.imprimatur.cert-check"},
		{legacyLaunchdLabel, "sh.sange.imprimatur.serve"},
		{legacyCheckLabel, "sh.sange.imprimatur.cert-check"},
		{notify.AppID, "com.simtabi.sange.imprimatur"},
		{notify.LegacyAppID, "sh.sange.imprimatur"}, //nolint:staticcheck // SA1019: pins the deprecated id

	} {
		if c[0] != c[1] {
			t.Errorf("got %q, want %q", c[0], c[1])
		}
	}
	if c := notify.Config(t.TempDir(), true, nil, os.Getenv); c.AppID != "com.simtabi.sange.imprimatur" || c.BundleID != "com.simtabi.sange.imprimatur.notifier" {
		t.Fatalf("notifier identity %q %q", c.AppID, c.BundleID)
	}
}

// legacyAgent writes the plist an older impr told the user to install.
func legacyAgent(t *testing.T, home, label string) string {
	t.Helper()
	p := filepath.Join(home, "Library", "LaunchAgents", label+".plist")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("<plist><dict><key>Label</key><string>"+label+"</string></dict></plist>\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// impr installs nothing, so the label migration is in what it prints: with
// an agent under the old label in place, the printed steps boot it out and
// remove its plist before bootstrapping the new one. Without one, they do
// not mention it. Printing is idempotent and changes nothing on disk.
func TestLaunchdUnitsMigrateTheOldLabel(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "bin", "impr")
	for _, c := range []struct {
		name, legacy, label string
		args                []string
	}{
		{"serve", legacyLaunchdLabel, launchdLabel, []string{"serve", "install-unit", "--print", "--for", "launchd", "--exe", exe}},
		{"cert-check", legacyCheckLabel, checkLabel, []string{"cert", "install-check", "--print", "--for", "launchd", "--exe", exe}},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			h.home = t.TempDir()
			h.ok("server", "token", "add", "--scopes", "read")

			out := h.ok(c.args...)
			_, _, errOut := h.impr(c.args...)
			if !strings.Contains(out, "<key>Label</key><string>"+c.label+"</string>") || strings.Contains(out, "sh.sange") {
				t.Fatalf("plist:\n%s", out)
			}
			if !strings.Contains(errOut, "~/Library/LaunchAgents/"+c.label+".plist") || strings.Contains(errOut, c.legacy) {
				t.Fatalf("no old agent, yet:\n%s", errOut)
			}

			old := legacyAgent(t, h.home, c.legacy)
			code, out2, errOut := h.impr(c.args...)
			if code != 0 || out2 != out {
				t.Fatalf("%d, plist changed:\n%s", code, out2)
			}
			bootout := "launchctl bootout gui/$(id -u)/" + c.legacy
			rm := "rm -f ~/Library/LaunchAgents/" + c.legacy + ".plist"
			bootstrap := "launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/" + c.label + ".plist"
			ib, ir, is := strings.Index(errOut, bootout), strings.Index(errOut, rm), strings.Index(errOut, bootstrap)
			if ib < 0 || ir < 0 || is < 0 || ib > ir || ir > is {
				t.Fatalf("want %q, then %q, then %q in:\n%s", bootout, rm, bootstrap, errOut)
			}
			// Idempotent: the same steps again, and impr itself removed nothing.
			if _, _, again := h.impr(c.args...); again != errOut {
				t.Fatalf("second print differs:\n%s\n---\n%s", errOut, again)
			}
			if _, err := os.Stat(old); err != nil {
				t.Fatalf("impr touched the old agent: %v", err)
			}
			// Once the user has followed the steps, they are no longer printed.
			if err := os.Remove(old); err != nil {
				t.Fatal(err)
			}
			if _, _, after := h.impr(c.args...); strings.Contains(after, c.legacy) {
				t.Fatalf("still migrating:\n%s", after)
			}
		})
	}
}

// doctor and uninstall recognise an agent under the old label.
func TestDoctorAndUninstallRecogniseTheOldLabels(t *testing.T) {
	h := newHarness(t)
	h.home = t.TempDir()
	sshProfile(t, h, "acme-release")
	h.ok("doctor")

	legacyAgent(t, h.home, legacyLaunchdLabel)
	legacyAgent(t, h.home, legacyCheckLabel)
	code, out, _ := h.impr("doctor", "--json")
	if code == 0 {
		t.Fatalf("doctor passed with old agents installed:\n%s", out)
	}
	for _, l := range []string{legacyLaunchdLabel, legacyCheckLabel} {
		if !strings.Contains(out, "launch agent "+l+" uses the label impr used before 2026-11-17") {
			t.Errorf("doctor does not name %s:\n%s", l, out)
		}
	}

	// uninstall names every agent left behind, under either label, and
	// removes none of them.
	dir := t.TempDir()
	legacyAgent(t, h.home, launchdLabel)
	_, _, errOut := h.impr("uninstall", "--dir", dir)
	for _, l := range []string{legacyLaunchdLabel, legacyCheckLabel, launchdLabel} {
		if !strings.Contains(errOut, "launchctl bootout gui/$(id -u)/"+l) {
			t.Errorf("uninstall does not name %s:\n%s", l, errOut)
		}
		if _, err := os.Stat(filepath.Join(h.home, "Library", "LaunchAgents", l+".plist")); err != nil {
			t.Errorf("uninstall removed %s", l)
		}
	}
}

// events.source switches the source of every event impr writes, and an
// unknown value is refused.
func TestEventsSourceSettingReachesEvents(t *testing.T) {
	h := newHarness(t)
	h.ok("config", "set", "notify.desktop", "false")
	if ev := h.ok("events", "tail", "--json"); !strings.Contains(ev, `"source":"https://sange.sh/imprimatur/install/`) ||
		!strings.Contains(ev, `"type":"com.simtabi.sange.imprimatur.config.changed"`) {
		t.Fatalf("default:\n%s", ev)
	}
	if code, _, errOut := h.impr("config", "set", "events.source", "example.com"); code == 0 || !strings.Contains(errOut, "events.source") {
		t.Fatalf("an unknown source was saved: %d %s", code, errOut)
	}
	h.ok("config", "set", "events.source", "simtabi.com")
	h.ok("config", "set", "notify.desktop", "true")
	ev := h.ok("events", "tail", "--json", "--limit", "1")
	if !strings.Contains(ev, `"source":"https://simtabi.com/sange/imprimatur/install/`) {
		t.Fatalf("simtabi.com:\n%s", ev)
	}
	// The old type prefix still selects, deprecated.
	if old := h.ok("events", "tail", "--json", "--type", "sh.sange.imprimatur.config.*"); !strings.Contains(old, "config.changed") {
		t.Fatalf("old prefix filter:\n%s", old)
	}
}
