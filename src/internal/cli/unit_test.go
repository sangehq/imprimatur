package cli

import (
	"encoding/xml"
	"errors"
	"io"
	"strings"
	"testing"
)

func wellFormedXML(t *testing.T, doc string) {
	t.Helper()
	d := xml.NewDecoder(strings.NewReader(doc))
	d.Strict = true
	for {
		if _, err := d.Token(); err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			t.Fatalf("not well-formed XML: %v\n%s", err, doc)
		}
	}
}

// A path an attacker cannot choose, but a person can: spaces, &, <, % and $.
var oddUnit = Unit{Exe: `/opt/my tools/impr & co/<impr>`, Config: "/home/a/.config/imprimatur", State: "/home/a/.local/state/imprimatur",
	Roots: []string{"/srv/builds 100%", "/srv/$HOME"}}

func TestLaunchdAndTaskUnitsEscapePaths(t *testing.T) {
	for name, doc := range map[string]string{"launchd": LaunchdPlist(oddUnit), "task": TaskXML(oddUnit)} {
		wellFormedXML(t, doc)
		if !strings.Contains(doc, "&amp; co/&lt;impr&gt;") {
			t.Errorf("%s: the path is not escaped:\n%s", name, doc)
		}
	}
}

func TestSystemdUnitQuotesPathsAndWritesOnlyStateAndRoots(t *testing.T) {
	u := SystemdUnit(oddUnit)
	for _, want := range []string{
		`ExecStart="/opt/my tools/impr & co/<impr>" serve`,
		`ReadWritePaths="/home/a/.local/state/imprimatur" "/srv/builds 100%%" "/srv/$$HOME"`,
		"ProtectSystem=strict", "ProtectHome=read-only", "NoNewPrivileges=yes", "UMask=0077",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("missing %q in:\n%s", want, u)
		}
	}
}

func TestInstallUnitPrintsOnlyAndNeedsAWorkingConfig(t *testing.T) {
	h := newHarness(t)
	if code, _, errOut := h.impr("serve", "install-unit"); code != 1 || !strings.Contains(errOut, "never installs") {
		t.Fatalf("without --print: %d %s", code, errOut)
	}
	if code, _, errOut := h.impr("serve", "install-unit", "--print", "--exe", "/usr/local/bin/impr"); code != 1 || !strings.Contains(errOut, "no API token") {
		t.Fatalf("without a token: %d %s", code, errOut)
	}
	h.ok("server", "token", "add", "--scopes", "read")
	h.exits(1, "serve", "install-unit", "--print", "--exe", "impr")
	h.exits(1, "serve", "install-unit", "--print", "--exe", "/usr/local/bin/impr", "--for", "upstart")
	for kind, want := range map[string]string{"systemd": "ExecStart=\"/usr/local/bin/impr\" serve", "launchd": "<string>/usr/local/bin/impr</string>",
		"task": "<Command>/usr/local/bin/impr</Command>"} {
		code, out, errOut := h.impr("serve", "install-unit", "--print", "--exe", "/usr/local/bin/impr", "--for", kind)
		if code != 0 || !strings.Contains(out, want) || !strings.Contains(errOut, "installed nothing") {
			t.Errorf("%s: %d %s %s", kind, code, out, errOut)
		}
	}
}
