package cli

import (
	"strings"
	"testing"
)

// Security review: a line break in a path printed into a unit would start a
// new directive (ExecStartPre=..., a launchd key, a task action). Every path
// a unit carries is refused when it holds a control character.
func TestUnitsRefuseControlCharactersInPaths(t *testing.T) {
	h := newHarness(t)
	bad := "/opt/impr\nExecStartPre=/bin/sh -c id"
	for _, kind := range []string{"systemd", "launchd", "task"} {
		code, out, errOut := h.impr("cert", "install-check", "--print", "--for", kind, "--exe", bad)
		if code != 1 || strings.Contains(out, "ExecStartPre") || !strings.Contains(errOut, "control character") {
			t.Errorf("%s: exit %d\n%s%s", kind, code, out, errOut)
		}
	}
	if err := (Unit{Exe: "/opt/impr", Config: "/c", State: "/s", Roots: []string{"/r\rX"}}).check(); err == nil {
		t.Error("a root with a carriage return was accepted")
	}
	if err := (Unit{Exe: "/opt/impr", Config: "/c", State: "/s", Roots: []string{"/builds"}}).check(); err != nil {
		t.Errorf("ordinary paths: %v", err)
	}
}
