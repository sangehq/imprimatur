package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ID-16, O-69: impr cert show is cert list plus the steps to trust a test
// certificate impr made, and only when the .cer on disk is the certificate
// the profile pins (old security finding 1: never point at another file).
func TestCertShow(t *testing.T) {
	h := newHarness(t)
	h.home = t.TempDir()
	var c CertCreated
	if err := json.Unmarshal([]byte(h.ok("cert", "create", "--name", "me-test", "--json")), &c); err != nil {
		t.Fatal(err)
	}
	_, _, e := h.impr("cert", "show")
	if !strings.Contains(e, "me-test") || !strings.Contains(e, "certutil -user -addstore Root "+c.PublicCert) {
		t.Fatalf("cert show: %s", e)
	}
	if h.ok("cert", "show", "--json") != h.ok("cert", "list", "--json") {
		t.Fatal("cert show --json differs from cert list --json")
	}
	if err := os.WriteFile(c.PublicCert, []byte("not the pinned certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, e = h.impr("cert", "show")
	if strings.Contains(e, "certutil") || !strings.Contains(e, "does not match") {
		t.Fatalf("a .cer that is not the pinned certificate was offered for trust: %s", e)
	}
}

// ID-16, O-72, O-74: config list is config show; config set joins the words
// of its value, as the PowerShell toolkit did, and refuses an empty one.
func TestConfigListAndSetWords(t *testing.T) {
	h := newHarness(t)
	if h.ok("config", "list") != h.ok("config", "show") {
		t.Fatal("config list differs from config show")
	}
	dir1, dir2 := filepath.ToSlash(t.TempDir()), filepath.ToSlash(t.TempDir())
	h.ok("config", "set", "server.roots", `["`+dir1+`",`, `"`+dir2+`"]`)
	if got := h.ok("config", "get", "server.roots"); !strings.Contains(got, dir1) || !strings.Contains(got, dir2) {
		t.Fatalf("server.roots: %s", got)
	}
	h.exits(1, "config", "set", "server.listen", "")
	h.exits(1, "config", "set", "server.listen")
}
