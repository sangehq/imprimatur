package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnchorIsOptInAndCatchesARewrite(t *testing.T) {
	h := newHarness(t)
	h.ok("config", "set", "notify.desktop", "false") // an audited command
	if ev := h.ok("events", "tail", "--json", "--type", "audit.*"); strings.Contains(ev, "audit.head") {
		t.Fatal("audit.head was emitted without audit.anchor.enabled")
	}
	h.ok("config", "set", "audit.anchor.enabled", "true")
	h.ok("config", "set", "notify.checkOnCommand", "false")
	if ev := h.ok("events", "tail", "--json", "--type", "audit.*"); !strings.Contains(ev, "audit.head") {
		t.Fatalf("no audit.head after an audited command: %s", ev)
	}

	// Keep an anchor, as a receiver would, then check it.
	anchor := filepath.Join(t.TempDir(), "anchor.json")
	if err := os.WriteFile(anchor, []byte(h.ok("audit", "anchor", "--json")), 0o600); err != nil {
		t.Fatal(err)
	}
	h.ok("config", "set", "notify.desktop", "true") // more history after the anchor
	h.ok("audit", "verify", "--against", anchor)

	// Rewrite the audit trail consistently: it verifies alone, not against the anchor.
	state := h.env["IMPR_STATE_DIR"]
	if err := os.RemoveAll(filepath.Join(state, "audit")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		h.ok("config", "set", "notify.desktop", "true")
	}
	h.ok("audit", "verify")
	out := h.exits(4, "audit", "verify", "--json", "--against", anchor)
	if !strings.Contains(out, `"ok":false`) || !strings.Contains(out, "rewritten") {
		t.Fatalf("a rewrite before the anchor was not caught: %s", out)
	}
}
