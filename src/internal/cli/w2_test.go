package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sangehq/imprimatur/src/internal/notify"
	notifykit "github.com/simtabi/go-notifykit/src"
)

// W2: impr profile import-legacy, run as a command (it was never run).
func TestImportLegacyCommand(t *testing.T) {
	h := newHarness(t)
	legacy := t.TempDir()
	settings := `{"WINDOWS_SIGNER":"Certum","CERTUM_SUBJECT":"Open Source Developer, Pat Doe","CERTUM_THUMBPRINT":"` + strings.Repeat("CD", 20) + `"}`
	if err := os.WriteFile(filepath.Join(legacy, "imprimatur.settings.json"), []byte(settings), 0o600); err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Imported []string `json:"imported"`
		Skipped  []string `json:"skipped"`
		Default  string   `json:"default"`
	}
	if err := json.Unmarshal([]byte(h.ok("profile", "import-legacy", "--from", legacy, "--json")), &rep); err != nil ||
		len(rep.Imported) != 1 || rep.Default != "default" {
		t.Fatalf("import: %+v %v", rep, err)
	}
	// A second run keeps what is there; text mode says what it did.
	if _, _, e := h.impr("profile", "import-legacy", "--from", legacy); !strings.Contains(e, "default") {
		t.Fatalf("second import: %s", e)
	}
	h.exits(1, "profile", "import-legacy", "--from", filepath.Join(t.TempDir(), "missing"))
}

// W2: impr tools list and pin (never run).
func TestToolsCommand(t *testing.T) {
	h := newHarness(t)
	var list struct {
		Contract int       `json:"contract"`
		Tools    []ToolRow `json:"tools"`
	}
	if err := json.Unmarshal([]byte(h.ok("tools", "list", "--json")), &list); err != nil || list.Contract != 1 || len(list.Tools) < 15 {
		t.Fatalf("tools list: %+v %v", list, err)
	}
	if _, _, e := h.impr("tools"); !strings.Contains(e, "git") {
		t.Fatalf("tools (text): %s", e)
	}
	if _, err := exec.LookPath("git"); err == nil {
		out := h.ok("tools", "pin", "git")
		var pin struct{ Path, SHA256 string }
		if err := json.Unmarshal([]byte(out), &pin); err != nil || len(pin.SHA256) != 64 || !filepath.IsAbs(pin.Path) {
			t.Fatalf("tools pin git: %s %v", out, err)
		}
	}
	h.exits(1, "tools", "pin", "bash")
	h.exits(1, "tools", "pin")
	h.exits(1, "tools", "frob")
}

// W2: impr notify reaches go-notifykit's command (never run); a send goes to
// the notifier, here a recorder, never to the desktop.
func TestNotifyCommand(t *testing.T) {
	h := newHarness(t)
	rec := &notifykit.Recorder{}
	cfg := notify.Config(t.TempDir(), false, nil, func(string) string { return "" })
	cfg.Backend = rec
	n, err := notifykit.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.notifier = n
	h.ok("notify", "send", "--title", "Release signed", "--body", "acme/tool v1.2.3")
	if sent := rec.Sent(); len(sent) != 1 || sent[0].Title != "Release signed" {
		t.Fatalf("sent %+v", sent)
	}
	if runtime.GOOS != "windows" {
		h.exits(1, "notify", "frob")
	}
}
