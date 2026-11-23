package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sangehq/imprimatur/src/internal/secrets"
)

// impr secret set NAME stores a value read from stdin or --file in the OS
// store (here: an owner-only file, as on a host without one) and records
// NAME=reference in .env; impr secret list shows names and references, never
// a value.
func TestSecretSetAndList(t *testing.T) {
	h := newHarness(t)
	h.os = "plan9" // a host with no OS secret store: the file fallback
	val := "-----BEGIN PRIVATE KEY-----\n" + randHex(t, 24) + "\n-----END PRIVATE KEY-----\n"
	h.stdin = val
	var set struct {
		Name string `json:"name"`
		Ref  string `json:"ref"`
	}
	out := h.ok("secret", "set", "IMPR_NOTARY_KEY", "--json")
	if err := json.Unmarshal([]byte(out), &set); err != nil || set.Name != "IMPR_NOTARY_KEY" || !strings.HasPrefix(set.Ref, "file://") {
		t.Fatalf("set: %s %v", out, err)
	}
	if strings.Contains(out, "PRIVATE") {
		t.Fatalf("the value was echoed: %s", out)
	}
	cfg := h.env["IMPR_CONFIG_DIR"]
	m, err := secrets.ReadEnvFile(filepath.Join(cfg, ".env"))
	if err != nil || m["IMPR_NOTARY_KEY"] != set.Ref {
		t.Fatalf(".env: %v %v", m, err)
	}
	b, err := os.ReadFile(strings.TrimPrefix(set.Ref, "file://")) //nolint:gosec // G304: the file under test
	if err != nil || string(b) != val {
		t.Fatalf("stored %q %v", b, err)
	}
	// From a file.
	src := filepath.Join(t.TempDir(), "AuthKey.p8")
	if err := os.WriteFile(src, []byte(val), 0o600); err != nil {
		t.Fatal(err)
	}
	h.stdin = ""
	h.ok("secret", "set", "IMPR_OTHER_KEY", "--file", src)
	list := h.ok("secret", "list", "--json")
	if !strings.Contains(list, "IMPR_NOTARY_KEY") || !strings.Contains(list, "IMPR_OTHER_KEY") || strings.Contains(list, "PRIVATE") {
		t.Fatalf("list: %s", list)
	}
	// Refusals: a bad name, an empty value, both stdin and --file missing.
	h.exits(1, "secret", "set", "impr-key")
	h.exits(1, "secret", "set", "IMPR_EMPTY")
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(filepath.Join(cfg, "secrets")); st.Mode().Perm() != 0o700 {
			t.Fatalf("secrets folder %v", st.Mode().Perm())
		}
	}
}
