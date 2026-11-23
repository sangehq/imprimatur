package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// ID-32, ID-33: impr creates its config folder, secrets folder and .env
// owner-only, and doctor reports a .env or secrets folder others can read, a
// .env holding a value, and config files others can write.
func TestConfigLayoutIsOwnerOnlyAndDoctorChecksIt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits")
	}
	h := newHarness(t)
	cfg := filepath.Join(t.TempDir(), "imprimatur") // not there yet: impr creates it
	h.env["IMPR_CONFIG_DIR"] = cfg
	h.ok("profile", "list")
	for p, want := range map[string]os.FileMode{cfg: 0o700, filepath.Join(cfg, "secrets"): 0o700, filepath.Join(cfg, ".env"): 0o600} {
		st, err := os.Stat(p)
		if err != nil || st.Mode().Perm() != want {
			t.Fatalf("%s: %v %v, want %v", p, st, err, want)
		}
	}
	problems := func() string {
		t.Helper()
		var rep DoctorReport
		_, out, errOut := h.impr("doctor", "--json")
		if err := json.Unmarshal([]byte(out), &rep); err != nil {
			t.Fatalf("%v: %s %s", err, out, errOut)
		}
		return strings.Join(rep.Problems, "\n")
	}
	if p := problems(); strings.Contains(p, ".env") || strings.Contains(p, "secrets") {
		t.Fatalf("a fresh layout has problems: %s", p)
	}
	env := filepath.Join(cfg, ".env")
	if err := os.Chmod(env, 0o644); err != nil { //nolint:gosec // G302: the defect under test
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(cfg, "secrets"), 0o755); err != nil { //nolint:gosec // G302: the defect under test
		t.Fatal(err)
	}
	p := problems()
	for _, want := range []string{".env", "secrets"} {
		if !strings.Contains(p, want) {
			t.Errorf("doctor does not report %s:\n%s", want, p)
		}
	}
	// Owner-only again, but the .env holds a value.
	if err := os.Chmod(env, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env, []byte("IMPR_NOTARY_KEY=not-a-reference\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(cfg, "secrets"), 0o700); err != nil { //nolint:gosec // G302: a folder, owner-only
		t.Fatal(err)
	}
	if p := problems(); !strings.Contains(p, "never a value") {
		t.Errorf("a .env value is not reported:\n%s", p)
	}
	// A config.json others can write stops doctor (and every command) outright.
	cfgFile := filepath.Join(cfg, "config.json")
	if err := os.WriteFile(cfgFile, []byte(`{"schema":"imprimatur.config/v1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cfgFile, 0o666); err != nil { //nolint:gosec // G302: the defect under test
		t.Fatal(err)
	}
	if _, out, _ := h.impr("doctor", "--json"); !strings.Contains(out, "config.json is writable by group or others") {
		t.Errorf("a config.json others can write: %s", out)
	}
}
