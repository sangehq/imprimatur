package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDoctorReportsLoosePermissionsAndToolDigests(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no Unix mode bits; doctor reports none there")
	}
	h := newHarness(t)
	key := filepath.Join(t.TempDir(), "release.key")
	if err := os.WriteFile(key, []byte("not a real key"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.ok("profile", "add", "me-test", "--scope", "personal", "--owner", "me", "--purpose", "test",
		"--set", "platforms.checksums.kind=ssh", "--set", "platforms.checksums.keyRef=file://"+key,
		"--set", "platforms.checksums.fingerprint=SHA256:"+randHex(t, 16))
	doctor := func() DoctorReport {
		t.Helper()
		_, out, _ := h.impr("doctor", "--json")
		var r DoctorReport
		if err := json.Unmarshal([]byte(out), &r); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		return r
	}
	has := func(r DoctorReport, sub string) bool {
		return strings.Contains(strings.Join(r.Problems, "\n"), sub)
	}
	r := doctor()
	if has(r, "writable by group or others") || has(r, "readable by group or others") {
		t.Fatalf("owner-only files were reported: %v", r.Problems)
	}
	if len(r.Tools) < 10 {
		t.Fatalf("doctor lists %d tools, want the allow-list", len(r.Tools))
	}

	cfg := h.env["IMPR_CONFIG_DIR"]
	if err := os.Chmod(cfg, 0o777); err != nil { //nolint:gosec // G302: the test loosens it on purpose
		t.Fatal(err)
	}
	if err := os.Chmod(key, 0o644); err != nil { //nolint:gosec // G302: as above
		t.Fatal(err)
	}
	r = doctor()
	if r.OK || !has(r, cfg+" is writable by group or others") || !has(r, "key file "+key+" is readable by group or others") {
		t.Fatalf("loose permissions were not reported: %v", r.Problems)
	}
}
