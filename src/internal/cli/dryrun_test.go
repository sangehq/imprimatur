package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sangehq/imprimatur/src/internal/signing"
)

// impr sign --dry-run runs every check and prints the plan, signing nothing
// and writing no record; a plan a real run would stop at exits 5.
func TestSignDryRunSignsNothing(t *testing.T) {
	h := newHarness(t)
	internalSSHProfile(t, h, "p")
	root, manifest, commit, tree := build(t)
	args := []string{"sign", "--root", root, "--manifest", manifest, "--commit", commit, "--tree", tree,
		"--profile", "p", "--purpose", "internal", "--platforms", "checksums", "--dry-run"}
	var res signing.Result
	if err := json.Unmarshal([]byte(h.ok(append(args, "--json")...)), &res); err != nil {
		t.Fatal(err)
	}
	if !res.DryRun || !res.OK || len(res.Plan) != 1 || res.Plan[0].Platform != "checksums" || !res.Plan[0].Ready {
		t.Fatalf("plan: %+v", res)
	}
	_, _, errOut := h.impr(args...)
	if !strings.Contains(errOut, "nothing was signed") {
		t.Fatalf("the human answer: %s", errOut)
	}
	for _, f := range []string{signing.ManifestFile, signing.SumsFile} {
		if _, err := os.Stat(filepath.Join(root, "build", f)); !os.IsNotExist(err) {
			t.Fatalf("a dry run wrote %s: %v", f, err)
		}
	}
	// A key that is not there: the plan says so and exits 5.
	h.env["IMPR_K"] = filepath.Join(t.TempDir(), "missing")
	h.exits(5, args...)
}
