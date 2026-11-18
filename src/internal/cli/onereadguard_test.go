package cli

import (
	"os"
	"strings"
	"testing"
)

// Security review (I-15): rulesFromFiles takes each file's signer, signature
// check, digest and version information from one read. Reading the file by
// path a second time would let a racer pair one file's signer with another
// file's bytes, so the by-path readers must not appear in it.
func TestRulesReadEachFileOnce(t *testing.T) {
	src, err := os.ReadFile("rulesfiles.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	start := strings.Index(s, "func rulesFromFiles(")
	end := strings.Index(s[start+1:], "\nfunc ")
	if start < 0 || end < 0 {
		t.Fatal("rulesFromFiles not found")
	}
	body := s[start : start+1+end]
	if n := strings.Count(body, "\n"); n < 100 {
		t.Fatalf("rulesFromFiles is %d lines; the guard is reading the wrong text", n)
	}
	if strings.Count(body, "os.ReadFile(") != 1 {
		t.Errorf("rulesFromFiles reads files %d times, want once", strings.Count(body, "os.ReadFile("))
	}
	for _, by := range []string{"backend.ReadPESigner(", "backend.VerifyAuthenticode(", "artifact.SHA256(", "winres.ReadVersion("} {
		if strings.Contains(body, by) {
			t.Errorf("rulesFromFiles reads the file again with %s", by)
		}
	}
}
