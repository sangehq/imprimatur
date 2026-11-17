package guardtest

import (
	"os/exec"
	"path"
	"strings"
	"testing"
)

// keyFileExts are certificate and key files that never belong in the
// repository: the PowerShell toolkit once shipped its author's test
// certificate (old security finding 1, commit 181fee9). Tests generate theirs.
var keyFileExts = []string{".pfx", ".p12", ".cer", ".crt", ".key", ".p8", ".pem"}

// trackedKeyFiles lists the files among tracked that are certificates or keys.
func trackedKeyFiles(tracked []string) []string {
	var bad []string
	for _, f := range tracked {
		ext := strings.ToLower(path.Ext(f))
		for _, k := range keyFileExts {
			if ext == k {
				bad = append(bad, f)
			}
		}
	}
	return bad
}

// ID-24: no certificate or key is tracked, and .gitignore keeps them out.
func TestNoCertificatesOrKeysTracked(t *testing.T) {
	root := repoRoot(t)
	out, err := exec.Command("git", "-C", root, "ls-files").Output()
	if err != nil {
		t.Skipf("not a git checkout: %v", err)
	}
	tracked := strings.Fields(string(out))
	atLeast(t, "tracked files", len(tracked), 100)
	for _, f := range trackedKeyFiles(tracked) {
		t.Errorf("%s is a certificate or key; generate it in the test instead", f)
	}
	ignore := readFile(t, root+"/.gitignore")
	for _, k := range keyFileExts {
		if !strings.Contains(ignore, "*"+k) {
			t.Errorf(".gitignore does not ignore *%s", k)
		}
	}
	if len(trackedKeyFiles([]string{"certs/test-signer.cer", "src/x.go"})) != 1 {
		t.Error("the matcher missed a tracked .cer")
	}
}
