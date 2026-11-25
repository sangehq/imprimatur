package guardtest

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The docs drifted from the code in ways no reader caught: a recipe naming
// a policy file impr never writes, pages naming options impr refuses (the
// 2026-11-17 readiness audit, old bug 16). These guards read the docs and the
// code and fail on either kind of mismatch.

var (
	imprCall  = regexp.MustCompile("\\bimpr [a-z][^`|;&]*")
	longFlag  = regexp.MustCompile(`(?:^|[^\w-])(--[a-z][a-z0-9-]*)`)
	flagSpec  = regexp.MustCompile(`"([a-z][a-z0-9-]*)":\s*(?:boolFlag|stringFlag|listFlag|repeatFlag|foldFlag)`)
	policyXML = regexp.MustCompile(`\b([a-z][a-z0-9-]*\.xml)\b`)
	codeXML   = regexp.MustCompile(`"([a-z][a-z0-9-]*\.xml)"`)
)

// flagExempt are commands whose options another package defines, with why.
var flagExempt = map[string]string{
	"notify": "go-notifykit's RunCLI parses impr notify's options (--title, --body); measured 2026-11-17, 1 docs line",
}

// docsFiles are the docs pages and README, without the migration recipe,
// which names the PowerShell options on purpose.
func docsFiles(t *testing.T) map[string]string {
	t.Helper()
	root := repoRoot(t)
	out := map[string]string{"README.md": readFile(t, filepath.Join(root, "README.md"))}
	err := filepath.Walk(filepath.Join(root, "docs"), func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(p, ".md") || strings.HasSuffix(p, "migrate-from-powershell.md") {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		out[filepath.ToSlash(rel)] = readFile(t, p)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// cliSources is the non-test source of the cli package.
func cliSources(t *testing.T) string {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(repoRoot(t), "src", "internal", "cli", "*.go"))
	var b strings.Builder
	n := 0
	for _, f := range files {
		if !strings.HasSuffix(f, "_test.go") {
			b.WriteString(readFile(t, f))
			n++
		}
	}
	atLeast(t, "cli source files", n, 20)
	return b.String()
}

// unknownFlags lists the --options an `impr CMD ...` call in text uses that
// impr does not accept.
func unknownFlags(text string, known map[string]bool) []string {
	var bad []string
	for _, call := range imprCall.FindAllString(text, -1) {
		cmd := strings.Fields(call)[1]
		if _, ok := flagExempt[cmd]; ok {
			continue
		}
		for _, m := range longFlag.FindAllStringSubmatch(call, -1) {
			if !known[m[1]] {
				bad = append(bad, m[1]+" in `"+strings.TrimSpace(call)+"`")
			}
		}
	}
	return bad
}

func TestDocsNameOnlyOptionsImprAccepts(t *testing.T) {
	known := map[string]bool{"--help": true, "--version": true}
	specs := flagSpec.FindAllStringSubmatch(cliSources(t), -1)
	for _, m := range specs {
		known["--"+m[1]] = true
	}
	atLeast(t, "option specs in the cli package", len(specs), 60)
	calls := 0
	for name, body := range docsFiles(t) {
		calls += len(imprCall.FindAllString(body, -1))
		for _, b := range unknownFlags(body, known) {
			t.Errorf("%s names %s, which impr does not accept", name, b)
		}
	}
	atLeast(t, "impr calls in the docs", calls, 300)
}

func TestDocsNameOnlyPolicyFilesImprWrites(t *testing.T) {
	writes := map[string]bool{}
	for _, m := range codeXML.FindAllStringSubmatch(cliSources(t), -1) {
		writes[m[1]] = true
	}
	if !writes["applocker.xml"] || !writes["wdac-supplemental.xml"] {
		t.Fatalf("the cli package no longer names the policy files it writes: %v", writes)
	}
	seen := 0
	for name, body := range docsFiles(t) {
		for _, m := range policyXML.FindAllStringSubmatch(body, -1) {
			seen++
			if !writes[m[1]] {
				t.Errorf("%s names %s; impr writes %s", name, m[1], "applocker.xml and wdac-supplemental.xml")
			}
		}
	}
	atLeast(t, "policy file names in the docs", seen, 2)
}

func TestDocsDriftGuardsCanFail(t *testing.T) {
	known := map[string]bool{"--profile": true}
	if len(unknownFlags("run `impr build --out dist`", known)) != 1 {
		t.Error("an option impr refuses passed the flag guard")
	}
	if len(unknownFlags("`impr notify send --title x`", known)) != 0 {
		t.Error("an exempt command's options failed the flag guard")
	}
	if m := policyXML.FindAllStringSubmatch(`ConvertFrom-CIPolicy -XmlFilePath policies\wdac.xml`, -1); len(m) != 1 || m[0][1] != "wdac.xml" {
		t.Errorf("the policy file matcher missed wdac.xml: %v", m)
	}
}
