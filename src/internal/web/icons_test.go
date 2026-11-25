package web

import (
	"regexp"
	"strings"
	"testing"
)

var (
	iconUseRe = regexp.MustCompile(`icon "([a-z0-9-]+)"`)
	symbolRe  = regexp.MustCompile(`<symbol id="tabler-([a-z0-9-]+)"`)
)

// usedIcons is every icon a template names.
func usedIcons(t *testing.T) map[string]bool {
	t.Helper()
	used := map[string]bool{}
	for _, text := range templateFiles(t) {
		for _, m := range iconUseRe.FindAllStringSubmatch(text, -1) {
			used[m[1]] = true
		}
	}
	return used
}

// spriteIcons is every icon the vendored sprite holds.
func spriteIcons(t *testing.T) map[string]bool {
	t.Helper()
	b, err := assetFS.ReadFile("assets/vendor/tabler-icons.svg")
	if err != nil {
		t.Fatal(err)
	}
	in := map[string]bool{}
	for _, m := range symbolRe.FindAllStringSubmatch(string(b), -1) {
		in[m[1]] = true
	}
	return in
}

// Every icon a template names is in the sprite: a missing one draws nothing
// and fails nowhere else.
func TestEveryIconIsInTheSprite(t *testing.T) {
	used, in := usedIcons(t), spriteIcons(t)
	atLeast(t, "icons named by templates", len(used), 10)
	atLeast(t, "icons in the sprite", len(in), 10)
	var missing []string
	for name := range used {
		if !in[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("the sprite lacks %s: add them to assets/vendor/icons.txt and run make tabler-vendor", strings.Join(missing, ", "))
	}
}
