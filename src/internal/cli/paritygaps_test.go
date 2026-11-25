package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// O-62: profile add NAME --file FILE refuses a file whose profile is named
// something else, and adds nothing; a file with the same name is taken.
func TestProfileAddFileMustNameTheSameProfile(t *testing.T) {
	h := newHarness(t)
	h.ok("profile", "add", "other", "--scope", "personal", "--owner", "tester", "--purpose", "test",
		"--set", "platforms.checksums.kind=ssh", "--set", "platforms.checksums.keyRef=env://K",
		"--set", "platforms.checksums.fingerprint=SHA256:"+strings.Repeat("A", 43))
	f := filepath.Join(t.TempDir(), "other.json")
	h.ok("profile", "export", "other", "--out", f)
	code, _, errOut := h.impr("profile", "add", "mine", "--file", f)
	if code != 1 || !strings.Contains(errOut, "the file names profile other, not mine") {
		t.Fatalf("a file naming another profile: %d %s", code, errOut)
	}
	if strings.Contains(h.ok("profile", "list"), "mine") {
		t.Fatal("the refused profile was added")
	}
	h.ok("profile", "rm", "other", "--force")
	h.ok("profile", "add", "other", "--file", f)
}

// O-12: the PowerShell parser matched an option's value from a fixed set
// without regard to case (its Map options: --purpose and rules' --scope), so
// --purpose Release and --scope Product still work; other values keep their
// case.
func TestFixedSetValuesIgnoreCase(t *testing.T) {
	for name, spec := range map[string]flagSpec{"sign": signFlags, "build": buildFlags, "approve": approveFlags} {
		p, err := parse([]string{"--purpose", "Release", "--profile", "Acme"}, spec)
		if err != nil || p.str("purpose") != "release" || p.str("profile") != "Acme" {
			t.Errorf("%s: purpose %q profile %q (%v)", name, p.str("purpose"), p.str("profile"), err)
		}
	}
	p, err := parse([]string{"--scope=Product", "--product", "Tool"}, rulesFlags)
	if err != nil || p.str("scope") != "product" || p.str("product") != "Tool" {
		t.Errorf("rules: scope %q product %q (%v)", p.str("scope"), p.str("product"), err)
	}
}

// O-74: config set trims the spaces and the quotes around a value, as the
// PowerShell line did (impr.ps1:474), so a value quoted twice is stored bare.
func TestConfigSetTrimsQuotes(t *testing.T) {
	h := newHarness(t)
	for _, v := range []string{`'127.0.0.1:8765'`, `"127.0.0.1:8765"`, ` "127.0.0.1:8765" `} {
		h.ok("config", "set", "server.listen", v)
		if got := strings.TrimSpace(h.ok("config", "get", "server.listen")); got != `"127.0.0.1:8765"` { // get prints JSON
			t.Errorf("set %q: got %q", v, got)
		}
	}
	h.ok("config", "set", "server.roots", `'["/srv/a", "/srv/b"]'`)
	if got := h.ok("config", "get", "server.roots"); !strings.Contains(got, "/srv/b") {
		t.Errorf("a quoted JSON list: %q", got)
	}
	if code, _, _ := h.impr("config", "set", "server.listen", `""`); code != 1 {
		t.Errorf("a value that is only quotes was accepted: %d", code)
	}
	// Exactly one matched pair goes: quotes inside it, or a quote with no
	// partner, are part of the value.
	for in, want := range map[string]string{
		`'"a b"'`: `"a b"`, `"'a b'"`: `'a b'`, `a b"`: `a b"`, `"a b'`: `"a b'`, `'a b`: `'a b`,
		` 'a b' `: `a b`, `""`: ``, `"`: `"`, `''x''`: `'x'`,
	} {
		if got := trimValueQuotes(in); got != want {
			t.Errorf("trimValueQuotes(%s) = %s, want %s", in, got, want)
		}
	}
}

// O-95: bash splits --purpose=re at the "=" (COMP_WORDBREAKS), and the
// completer still offers the option's values, as the PowerShell line's did.
func TestBashCompletesAfterAnEqualsSign(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("needs bash")
	}
	script, err := CompletionScript("bash")
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "impr.bash")
	if err := os.WriteFile(f, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	for words, want := range map[string]string{
		`impr sign --purpose = re`: "release",
		`impr sign --purpose =`:    "release test internal",
		`impr sign --purpose re`:   "release",
		`impr rules --scope = pu`:  "publisher",
	} {
		w := strings.Fields(words)
		cword := len(w) - 1
		cmd := exec.Command(bash, "-c", `source "$1"; COMP_WORDS=(`+words+`); COMP_CWORD=`+strconv.Itoa(cword)+`; _impr; echo "${COMPREPLY[*]}"`, "x", f)
		out, err := cmd.CombinedOutput()
		got := strings.Join(strings.Fields(string(out)), " ")
		if err != nil || got != want {
			t.Errorf("%q: %q (%v), want %q", words, got, err, want)
		}
	}
}

// O-120: the first run on Windows with no PowerShell settings makes the
// default profile the old migration made (profiles.ps1 Invoke-ProfileMigration):
// the self-signed test certificate as a personal test profile, which can
// never sign a release. Elsewhere, and on a later run, nothing is made.
func TestFirstRunOnWindowsMakesTheTestDefaultProfile(t *testing.T) {
	h := newHarness(t)
	h.os = "windows"
	var list struct {
		Default  string `json:"default"`
		Profiles []struct {
			Name      string   `json:"name"`
			Scope     string   `json:"scope"`
			Purpose   []string `json:"purpose"`
			Platforms struct {
				Windows struct {
					Backend string `json:"backend"`
					Subject string `json:"subject"`
				} `json:"windows"`
			} `json:"platforms"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal([]byte(h.ok("profile", "list", "--json")), &list); err != nil {
		t.Fatal(err)
	}
	if list.Default != "default" || len(list.Profiles) != 1 {
		t.Fatalf("a first run on Windows: %+v", list)
	}
	p := list.Profiles[0]
	if p.Name != "default" || p.Scope != "personal" || strings.Join(p.Purpose, ",") != "test" ||
		p.Platforms.Windows.Backend != "cert-store" || p.Platforms.Windows.Subject != "CN=tester Code Signing (Test)" {
		t.Fatalf("the profile: %+v", p)
	}
	// Removed, it is not made again: the index records the first run.
	h.ok("profile", "rm", "default", "--force")
	if out := h.ok("profile", "list", "--json"); strings.Contains(out, `"default"`) && strings.Contains(out, `"name"`) {
		t.Fatalf("made twice: %s", out)
	}
	other := newHarness(t)
	other.os = "linux"
	if out := other.ok("profile", "list", "--json"); strings.Contains(out, `"name"`) {
		t.Fatalf("a first run on Linux made a profile: %s", out)
	}
}
