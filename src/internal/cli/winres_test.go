package cli

import (
	"crypto/x509/pkix"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sangehq/imprimatur/src/internal/testpe"
	"github.com/sangehq/imprimatur/src/internal/winres"
)

func TestBuildEmbedsWindowsVersionInfo(t *testing.T) {
	repo := goRepo(t)
	h := newHarness(t)
	pkg := filepath.Join(repo, "src", "cmd", "hello")
	exe := filepath.Join(repo, "build", "windows", "hello_windows_amd64.exe")
	read := func() map[string]string {
		t.Helper()
		v, err := winres.ReadVersion(exe)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	noSyso := func() {
		t.Helper()
		if left, _ := filepath.Glob(filepath.Join(pkg, "zz_impr_winres_*.syso")); len(left) > 0 {
			t.Fatalf("impr left its .syso in the package: %v", left)
		}
	}

	h.ok("build", "--repo-root", repo, "--targets", "windows/amd64", "--version", "v1.4.2",
		"--product", "Hello Tool", "--company", "Acme Ltd", "--copyright", "2026 Acme Ltd")
	noSyso()
	if v := read(); v["ProductName"] != "Hello Tool" || v["CompanyName"] != "Acme Ltd" || v["FileVersion"] != "1.4.2.0" ||
		v["ProductVersion"] != "v1.4.2" || v["OriginalFilename"] != "hello.exe" {
		t.Fatalf("version info: %v", v)
	}

	// The default product name is the binary name.
	h.ok("build", "--repo-root", repo, "--targets", "windows/amd64", "--version", "v1.4.2")
	if v := read(); v["ProductName"] != "hello" {
		t.Fatalf("default product: %v", v)
	}

	// --no-winres embeds nothing.
	h.ok("build", "--repo-root", repo, "--targets", "windows/amd64", "--no-winres")
	if v := read(); len(v) != 0 {
		t.Fatalf("--no-winres embedded %v", v)
	}

	// winres/winres.json in the package supplies the strings. The files this
	// test adds are untracked, so these builds pass --allow-dirty.
	if err := os.MkdirAll(filepath.Join(pkg, "winres"), 0o750); err != nil {
		t.Fatal(err)
	}
	j := `{"RT_VERSION":{"#1":{"0000":{"fixed":{"file_version":"0.0.0.0"},"info":{"0409":{"ProductName":"From JSON","CompanyName":"JSON Ltd"}}}}},
	      "RT_MANIFEST":{"#1":{"0409":{"execution-level":"asInvoker"}}}}`
	if err := os.WriteFile(filepath.Join(pkg, "winres", "winres.json"), []byte(j), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, errOut := h.impr("build", "--allow-dirty", "--repo-root", repo, "--targets", "windows/amd64", "--version", "v2.0.0")
	if v := read(); v["ProductName"] != "From JSON" || v["CompanyName"] != "JSON Ltd" || v["FileVersion"] != "2.0.0.0" {
		t.Fatalf("winres.json: %v", v)
	}
	if !strings.Contains(errOut, "RT_MANIFEST settings are not applied") {
		t.Errorf("unapplied manifest settings must be reported: %s", errOut)
	}
	// A PNG icon in winres.json is refused, with the fix.
	if err := os.WriteFile(filepath.Join(pkg, "winres", "winres.json"), []byte(`{"RT_GROUP_ICON":{"APP":{"0000":["icon.png"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := h.impr("build", "--allow-dirty", "--repo-root", repo, "--targets", "windows/amd64"); code != 1 || !strings.Contains(errOut, "not a .ico file") {
		t.Fatalf("a PNG icon: %d %s", code, errOut)
	}
	noSyso()
	if err := os.RemoveAll(filepath.Join(pkg, "winres")); err != nil {
		t.Fatal(err)
	}

	// The project's own .syso for the target wins; another OS's does not count.
	own, err := winres.Syso("amd64", winres.Info{ProductName: "Their Own", FileVersion: "9"}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkg, "x_linux_amd64.syso"), []byte("not for windows"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.ok("build", "--allow-dirty", "--repo-root", repo, "--targets", "windows/amd64", "--version", "v1.0.0", "--product", "Ours")
	if v := read(); v["ProductName"] != "Ours" {
		t.Fatalf("a linux .syso stopped the version info: %v", v)
	}
	if err := os.Remove(filepath.Join(pkg, "x_linux_amd64.syso")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkg, "rsrc_windows_amd64.syso"), own, 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, errOut = h.impr("build", "--allow-dirty", "--repo-root", repo, "--targets", "windows/amd64", "--version", "v1.0.0", "--product", "Ours")
	if v := read(); v["ProductName"] != "Their Own" || !strings.Contains(errOut, "has its own rsrc_windows_amd64.syso") {
		t.Fatalf("the project's own .syso: %v %s", v, errOut)
	}
}

// TestRulesReadTheProductNameFromTheFiles: a binary impr build made carries
// its ProductName, so impr rules needs no --product.
func TestRulesReadTheProductNameFromTheFiles(t *testing.T) {
	repo := goRepo(t)
	h := newHarness(t)
	h.ok("build", "--repo-root", repo, "--targets", "windows/amd64", "--version", "v1.2.0", "--product", "Acme Tool")
	exe := filepath.Join(repo, "build", "windows", "hello_windows_amd64.exe")
	ca := testpe.NewCA(t, "Acme Code Signing CA")
	sub := pkix.Name{CommonName: "Acme Ltd", Organization: []string{"Acme Ltd"}, Country: []string{"GB"}}
	testpe.SignFile(t, exe, sub, ca)

	code, out, errOut := h.impr("rules", exe, "--scope", "product", "--json")
	if code != 0 || !strings.Contains(out, "ACME TOOL") || !strings.Contains(errOut, `product "Acme Tool", read from the files`) {
		t.Fatalf("product from the file: %d %s %s", code, out, errOut)
	}
	// An explicit --product still wins.
	if out := h.ok("rules", exe, "--scope", "product", "--product", "Other", "--json"); !strings.Contains(out, "OTHER") {
		t.Fatalf("--product: %s", out)
	}
	// A file with no version information needs --product.
	bare, _ := testpe.Signed(t, t.TempDir(), "bare.exe", sub, ca)
	if code, _, errOut := h.impr("rules", bare, "--scope", "product"); code != 1 || !strings.Contains(errOut, "carries no ProductName") {
		t.Fatalf("no version info: %d %s", code, errOut)
	}
}
