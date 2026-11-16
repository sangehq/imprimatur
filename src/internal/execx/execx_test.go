package execx

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestAllowListIsExactly pins the allow-list: adding a tool is a reviewed
// change to this test, never a side effect.
func TestAllowListIsExactly(t *testing.T) {
	// powershell joined 2026-11-16 for impr rules test, in one form: impr's embedded
	// Test-AppLockerPolicy script, checked byte for byte (powershell.go).
	want := []string{"az", "certutil", "codesign", "cosign", "ditto", "git", "go", "gpg", "minisign", "osslsigncode", "powershell", "secret-tool", "security",
		"signtool", "spctl", "ssh-keygen", "xcrun"}
	if got := Names(); !slices.Equal(got, want) {
		t.Fatalf("allow-list %v, want %v", got, want)
	}
}

func TestCheckRefuses(t *testing.T) {
	for _, c := range []Cmd{
		{Tool: "sh", Args: []string{"-c", "true"}},
		{Tool: "bash"},
		{Tool: "/usr/bin/codesign"},
		{Tool: "xcrun", Args: []string{"clang"}},
		{Tool: "xcrun"},
		{Tool: "git", Args: []string{"status", "--porcelain"}}, // fsmonitor not forced off
		{Tool: "git", Args: []string{"-c", "core.sshCommand=x", "fetch"}},
		{Tool: "git"},
		{Tool: "go", Args: []string{"run", "."}},
		{Tool: "go", Args: []string{"build", "-toolexec", "x", "."}},
		{Tool: "go", Args: []string{"build", "-overlay=o.json", "."}},
		{Tool: "go"},
	} {
		if err := Check(c); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("%v: want ErrNotAllowed, got %v", c, err)
		}
	}
	for _, ok := range []Cmd{
		{Tool: "xcrun", Args: []string{"notarytool", "submit"}},
		{Tool: "git", Args: []string{"rev-parse", "HEAD^{tree}"}},
		{Tool: "go", Args: []string{"build", "-trimpath", "-o", "x", "./cmd/x"}},
	} {
		if err := Check(ok); err != nil {
			t.Fatalf("%v: %v", ok, err)
		}
	}
}

func TestOSRunnerRefusesAndResolvesAbsolute(t *testing.T) {
	if _, err := (OS{}).Run(context.Background(), Cmd{Tool: "sh", Args: []string{"-c", "true"}}); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("the real runner ran a shell: %v", err)
	}
	if p, err := (OS{}).LookPath("ssh-keygen"); err == nil && !filepath.IsAbs(p) {
		t.Fatalf("resolved to a relative path %q", p)
	}
	r, err := (OS{}).Run(context.Background(), Cmd{Tool: "ssh-keygen", Args: []string{"-l", "-f", "/nonexistent/key"}})
	if err == nil && r.ExitCode == 0 {
		t.Fatal("a failing tool reported success")
	}
}

func TestFakeAppliesTheSameAllowList(t *testing.T) {
	f := NewFake("gpg")
	if _, err := f.Run(context.Background(), Cmd{Tool: "sh"}); !errors.Is(err, ErrNotAllowed) {
		t.Fatal("the fake ran a tool the real runner refuses")
	}
	if _, err := f.Run(context.Background(), Cmd{Tool: "cosign"}); !errors.Is(err, ErrNotFound) {
		t.Fatal("the fake ran a tool it was not given")
	}
}

func TestChildEnvPassesOnlyWhatTheToolNeeds(t *testing.T) {
	environ := []string{"PATH=/bin", "HOME=/h", "LC_ALL=C", "IMPR_RELEASE_KEY=secret-material", "AWS_SECRET_ACCESS_KEY=x",
		"GNUPGHOME=/g", "SSH_AUTH_SOCK=/s", "SIGSTORE_REKOR_URL=https://r"}
	got := strings.Join(ChildEnv(environ, "gpg", []string{"EXTRA=1"}), "\n")
	for _, want := range []string{"PATH=/bin", "HOME=/h", "LC_ALL=C", "GNUPGHOME=/g", "EXTRA=1"} {
		if !strings.Contains(got, want) {
			t.Errorf("gpg env lacks %s", want)
		}
	}
	for _, leak := range []string{"IMPR_RELEASE_KEY", "AWS_SECRET_ACCESS_KEY", "SSH_AUTH_SOCK", "SIGSTORE_REKOR_URL"} {
		if strings.Contains(got, leak) {
			t.Errorf("gpg env leaks %s", leak)
		}
	}
	if c := strings.Join(ChildEnv(environ, "cosign", nil), "\n"); !strings.Contains(c, "SIGSTORE_REKOR_URL") || strings.Contains(c, "GNUPGHOME") {
		t.Errorf("cosign env: %s", c)
	}
	// The guard inspected every variable it was given (a filter that dropped
	// everything would pass the leak checks above).
	if n := len(ChildEnv(environ, "gpg", nil)); n != 4 {
		t.Errorf("gpg kept %d variables, want 4", n)
	}
}

// Audit N-B24: output past the cap marks the buffer truncated, which Run
// turns into an error instead of handing back a cut-off answer.
func TestLimitedMarksTruncation(t *testing.T) {
	var b limited
	b.max = 8
	_, _ = b.Write([]byte("12345"))
	if b.truncated {
		t.Fatal("truncated too early")
	}
	_, _ = b.Write([]byte("67890"))
	if !b.truncated || b.Len() != 8 {
		t.Fatalf("truncated %v len %d", b.truncated, b.Len())
	}
}

// Audit N-B11: a pinned tool is the configured file, not whatever PATH finds,
// and a file whose digest changed is refused before it runs.
func TestPinnedToolsAreExactlyThatFile(t *testing.T) {
	real, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("needs ssh-keygen")
	}
	b, err := os.ReadFile(real)
	if err != nil {
		t.Skip("cannot read ssh-keygen")
	}
	copyPath := filepath.Join(t.TempDir(), "ssh-keygen-pinned")
	if err := os.WriteFile(copyPath, b, 0o700); err != nil { //nolint:gosec // G306: an executable copy
		t.Fatal(err)
	}
	sum, err := CheckPinned(copyPath, "")
	if sum == "" {
		t.Fatalf("digest: %v", err)
	}
	o := OS{Pins: map[string]Pin{"ssh-keygen": {Path: copyPath, SHA256: sum}}}
	if got, err := o.LookPath("ssh-keygen"); err != nil || got != copyPath {
		t.Fatalf("pinned lookup: %s %v (PATH has %s)", got, err, real)
	}
	o.Pins["ssh-keygen"] = Pin{Path: copyPath, SHA256: strings.Repeat("0", 64)}
	if _, err := o.LookPath("ssh-keygen"); err == nil {
		t.Fatal("a tool whose digest does not match its pin was resolved")
	}
	if _, err := o.Run(context.Background(), Cmd{Tool: "ssh-keygen", Args: []string{"-V"}}); err == nil {
		t.Fatal("a tool whose digest does not match its pin ran")
	}
}
