package execx

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestAllowListIsExactly pins the allow-list: adding a tool is a reviewed
// change to this test, never a side effect.
func TestAllowListIsExactly(t *testing.T) {
	want := []string{"certutil", "codesign", "cosign", "ditto", "gpg", "minisign", "osslsigncode", "secret-tool", "security",
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
	} {
		if err := Check(c); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("%v: want ErrNotAllowed, got %v", c, err)
		}
	}
	if err := Check(Cmd{Tool: "xcrun", Args: []string{"notarytool", "submit"}}); err != nil {
		t.Fatal(err)
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
