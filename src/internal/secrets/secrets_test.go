package secrets

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/execx"
)

func TestResolve(t *testing.T) {
	r := Resolver{Runner: execx.NewFake(), GOOS: "windows", Getenv: func(k string) string {
		if k == "SET" {
			return "value"
		}
		return ""
	}}
	ctx := context.Background()
	if v, err := r.Resolve(ctx, "env://SET"); err != nil || v != "value" {
		t.Fatalf("%q %v", v, err)
	}
	if _, err := r.Resolve(ctx, "env://UNSET"); contract.CodeOf(err) != contract.Unavailable {
		t.Fatalf("an unset variable: %v", err)
	}
	if v, _ := r.Resolve(ctx, "gpg-agent://ABC"); v != "ABC" {
		t.Fatal("a store reference resolves to its name")
	}
	if _, err := r.Resolve(ctx, "secret://x"); contract.CodeOf(err) != contract.Unavailable {
		t.Fatalf("secret:// on Windows: %v", err)
	}
	if _, err := r.Resolve(ctx, "plain"); contract.CodeOf(err) != contract.Usage {
		t.Fatalf("a value that is not a reference: %v", err)
	}
	f := execx.NewFake("security")
	f.Handle = func(execx.Cmd) execx.Result { return execx.Result{Stdout: []byte("from-keychain\n")} }
	mac := Resolver{Runner: f, GOOS: "darwin", Getenv: func(string) string { return "" }}
	if v, err := mac.Resolve(ctx, "secret://acme/release"); err != nil || v != "from-keychain" {
		t.Fatalf("%q %v", v, err)
	}
}

func TestAsFileWritesKeyMaterialOwnerOnlyAndRemovesIt(t *testing.T) {
	f, err := AsFile("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n", false)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(f.Path)
	if err != nil || (runtime.GOOS != "windows" && st.Mode().Perm() != 0o600) {
		t.Fatalf("mode %v %v", st, err)
	}
	f.Close()
	if _, err := os.Stat(f.Path); !os.IsNotExist(err) {
		t.Fatal("the temporary key file was left behind")
	}
	if _, err := AsFile("/no/such/key", false); contract.CodeOf(err) != contract.Unavailable {
		t.Fatalf("a missing file: %v", err)
	}
}

func TestFileReferences(t *testing.T) {
	p := filepath.Join(t.TempDir(), "k.pem")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := Resolver{Getenv: func(string) string { return "" }}
	if v, err := r.Resolve(context.Background(), "file://"+p); err != nil || v != p {
		t.Fatalf("%q %v", v, err)
	}
	if _, err := r.Resolve(context.Background(), "file://relative.pem"); err == nil {
		t.Error("a relative file:// was accepted")
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(p, 0o644); err != nil { //nolint:gosec // G302: the unsafe mode under test
			t.Fatal(err)
		}
		if _, err := r.Resolve(context.Background(), "file://"+p); err == nil {
			t.Error("a key file others can read was accepted")
		}
	}
}
