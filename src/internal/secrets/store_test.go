package secrets

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/execx"
)

func secretValue(t *testing.T) string {
	t.Helper()
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "-----BEGIN PRIVATE KEY-----\n" + hex.EncodeToString(b) + "\n-----END PRIVATE KEY-----\n"
}

// ID-32: .env holds references only. env://NAME reads the process first,
// then the .env line, resolving its reference once.
func TestEnvFileHoldsReferencesOnly(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, ".env")
	if err := os.WriteFile(env, []byte("# imprimatur\nIMPR_NOTARY_KEY=secret://IMPR_NOTARY_KEY\nIMPR_SUBJECT=keychain://Acme\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := execx.NewFake("security")
	val := secretValue(t)
	f.Handle = func(c execx.Cmd) execx.Result {
		if c.Tool == "security" && len(c.Args) > 0 && c.Args[0] == "find-generic-password" {
			return execx.Result{Stdout: []byte(encodeStored(val) + "\n")}
		}
		return execx.Result{}
	}
	r := Resolver{Runner: f, GOOS: "darwin", Getenv: func(string) string { return "" }, EnvFile: env}
	if got, err := r.Resolve(context.Background(), "env://IMPR_NOTARY_KEY"); err != nil || got != val {
		t.Fatalf("env:// through .env: %q %v", got, err)
	}
	if got, err := r.Resolve(context.Background(), "env://IMPR_SUBJECT"); err != nil || got != "Acme" {
		t.Fatalf("a keychain reference: %q %v", got, err)
	}
	// The process environment still wins.
	r.Getenv = func(k string) string {
		if k == "IMPR_SUBJECT" {
			return "From the process"
		}
		return ""
	}
	if got, _ := r.Resolve(context.Background(), "env://IMPR_SUBJECT"); got != "From the process" {
		t.Fatalf("the process environment lost: %q", got)
	}
	for name, body := range map[string]string{
		"a value":     "IMPR_X=" + secretValue(t)[:30] + "\n",
		"an env loop": "IMPR_X=env://IMPR_X\n",
		"a bad name":  "impr-x=secret://A\n",
		"no equals":   "IMPR_X\n",
		"a duplicate": "IMPR_X=secret://A\nIMPR_X=secret://B\n",
	} {
		if err := os.WriteFile(env, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadEnvFile(env); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if runtime.GOOS != "windows" {
		if err := os.WriteFile(env, []byte("IMPR_X=secret://A\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(env, 0o644); err != nil { //nolint:gosec // G302: the defect under test
			t.Fatal(err)
		}
		if _, err := ReadEnvFile(env); contract.CodeOf(err) != contract.Usage {
			t.Fatalf("a .env others can read: %v", err)
		}
	}
}

// ID-33: Put stores a value in the OS store and returns its reference. On
// macOS the value reaches security on stdin, never on its command line; with
// no store it lands in an owner-only file and the reference is file://.
func TestPutKeepsTheValueOffCommandLines(t *testing.T) {
	val := secretValue(t)
	f := execx.NewFake("security")
	r := Resolver{Runner: f, GOOS: "darwin", Getenv: func(string) string { return "" }}
	ref, err := r.Put(context.Background(), "IMPR_NOTARY_KEY", val, t.TempDir())
	if err != nil || ref != "secret://IMPR_NOTARY_KEY" {
		t.Fatalf("put: %q %v", ref, err)
	}
	if len(f.Calls) != 1 {
		t.Fatalf("calls: %v", f.Calls)
	}
	c := f.Calls[0]
	if strings.Contains(strings.Join(c.Args, " "), "PRIVATE") || strings.Contains(strings.Join(c.Args, " "), encodeStored(val)) {
		t.Fatalf("the value is on the command line: %v", c.Args)
	}
	if !strings.Contains(string(c.Stdin), encodeStored(val)) || strings.Contains(string(c.Stdin), "PRIVATE") {
		t.Fatalf("the value did not reach stdin encoded: %q", c.Stdin)
	}
	for _, bad := range []string{"impr-key", "IMPR KEY", "", strings.Repeat("A", 80)} {
		if _, err := r.Put(context.Background(), bad, val, t.TempDir()); err == nil {
			t.Errorf("name %q was accepted", bad)
		}
	}

	// No store on this host: an owner-only file.
	dir := t.TempDir()
	r = Resolver{Runner: execx.NewFake(), GOOS: "plan9", Getenv: func(string) string { return "" }}
	ref, err = r.Put(context.Background(), "IMPR_NOTARY_KEY", val, dir)
	if err != nil || !strings.HasPrefix(ref, "file://") {
		t.Fatalf("fallback: %q %v", ref, err)
	}
	p := strings.TrimPrefix(ref, "file://")
	b, err := os.ReadFile(p) //nolint:gosec // G304: the file under test
	if err != nil || string(b) != val {
		t.Fatalf("the file holds %q, %v", b, err)
	}
	if st, _ := os.Stat(p); runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %v", st.Mode().Perm())
	}
	if st, _ := os.Stat(filepath.Dir(p)); runtime.GOOS != "windows" && st.Mode().Perm() != 0o700 {
		t.Fatalf("folder mode %v", st.Mode().Perm())
	}
}

// SetEnv adds or replaces one NAME=reference line, owner-only, and refuses a
// value that is not a reference.
func TestSetEnvWritesReferencesOwnerOnly(t *testing.T) {
	env := filepath.Join(t.TempDir(), ".env")
	if err := SetEnv(env, "IMPR_A", "secret://IMPR_A"); err != nil {
		t.Fatal(err)
	}
	if err := SetEnv(env, "IMPR_A", "file:///opt/key.p8"); err != nil {
		t.Fatal(err)
	}
	if err := SetEnv(env, "IMPR_B", "plain text"); err == nil {
		t.Fatal("a value was written to .env")
	}
	m, err := ReadEnvFile(env)
	if err != nil || len(m) != 1 || m["IMPR_A"] != "file:///opt/key.p8" {
		t.Fatalf(".env: %v %v", m, err)
	}
	if st, _ := os.Stat(env); runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatalf(".env mode %v", st.Mode().Perm())
	}
}
