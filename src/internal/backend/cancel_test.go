package backend

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sangehq/imprimatur/src/internal/execx"
	"github.com/sangehq/imprimatur/src/internal/profile"
)

// blockingRunner is a fake whose codesign --sign waits until the context is
// cancelled, as a real tool killed by Ctrl-C would return.
type blockingRunner struct {
	*execx.Fake
	started chan struct{}
}

func (b blockingRunner) Run(ctx context.Context, c execx.Cmd) (execx.Result, error) {
	if c.Tool == "codesign" && strings.Contains(strings.Join(c.Args, " "), "--sign") {
		close(b.started)
		<-ctx.Done()
		return execx.Result{}, ctx.Err()
	}
	return b.Fake.Run(ctx, c)
}

// TestAnInterruptedSignRemovesItsKeychain: cancelling the context mid-sign
// (impr's Ctrl-C) deletes the temporary keychain and the folder holding the
// re-wrapped .p12 before Sign returns.
func TestAnInterruptedSignRemovesItsKeychain(t *testing.T) {
	file := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(file, []byte{0xcf, 0xfa, 0xed, 0xfe}, 0o600); err != nil {
		t.Fatal(err)
	}
	p12 := filepath.Join(t.TempDir(), "id.p12")
	if err := os.WriteFile(p12, []byte(randHex(t, 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	f := execx.NewFake("codesign", "security", "spctl", "xcrun", "ditto", "openssl")
	r := blockingRunner{Fake: f, started: make(chan struct{})}
	spec := macSpec()
	spec.CertRef, spec.PasswordRef = "env://IMPR_P12", "env://IMPR_P12_PW"
	h := fakeHost("darwin", f, map[string]string{"IMPR_P12": p12, "IMPR_P12_PW": randHex(t, 6)})
	h.Runner = r
	a := &Apple{H: h, Spec: spec}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := a.Sign(ctx, Artifact{Path: file, Rel: "tool"}, profile.Profile{Name: "mac"})
		done <- err
	}()
	<-r.started
	var keychain string
	for _, c := range f.Calls {
		if c.Tool == "security" && len(c.Args) > 0 && c.Args[0] == "create-keychain" {
			keychain = c.Args[len(c.Args)-1]
		}
	}
	if keychain == "" {
		t.Fatal("no temporary keychain was created")
	}
	cancel()
	if err := <-done; err == nil {
		t.Fatal("an interrupted sign reported success")
	}
	if !f.Called("security", "delete-keychain") {
		t.Fatal("the interrupted sign did not delete its keychain")
	}
	if _, err := os.Stat(filepath.Dir(keychain)); !os.IsNotExist(err) {
		t.Fatalf("the keychain folder %s was left behind", filepath.Dir(keychain))
	}
}
