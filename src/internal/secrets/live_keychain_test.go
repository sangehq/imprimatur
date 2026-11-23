package secrets

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/sangehq/imprimatur/src/internal/execx"
)

// TestLiveKeychainRoundTrip writes a throwaway secret to the real macOS login
// keychain through Put, reads it back through Resolve, deletes it and checks
// it is gone. It runs only with IMPR_LIVE_KEYCHAIN=1 on macOS, because it
// touches the person's own keychain; the owner asked for it on 2026-11-23.
// The value is generated here and never printed.
func TestLiveKeychainRoundTrip(t *testing.T) {
	if runtime.GOOS != "darwin" || os.Getenv("IMPR_LIVE_KEYCHAIN") != "1" {
		t.Skip("set IMPR_LIVE_KEYCHAIN=1 on macOS to write to the real keychain")
	}
	const name = "IMPR_SELFTEST"
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	value := "-----BEGIN TEST KEY-----\n" + hex.EncodeToString(b) + "\n-----END TEST KEY-----\n"
	del := func() error {
		return exec.Command("security", "delete-generic-password", "-s", Service, "-a", name).Run() //nolint:gosec // G204: fixed arguments
	}
	_ = del() // an item left by an earlier, interrupted run
	r := Resolver{Runner: execx.OS{Timeout: time.Minute}, GOOS: "darwin", Getenv: func(string) string { return "" }}
	ctx := context.Background()
	ref, err := r.Put(ctx, name, value, "")
	if err != nil || ref != "secret://"+name {
		t.Fatalf("put: %q %v", ref, err)
	}
	t.Cleanup(func() { _ = del() })
	got, err := r.Resolve(ctx, ref)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got != value {
		t.Fatal("the value read back differs from the value written")
	}
	if err := del(); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := exec.Command("security", "find-generic-password", "-s", Service, "-a", name).Run(); err == nil { //nolint:gosec // G204: fixed arguments
		t.Fatal("the item is still in the keychain after delete")
	}
	t.Logf("keychain round trip: written as %s, read back equal, deleted, gone", ref)
}
