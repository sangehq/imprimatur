package signing

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/sangehq/imprimatur/src/internal/backend"
	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/profile"
)

// Owner decision D-S2 (ID-29, I-20): a Windows or macOS certificate whose
// expiry this host cannot read fails a strict sign, and a lenient one signs
// with a warning. A declared or read expiry signs as before.
func TestUnknownExpiryFailsAStrictSign(t *testing.T) {
	rel := "build/windows/tool_amd64.exe"
	run := func(strict bool, notAfter bool) (string, map[string]string, error) {
		svc, signed, root, manifest := setupMulti(t, map[string]uint16{rel: 0x8664})
		var log bytes.Buffer
		svc.Log = &log
		svc.BackendFor = func(_ backend.Host, p profile.Profile, _ string) (backend.Backend, error) {
			f := &fakeWin{mu: &sync.Mutex{}, signed: signed, thumb: p.Platforms.Windows.Thumbprint}
			if notAfter {
				f.notAfter = &testExpiry
			}
			return f, nil
		}
		_, err := svc.Sign(context.Background(), SignOptions{Root: root, Manifest: manifest, Commit: strings.Repeat("1", 40),
			Tree: strings.Repeat("2", 40), Profile: "acme", Purpose: "internal", Platforms: []string{"windows"}, Strict: strict})
		return log.String(), signed, err
	}
	if _, signed, err := run(true, false); contract.CodeOf(err) != contract.SignFailed || !strings.Contains(err.Error(), "expiry") || len(signed) != 0 {
		t.Fatalf("strict, unknown expiry: %v, signed %v", err, signed)
	}
	if log, signed, err := run(false, false); err != nil || len(signed) != 1 || !strings.Contains(log, "expiry") {
		t.Fatalf("lenient, unknown expiry: %v, signed %v, log %q", err, signed, log)
	}
	if _, signed, err := run(true, true); err != nil || len(signed) != 1 {
		t.Fatalf("strict, known expiry: %v, signed %v", err, signed)
	}
}
