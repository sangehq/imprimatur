package signing

import (
	"bytes"
	"context"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/sangehq/imprimatur/src/internal/backend"
	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/profile"
)

// swapper is a Windows backend whose Preflight, which runs after impr hashed
// the files, replaces the file on disk: the attack in security review R2.
type swapper struct {
	fakeWin
	path   string
	evil   []byte
	signed [][]byte
}

func (s *swapper) Preflight(context.Context, profile.Profile) error {
	return os.WriteFile(s.path, s.evil, 0o600)
}

func (s *swapper) Sign(ctx context.Context, a backend.Artifact, p profile.Profile) (backend.Signature, error) {
	b, _ := os.ReadFile(a.Path)
	s.signed = append(s.signed, b)
	return s.fakeWin.Sign(ctx, a, p)
}

// Security review R2: the bytes signed are the bytes that were checked. A file
// changed between the check and the signing tool is refused, never signed.
func TestSignRefusesAFileChangedAfterItWasChecked(t *testing.T) {
	rel := "build/windows/tool_amd64.exe"
	svc, signed, root, manifest := setupMulti(t, map[string]uint16{rel: 0x8664})
	evil := append(minimalPE(0x8664, "evil"), []byte("payload")...)
	sw := &swapper{fakeWin: fakeWin{mu: &sync.Mutex{}, signed: signed, thumb: tA, notAfter: &testExpiry}, path: root + "/" + rel, evil: evil}
	svc.BackendFor = func(backend.Host, profile.Profile, string) (backend.Backend, error) { return sw, nil }
	_, err := svc.Sign(context.Background(), SignOptions{Root: root, Manifest: manifest, Commit: strings.Repeat("1", 40),
		Tree: strings.Repeat("2", 40), Profile: "acme", Purpose: "internal", Platforms: []string{"windows"}, Strict: true})
	if contract.CodeOf(err) != contract.SignFailed || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("a file swapped after the check: %v", err)
	}
	for _, b := range sw.signed {
		if bytes.Contains(b, []byte("payload")) {
			t.Fatal("the swapped bytes reached the signing tool")
		}
	}
}
