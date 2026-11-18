package bundle

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/profile"
)

// Security review R5 (I-05): a profile an installed bundle names is managed
// whatever its file says, so turning "managed" off, or changing the owner,
// does not skip the bundle check.
func TestAProfileNamedInABundleMustStayManaged(t *testing.T) {
	s := newSigner(t)
	ctx := context.Background()
	cfg := t.TempDir()
	store := profile.Store{Dir: cfg}
	trusted := []TrustedKey{{Owner: "acme", PublicKey: s.pub}}
	p := orgProfile(t, "acme-release", "acme")
	data := bundleJSON(t, "acme", p)
	if _, _, err := Install(ctx, runner(), store, cfg, data, s.sign(t, data, Namespace), trusted); err != nil {
		t.Fatal(err)
	}
	got, _, err := store.Get("acme-release")
	if err != nil {
		t.Fatal(err)
	}
	swapped := got
	swapped.Managed = false
	swapped.Platforms.Checksums.Fingerprint = "SHA256:" + randHex(t, 16)
	if err := Check(ctx, runner(), cfg, swapped, trusted); contract.CodeOf(err) != contract.VerifyFailed {
		t.Fatalf("managed turned off and the key swapped: %v", err)
	}
	reowned := swapped
	reowned.Owner = "me"
	if err := Check(ctx, runner(), cfg, reowned, trusted); contract.CodeOf(err) != contract.VerifyFailed {
		t.Fatalf("managed off, owner changed and the key swapped: %v", err)
	}
	// Only the flag flipped: the profile still matches its bundle. (A fresh
	// read: Checksums is a pointer the edits above shared.)
	flag, _, err := store.Get("acme-release")
	if err != nil {
		t.Fatal(err)
	}
	flag.Managed = false
	if err := Check(ctx, runner(), cfg, flag, trusted); err != nil {
		t.Fatalf("an unchanged profile with the flag off: %v", err)
	}
}

// Security review R5 (I-05): an older signed bundle cannot replace a newer one,
// so a profile cannot be rolled back to a key the owner has since replaced.
func TestBundleInstallRefusesAnOlderBundle(t *testing.T) {
	s := newSigner(t)
	ctx := context.Background()
	cfg := t.TempDir()
	store := profile.Store{Dir: cfg}
	trusted := []TrustedKey{{Owner: "acme", PublicKey: s.pub}}
	p := orgProfile(t, "acme-release", "acme")
	old := bundleJSON(t, "acme", p)
	var b Bundle
	if err := json.Unmarshal(old, &b); err != nil {
		t.Fatal(err)
	}
	b.IssuedAt = b.IssuedAt.Add(24 * time.Hour)
	newer, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Install(ctx, runner(), store, cfg, newer, s.sign(t, newer, Namespace), trusted); err != nil {
		t.Fatal(err)
	}
	_, _, err = Install(ctx, runner(), store, cfg, old, s.sign(t, old, Namespace), trusted)
	if contract.CodeOf(err) != contract.Usage || !strings.Contains(err.Error(), "older") {
		t.Fatalf("an older bundle over a newer one: %v", err)
	}
	// The same bundle again is fine.
	if _, _, err := Install(ctx, runner(), store, cfg, newer, s.sign(t, newer, Namespace), trusted); err != nil {
		t.Fatalf("reinstalling the same bundle: %v", err)
	}
}
