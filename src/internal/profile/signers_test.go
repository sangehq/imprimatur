package profile

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func day(d int) *time.Time {
	t := time.Date(2026, 1, d, 0, 0, 0, 0, time.UTC)
	return &t
}

func multi(signers ...WindowsSigner) Profile {
	return Profile{Name: "acme", Scope: ScopeCompany, Owner: "acme", Purpose: []Purpose{PurposeInternal},
		Platforms: Platforms{Windows: &WindowsSpec{Kind: "authenticode", Signers: signers}}}
}

const thumbA, thumbB = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

func TestSignerValidation(t *testing.T) {
	ok := multi(WindowsSigner{ID: "x64", Backend: BackendCertStore, Thumbprint: thumbA, Select: &Selector{Arch: []string{"amd64"}}},
		WindowsSigner{ID: "arm", Backend: BackendCertStore, Thumbprint: thumbB, Select: &Selector{Arch: []string{"arm64"}}})
	if ps := ok.Validate(); len(ps) > 0 {
		t.Fatalf("a valid multi-certificate profile: %v", ps)
	}
	bad := map[string]func(p *Profile){
		"top-level pin beside signers": func(p *Profile) { p.Platforms.Windows.Thumbprint = thumbA },
		"dual signing":                 func(p *Profile) { p.Platforms.Windows.Mode = "all" },
		"duplicate id":                 func(p *Profile) { p.Platforms.Windows.Signers[1].ID = "x64" },
		"unpinned signer":              func(p *Profile) { p.Platforms.Windows.Signers[0].Thumbprint = "" },
		"unknown arch":                 func(p *Profile) { p.Platforms.Windows.Signers[0].Select.Arch = []string{"x86_64"} },
		"bad glob":                     func(p *Profile) { p.Platforms.Windows.Signers[0].Select.Glob = []string{"["} },
		"dates reversed": func(p *Profile) {
			p.Platforms.Windows.Signers[0].NotBefore, p.Platforms.Windows.Signers[0].NotAfter = day(9), day(2)
		},
		"pfx without certRef": func(p *Profile) { p.Platforms.Windows.Signers[0].Backend = BackendPFX },
	}
	for name, mutate := range bad {
		p := multi(WindowsSigner{ID: "x64", Backend: BackendCertStore, Thumbprint: thumbA, Select: &Selector{Arch: []string{"amd64"}}},
			WindowsSigner{ID: "arm", Backend: BackendCertStore, Thumbprint: thumbB, Select: &Selector{Arch: []string{"arm64"}}})
		mutate(&p)
		if len(p.Validate()) == 0 {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestChoose(t *testing.T) {
	now := *day(15)
	byArch := multi(WindowsSigner{ID: "x64", Backend: BackendCertStore, Thumbprint: thumbA, Select: &Selector{Arch: []string{"amd64"}}},
		WindowsSigner{ID: "arm", Backend: BackendCertStore, Thumbprint: thumbB, Select: &Selector{Arch: []string{"arm64"}}}).WindowsVariants()
	if v, err := Choose(byArch, "build/windows/t_arm64.exe", "arm64", now); err != nil || v.ID != "arm" || v.Profile.Platforms.Windows.Thumbprint != thumbB {
		t.Fatalf("arm64: %+v %v", v.ID, err)
	}
	if _, err := Choose(byArch, "build/windows/t_386.exe", "386", now); err == nil {
		t.Fatal("a file no signer covers was given one")
	}
	both := multi(WindowsSigner{ID: "a", Backend: BackendCertStore, Thumbprint: thumbA},
		WindowsSigner{ID: "b", Backend: BackendCertStore, Thumbprint: thumbB}).WindowsVariants()
	if _, err := Choose(both, "t.exe", "amd64", now); err == nil || !strings.Contains(err.Error(), "several signers") {
		t.Fatalf("ambiguity must fail, never first match: %v", err)
	}
	// A rotation: both match, both dated; the newer certificate signs, and an
	// expired one is never chosen.
	rot := multi(WindowsSigner{ID: "old", Backend: BackendCertStore, Thumbprint: thumbA, NotBefore: day(1), NotAfter: day(20)},
		WindowsSigner{ID: "new", Backend: BackendCertStore, Thumbprint: thumbB, NotBefore: day(10)}).WindowsVariants()
	if v, err := Choose(rot, "t.exe", "amd64", now); err != nil || v.ID != "new" {
		t.Fatalf("rotation: %s %v", v.ID, err)
	}
	if v, err := Choose(rot, "t.exe", "amd64", *day(5)); err != nil || v.ID != "old" {
		t.Fatalf("before the new one starts: %s %v", v.ID, err)
	}
	expired := multi(WindowsSigner{ID: "old", Backend: BackendCertStore, Thumbprint: thumbA, NotAfter: day(10)}).WindowsVariants()
	if _, err := Choose(expired, "t.exe", "amd64", now); err == nil {
		t.Fatal("an expired signer was chosen")
	}
	if !(&Selector{Glob: []string{"*.msi"}}).Matches("build/windows/setup.msi", "") || (&Selector{Glob: []string{"*.msi"}}).Matches("a.exe", "amd64") {
		t.Fatal("glob selector")
	}
}

// A single-certificate profile's pinned identity, which sange computes too,
// must not change because signers exist; a multi-certificate one pins every
// signer and changes when any of them does.
func TestPinnedIdentityWithSigners(t *testing.T) {
	single := Profile{Name: "s", Scope: ScopePersonal, Owner: "me", Purpose: []Purpose{PurposeInternal},
		Platforms: Platforms{Windows: &WindowsSpec{Kind: "authenticode", Backend: BackendCertStore, Thumbprint: thumbA}}}
	if got := single.Pinned().Windows; got != "thumbprint="+thumbA+";subject=" {
		t.Fatalf("single-certificate pin changed: %s", got)
	}
	m := multi(WindowsSigner{ID: "b", Backend: BackendCertStore, Thumbprint: thumbB}, WindowsSigner{ID: "a", Backend: BackendCertStore, Thumbprint: thumbA})
	if got := m.Pinned().Windows; got != "id=a;thumbprint="+thumbA+";subject=|id=b;thumbprint="+thumbB+";subject=" {
		t.Fatalf("multi pin: %s", got)
	}
	d1 := m.Pinned().Digest()
	m.Platforms.Windows.Signers[0].Thumbprint = strings.Repeat("C", 40)
	if m.Pinned().Digest() == d1 {
		t.Fatal("re-pinning one signer did not change the identity digest")
	}
}

// TestMultiSignerDigestGolden pins the multi-signer identity bytes and digest
// for sange's domain/signing to mirror. The entries are sorted as whole
// strings, so "id=a-b;…" comes before "id=a;…" (- is 0x2D, ; is 0x3B), a
// signer's subject is kept verbatim (empty included), and thumbprints are
// upper-cased.
func TestMultiSignerDigestGolden(t *testing.T) {
	p := Profile{Name: "acme-release", Scope: ScopeCompany, Owner: "Acme", Purpose: []Purpose{PurposeRelease},
		AllowedRepos: []string{"github.com/acme/**"},
		Platforms: Platforms{Windows: &WindowsSpec{Kind: "authenticode", Signers: []WindowsSigner{
			{ID: "a-b", Backend: BackendCertStore, Thumbprint: "0123456789abcdef0123456789abcdef01234567", Subject: "CN=Acme Ltd"},
			{ID: "a", Backend: BackendCertum, Thumbprint: "89abcdef0123456789abcdef0123456789abcdef"},
		}}}}
	b, _ := json.Marshal(p.Pinned())
	const wantJSON = `{"profile":"acme-release","scope":"company","owner":"acme","purpose":["release"],"allowedRepos":["github.com/acme/**"],"windows":"id=a-b;thumbprint=0123456789ABCDEF0123456789ABCDEF01234567;subject=CN=Acme Ltd|id=a;thumbprint=89ABCDEF0123456789ABCDEF0123456789ABCDEF;subject="}`
	if string(b) != wantJSON {
		t.Fatalf("identity JSON\n got %s\nwant %s", b, wantJSON)
	}
	if got := p.Pinned().Digest(); got != "sha256:bc9a45a250fb6c8831abecc12efe58f669bb0c919c8d75f36f638284382571c9" {
		t.Fatalf("digest %s", got)
	}
}
