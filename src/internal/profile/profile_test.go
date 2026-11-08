package profile

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// randHex returns n random bytes as upper-case hex: thumbprints and
// fingerprints are generated per run, never written down.
func randHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return strings.ToUpper(hex.EncodeToString(b))
}

func releaseProfile(t *testing.T) Profile {
	t.Helper()
	return Profile{
		Name: "acme-release", Scope: ScopeCompany, Owner: "acme", Purpose: []Purpose{PurposeRelease},
		AllowedRepos: []string{"github.com/acme/**"}, RequiresApproval: true,
		Platforms: Platforms{
			Windows: &WindowsSpec{Kind: "authenticode", Backend: BackendCertum, Subject: "CN=Acme Ltd", Thumbprint: randHex(t, 20)},
			MacOS: &MacOSSpec{Kind: "developer-id", TeamID: "ABCDE12345", Identity: "Developer ID Application: Acme Ltd (ABCDE12345)",
				Notary: &NotarySpec{APIKeyRef: "env://NOTARY_" + randHex(t, 3)}},
			Checksums: &ChecksumSpec{Kind: "gpg", KeyRef: "gpg-agent://" + randHex(t, 20), Fingerprint: randHex(t, 20)},
		},
	}
}

func codes(ps Problems) string {
	var out []string
	for _, p := range ps {
		out = append(out, p.Code)
	}
	return strings.Join(out, ",")
}

func TestValidateAcceptsACompleteReleaseProfile(t *testing.T) {
	if ps := releaseProfile(t).Validate(); len(ps) != 0 {
		t.Fatalf("problems: %v", ps.Strings())
	}
}

func TestValidateRefuses(t *testing.T) {
	cases := []struct {
		name string
		edit func(p *Profile)
		code string
	}{
		{"an inline credential", func(p *Profile) { p.Platforms.Windows.CertRef = "not-a-reference" }, "platforms.windows.certRef"},
		{"test and release together", func(p *Profile) { p.Purpose = []Purpose{PurposeRelease, PurposeTest} }, "profile.purpose"},
		{"a release profile with no repositories", func(p *Profile) { p.AllowedRepos = nil }, "profile.allowedRepos"},
		{"every repository", func(p *Profile) { p.AllowedRepos = []string{"**"} }, "profile.allowedRepos"},
		{"an unpinned Windows certificate", func(p *Profile) { p.Platforms.Windows.Thumbprint, p.Platforms.Windows.Subject = "", "" }, "platforms.windows.pin"},
		{"a short thumbprint", func(p *Profile) { p.Platforms.Windows.Thumbprint = "ABC" }, "platforms.windows.thumbprint"},
		{"a pfx with no file", func(p *Profile) { p.Platforms.Windows.Backend = BackendPFX }, "platforms.windows.certRef"},
		{"a team id missing from the identity", func(p *Profile) { p.Platforms.MacOS.Identity = "Developer ID Application: Acme" }, "platforms.macos.identity"},
		{"an unknown scope", func(p *Profile) { p.Scope = "everyone" }, "profile.scope"},
		{"a client scope for another owner", func(p *Profile) { p.Scope = "client:globex" }, "profile.owner"},
		{"no platform", func(p *Profile) { p.Platforms = Platforms{} }, "profile.platforms"},
		{"minisign without its public key", func(p *Profile) {
			p.Platforms.Checksums = &ChecksumSpec{Kind: "minisign", KeyRef: "env://K", Fingerprint: randHex(t, 8)}
		}, "platforms.checksums.publicKey"},
		{"keyless cosign without an issuer", func(p *Profile) {
			p.Platforms.Containers = &ContainerSpec{Kind: "cosign", Mode: "keyless", Identity: "release@acme.example"}
		}, "platforms.containers.identity"},
		{"attestations without their signer", func(p *Profile) {
			p.Platforms.Attestations = &AttestationSpec{Kind: "in-toto", Signer: "cosign"}
		}, "platforms.attestations.signer"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := releaseProfile(t)
			c.edit(&p)
			if got := codes(p.Validate()); !strings.Contains(got, c.code) {
				t.Fatalf("want %s, got %q", c.code, got)
			}
		})
	}
}

func TestDecodeRefusesSecretsAndUnknownFields(t *testing.T) {
	p := releaseProfile(t)
	b, _ := json.Marshal(p)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	m["platforms"].(map[string]any)["windows"].(map[string]any)["password"] = randHex(t, 8)
	bad, _ := json.Marshal(m)
	_, ps, err := Check(bad)
	if err != nil {
		t.Fatal(err)
	}
	if got := codes(ps); !strings.Contains(got, "profile.secret") || !strings.Contains(got, "profile.unknown") {
		t.Fatalf("want profile.secret and profile.unknown, got %q", got)
	}
	if _, ps, _ := Check(b); len(ps) != 0 {
		t.Fatalf("the clean profile has problems: %v", ps.Strings())
	}
}

// sangePinned is sange's domain/signing PinnedIdentity, field for field: the
// digest an approval binds is computed on sange's side from this shape.
type sangePinned struct {
	Profile      string   `json:"profile"`
	Scope        string   `json:"scope"`
	Owner        string   `json:"owner"`
	Purpose      []string `json:"purpose"`
	AllowedRepos []string `json:"allowedRepos,omitempty"`
	Windows      string   `json:"windows,omitempty"`
	MacOS        string   `json:"macos,omitempty"`
	Checksums    string   `json:"checksums,omitempty"`
	Containers   string   `json:"containers,omitempty"`
}

func TestPinnedIdentityDigestIsSanges(t *testing.T) {
	p := releaseProfile(t)
	id := p.Pinned()
	b, _ := json.Marshal(id)
	var theirs sangePinned
	if err := json.Unmarshal(b, &theirs); err != nil {
		t.Fatal(err)
	}
	tb, _ := json.Marshal(theirs)
	h := sha256.Sum256(tb)
	if want := "sha256:" + hex.EncodeToString(h[:]); id.Digest() != want {
		t.Fatalf("digest %s, sange computes %s", id.Digest(), want)
	}
	if id.MacOS != "team=ABCDE12345;identity=Developer ID Application: Acme Ltd (ABCDE12345)" || id.Owner != "acme" {
		t.Fatalf("shape: %+v", id)
	}
	before := id.Digest()
	p.Platforms.Windows.Thumbprint = randHex(t, 20)
	if p.Pinned().Digest() == before {
		t.Fatal("re-pinning the certificate did not change the identity digest")
	}
}

func TestAllowsRepo(t *testing.T) {
	p := releaseProfile(t)
	cases := map[string]bool{
		"git@github.com:acme/tool.git":       true,
		"https://github.com/acme/tool":       true,
		"ssh://git@github.com/ACME/tool.git": true,
		"https://github.com/acme/sub/tool":   true,
		"git@github.com:other/tool.git":      false,
		"https://gitlab.com/acme/tool":       false,
		"https://github.com/acme/../evil":    false,
		"":                                   false,
	}
	for url, want := range cases {
		if got := p.AllowsRepo(url); got != want {
			t.Errorf("%q: got %v, want %v", url, got, want)
		}
	}
	if (Profile{}).AllowsRepo("https://github.com/acme/tool") {
		t.Error("an empty allowedRepos allowed a repository")
	}
	for pat, want := range map[string]bool{"github.com/acme/tool": true, "github.com/acme/t?ol": true, "github.com/*/tool": true,
		"github.com": true, "github.com/acme/tools": false, "**": false} {
		if got := MatchRepo(pat, "github.com/acme/tool"); got != want {
			t.Errorf("pattern %q: got %v, want %v", pat, got, want)
		}
	}
}
