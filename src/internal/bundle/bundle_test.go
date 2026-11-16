package bundle

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/execx"
	"github.com/sangehq/imprimatur/src/internal/profile"
)

// signer is an ed25519 key made for this run, and the bundle it signs.
type signer struct {
	key, pub string
}

func newSigner(t *testing.T) signer {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("real ssh-keygen: not installed")
	}
	key := filepath.Join(t.TempDir(), "id")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}
	pub, err := os.ReadFile(key + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	f := strings.Fields(string(pub))
	return signer{key: key, pub: f[0] + " " + f[1]}
}

func (s signer) sign(t *testing.T, data []byte, ns string) []byte {
	t.Helper()
	cmd := exec.Command("ssh-keygen", "-Y", "sign", "-q", "-f", s.key, "-n", ns)
	cmd.Stdin = strings.NewReader(string(data))
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("ssh-keygen -Y sign: %v", err)
	}
	return out
}

func randHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func orgProfile(t *testing.T, name, owner string) profile.Profile {
	t.Helper()
	return profile.Profile{Name: name, Scope: profile.ScopeCompany, Owner: owner, Purpose: []profile.Purpose{profile.PurposeRelease}, AllowedRepos: []string{"github.com/acme/app"},
		Platforms: profile.Platforms{Checksums: &profile.ChecksumSpec{Kind: "ssh", KeyRef: "env://IMPR_TEST_KEY", Fingerprint: "SHA256:" + randHex(t, 16)}}}
}

func bundleJSON(t *testing.T, owner string, ps ...profile.Profile) []byte {
	t.Helper()
	b := Bundle{Schema: Schema, Owner: owner, IssuedAt: time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)}
	for _, p := range ps {
		raw, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		b.Profiles = append(b.Profiles, raw)
	}
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func runner() execx.Runner { return execx.OS{Timeout: time.Minute} }

func TestInstallVerifiesAndChecksManagedProfiles(t *testing.T) {
	s := newSigner(t)
	ctx := context.Background()
	cfg := t.TempDir()
	store := profile.Store{Dir: cfg}
	trusted := []TrustedKey{{Owner: "acme", PublicKey: s.pub}}
	p := orgProfile(t, "acme-release", "acme")
	data := bundleJSON(t, "acme", p)
	sig := s.sign(t, data, Namespace)

	b, names, err := Install(ctx, runner(), store, cfg, data, sig, trusted)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if b.Owner != "acme" || len(names) != 1 || names[0] != "acme-release" {
		t.Fatalf("installed %v %v", b.Owner, names)
	}
	got, ok, err := store.Get("acme-release")
	if err != nil || !ok || !got.Managed {
		t.Fatalf("the installed profile must be managed: %+v %v %v", got, ok, err)
	}
	if err := Check(ctx, runner(), cfg, got, trusted); err != nil {
		t.Fatalf("an untouched managed profile must pass: %v", err)
	}
	inst, err := Installed(cfg)
	if err != nil || len(inst["acme"]) != 1 {
		t.Fatalf("installed list: %v %v", inst, err)
	}

	// Edited by hand: the profile no longer matches its signed bundle.
	edited := got
	edited.Notes = "changed locally"
	if err := Check(ctx, runner(), cfg, edited, trusted); contract.CodeOf(err) != contract.VerifyFailed || !strings.Contains(err.Error(), "edited") {
		t.Fatalf("an edited managed profile must fail verification, got %v", err)
	}
	// The stored bundle tampered with: its signature no longer verifies.
	if err := os.WriteFile(filepath.Join(cfg, Dir, "acme.json"), bundleJSON(t, "acme", edited), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Check(ctx, runner(), cfg, edited, trusted); contract.CodeOf(err) != contract.VerifyFailed {
		t.Fatalf("a tampered bundle must fail verification, got %v", err)
	}
	// Unmanaged profiles are not this check's business.
	if err := Check(ctx, runner(), cfg, orgProfile(t, "mine", "me"), trusted); err != nil {
		t.Fatalf("an unmanaged profile must pass: %v", err)
	}
}

func TestInstallRefuses(t *testing.T) {
	s := newSigner(t)
	other := newSigner(t)
	ctx := context.Background()
	p := orgProfile(t, "acme-release", "acme")
	data := bundleJSON(t, "acme", p)
	good := s.sign(t, data, Namespace)
	trusted := []TrustedKey{{Owner: "acme", PublicKey: s.pub}}

	cases := []struct {
		name    string
		data    []byte
		sig     []byte
		trusted []TrustedKey
		code    contract.Code
		want    string
	}{
		{"no trusted key", data, good, nil, contract.VerifyFailed, "no key is trusted"},
		{"key trusted for another owner", data, good, []TrustedKey{{Owner: "other", PublicKey: s.pub}}, contract.VerifyFailed, "no key is trusted"},
		{"signed by an untrusted key", data, other.sign(t, data, Namespace), trusted, contract.VerifyFailed, "does not verify"},
		{"signed in another namespace", data, s.sign(t, data, "file"), trusted, contract.VerifyFailed, "does not verify"},
		{"data changed after signing", append([]byte(nil), bundleJSON(t, "acme", orgProfile(t, "acme-release", "acme"))...), good, trusted, contract.VerifyFailed, "does not verify"},
		{"profile owned by someone else", bundleJSON(t, "acme", orgProfile(t, "x", "evil")), nil, trusted, contract.Usage, "not the bundle's owner"},
		{"unknown field", []byte(`{"schema":"` + Schema + `","owner":"acme","profiles":[{}],"extra":1}`), good, trusted, contract.Usage, "not an"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := t.TempDir()
			sig := c.sig
			if sig == nil {
				sig = s.sign(t, c.data, Namespace)
			}
			_, _, err := Install(ctx, runner(), profile.Store{Dir: cfg}, cfg, c.data, sig, c.trusted)
			if contract.CodeOf(err) != c.code || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want %v %q, got %v", c.code, c.want, err)
			}
			if _, err := os.Stat(filepath.Join(cfg, Dir)); !os.IsNotExist(err) {
				t.Fatal("a refused bundle left files behind")
			}
		})
	}
}

func TestInstallNeverReplacesAPersonalProfile(t *testing.T) {
	s := newSigner(t)
	cfg := t.TempDir()
	store := profile.Store{Dir: cfg}
	mine := orgProfile(t, "acme-release", "acme")
	mine.Scope = profile.ScopePersonal
	if err := store.Save(mine, false); err != nil {
		t.Fatal(err)
	}
	data := bundleJSON(t, "acme", orgProfile(t, "acme-release", "acme"))
	_, _, err := Install(context.Background(), runner(), store, cfg, data, s.sign(t, data, Namespace), []TrustedKey{{Owner: "acme", PublicKey: s.pub}})
	if err == nil || !strings.Contains(err.Error(), "nothing was installed") {
		t.Fatalf("a personal profile of the same name must not be replaced, got %v", err)
	}
}

func TestValidKey(t *testing.T) {
	for k, want := range map[TrustedKey]bool{
		{Owner: "acme", PublicKey: "ssh-ed25519 AAAAC3Nza"}:           true,
		{Owner: "Acme", PublicKey: "ssh-ed25519 AAAAC3Nza"}:           false,
		{Owner: "acme", PublicKey: "ssh-ed25519 AAAAC3Nza comment"}:   false,
		{Owner: "acme", PublicKey: "ssh-dss AAAAB3Nza"}:               false,
		{Owner: "acme", PublicKey: "cert-authority ssh-ed25519 AAAA"}: false,
	} {
		if got := ValidKey(k) == ""; got != want {
			t.Errorf("ValidKey(%+v) ok=%v, want %v", k, got, want)
		}
	}
}
