// Package bundle installs and checks signed profile bundles: how an
// organisation hands its managed signing profiles to its people (design §3,
// audit N-B17). A bundle is imprimatur.profile-bundle/v1 JSON with a detached
// SSH signature (ssh-keygen -Y sign -n imprimatur-bundle). It installs only
// when that signature verifies against a key the configuration trusts for the
// bundle's owner, and a managed profile is checked against its bundle every
// time it signs or verifies, so editing it by hand cannot pass for managed.
package bundle

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/execx"
	"github.com/sangehq/imprimatur/src/internal/profile"
)

// Schema identifies a bundle.
const Schema = "imprimatur.profile-bundle/v1"

// Namespace is the ssh-keygen -Y namespace bundles are signed in.
const Namespace = "imprimatur-bundle"

// Dir is where installed bundles are kept, under the config dir.
const Dir = "bundles"

// Bundle is one organisation's profiles.
type Bundle struct {
	Schema   string            `json:"schema"`
	Owner    string            `json:"owner"`
	IssuedAt time.Time         `json:"issuedAt"`
	Profiles []json.RawMessage `json:"profiles"`
}

// TrustedKey is a public key allowed to sign one owner's bundles.
type TrustedKey struct {
	Owner     string `json:"owner"`
	PublicKey string `json:"publicKey"` // "ssh-ed25519 AAAA…"
}

var (
	ownerRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	keyRe   = regexp.MustCompile(`^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com) [A-Za-z0-9+/=]+$`)
)

// ValidPublicKey reports whether v is one SSH public key line with no
// comment. Approver keys use the same rule.
func ValidPublicKey(v string) bool { return keyRe.MatchString(strings.TrimSpace(v)) }

// ValidKey reports what is wrong with a trusted key, or "".
func ValidKey(k TrustedKey) string {
	if !ownerRe.MatchString(k.Owner) {
		return "owner must be lower-case letters, digits, . _ -"
	}
	if !ValidPublicKey(k.PublicKey) {
		return "publicKey must be an SSH public key line (ssh-ed25519 AAAA…), without a comment"
	}
	return ""
}

// Verify decodes a bundle strictly and checks its signature against the keys
// trusted for its owner.
func Verify(ctx context.Context, r execx.Runner, data, sig []byte, trusted []TrustedKey) (Bundle, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var b Bundle
	if err := dec.Decode(&b); err != nil || dec.More() {
		return Bundle{}, contract.New(contract.Usage, "not an %s document", Schema)
	}
	if b.Schema != Schema || !ownerRe.MatchString(b.Owner) || len(b.Profiles) == 0 {
		return Bundle{}, contract.New(contract.Usage, "the bundle needs schema %s, an owner and at least one profile", Schema)
	}
	var lines []string
	for _, k := range trusted {
		if k.Owner == b.Owner && ValidKey(k) == "" {
			lines = append(lines, b.Owner+` namespaces="`+Namespace+`" `+strings.TrimSpace(k.PublicKey))
		}
	}
	if len(lines) == 0 {
		return Bundle{}, contract.New(contract.VerifyFailed, "no key is trusted for %s's bundles", b.Owner).
			WithFix("an administrator adds it: bundles.trustedKeys in the system config.json")
	}
	dir, err := os.MkdirTemp("", "impr-bundle-")
	if err != nil {
		return Bundle{}, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	allowed := filepath.Join(dir, "allowed_signers")
	sigPath := filepath.Join(dir, "bundle.sig")
	if err := os.WriteFile(allowed, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		return Bundle{}, err
	}
	if err := os.WriteFile(sigPath, sig, 0o600); err != nil { //nolint:gosec // G703: a fixed name in a fresh temporary directory
		return Bundle{}, err
	}
	res, err := r.Run(ctx, execx.Cmd{Tool: "ssh-keygen", Args: []string{"-Y", "verify", "-f", allowed, "-I", b.Owner, "-n", Namespace, "-s", sigPath}, Stdin: data})
	if err != nil {
		return Bundle{}, contract.Wrap(contract.Unavailable, err, "ssh-keygen could not run")
	}
	if res.ExitCode != 0 {
		return Bundle{}, contract.New(contract.VerifyFailed, "the bundle's signature does not verify against the keys trusted for %s", b.Owner)
	}
	return b, nil
}

// Decode decodes and validates a verified bundle's profiles: each must be
// valid and owned by the bundle's owner, and comes back marked managed.
func (b Bundle) Decode() ([]profile.Profile, error) {
	var out []profile.Profile
	for i, raw := range b.Profiles {
		p, ps, err := profile.Check(raw)
		if err != nil {
			return nil, contract.Wrap(contract.Usage, err, "bundle profile %d", i)
		}
		if len(ps) > 0 {
			return nil, contract.New(contract.Usage, "bundle profile %s is not valid", p.Name).WithDetails(ps.Strings()...)
		}
		if !strings.EqualFold(p.Owner, b.Owner) {
			return nil, contract.New(contract.Usage, "bundle profile %s belongs to %s, not the bundle's owner %s", p.Name, p.Owner, b.Owner)
		}
		p.Managed, p.Schema = true, profile.Schema
		out = append(out, p)
	}
	return out, nil
}

// Install verifies a bundle, writes its profiles as managed, and keeps the
// bundle and its signature under <config>/bundles/ for later checks. A
// profile of the same name that is not managed by this owner is never
// replaced.
func Install(ctx context.Context, r execx.Runner, s profile.Store, configDir string, data, sig []byte, trusted []TrustedKey) (Bundle, []string, error) {
	b, err := Verify(ctx, r, data, sig, trusted)
	if err != nil {
		return Bundle{}, nil, err
	}
	ps, err := b.Decode()
	if err != nil {
		return Bundle{}, nil, err
	}
	for _, p := range ps {
		if old, ok, _ := s.Get(p.Name); ok && (!old.Managed || !strings.EqualFold(old.Owner, b.Owner)) {
			return Bundle{}, nil, contract.New(contract.Usage, "a profile named %s exists and is not %s's managed profile; nothing was installed", p.Name, b.Owner)
		}
	}
	dir := filepath.Join(configDir, Dir)
	// A bundle older than the one installed would roll the owner's profiles
	// back, to a key since replaced say (security review R5).
	if cur, err := os.ReadFile(filepath.Join(dir, b.Owner+".json")); err == nil { //nolint:gosec // G304: impr's own bundle copy
		var installed Bundle
		if json.Unmarshal(cur, &installed) == nil && b.IssuedAt.Before(installed.IssuedAt) {
			return Bundle{}, nil, contract.New(contract.Usage, "this %s bundle (issued %s) is older than the one installed (issued %s); nothing was installed",
				b.Owner, b.IssuedAt.UTC().Format(time.RFC3339), installed.IssuedAt.UTC().Format(time.RFC3339)).
				WithFix("ask " + b.Owner + "'s signing administrator for the current bundle")
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Bundle{}, nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, b.Owner+".json"), data, 0o600); err != nil {
		return Bundle{}, nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, b.Owner+".json.sig"), sig, 0o600); err != nil {
		return Bundle{}, nil, err
	}
	var names []string
	for _, p := range ps {
		if err := s.WriteUnchecked(p); err != nil {
			return Bundle{}, nil, err
		}
		names = append(names, p.Name)
	}
	return b, names, nil
}

// Check confirms a managed profile is exactly what its owner's installed,
// signed bundle says. A profile an installed bundle names is managed whatever
// its file says, so clearing "managed" or changing the owner by hand does not
// skip the check (security review R5). Any other profile passes.
func Check(ctx context.Context, r execx.Runner, configDir string, p profile.Profile, trusted []TrustedKey) error {
	owner := strings.ToLower(p.Owner)
	inst, err := Installed(configDir)
	if err != nil {
		return contract.Wrap(contract.VerifyFailed, err, "cannot read the installed bundles")
	}
	named := false
	for o, names := range inst {
		if slices.Contains(names, p.Name) {
			owner, named = o, true
			break
		}
	}
	if !p.Managed && !named {
		return nil
	}
	dir := filepath.Join(configDir, Dir)
	data, err := os.ReadFile(filepath.Join(dir, owner+".json")) //nolint:gosec // G304: impr's own bundle copy
	if err != nil {
		return contract.New(contract.VerifyFailed, "managed profile %s has no installed bundle from %s", p.Name, owner).
			WithFix("impr profile bundle install BUNDLE.json")
	}
	sig, err := os.ReadFile(filepath.Join(dir, owner+".json.sig")) //nolint:gosec // G304: impr's own bundle copy
	if err != nil {
		return contract.New(contract.VerifyFailed, "the %s bundle has no signature", owner)
	}
	b, err := Verify(ctx, r, data, sig, trusted)
	if err != nil {
		return err
	}
	ps, err := b.Decode()
	if err != nil {
		return err
	}
	for _, bp := range ps {
		if bp.Name != p.Name {
			continue
		}
		want, _ := json.Marshal(bp)
		q := p
		q.Schema, q.Managed = profile.Schema, true
		got, _ := json.Marshal(q)
		if !bytes.Equal(want, got) {
			return contract.New(contract.VerifyFailed, "managed profile %s differs from %s's signed bundle; it was edited", p.Name, owner).
				WithFix("impr profile bundle install BUNDLE.json (reinstall the signed version)")
		}
		return nil
	}
	return contract.New(contract.VerifyFailed, "managed profile %s is not in %s's signed bundle", p.Name, owner)
}

// Installed lists installed bundles: owner -> profile names.
func Installed(configDir string) (map[string][]string, error) {
	out := map[string][]string{}
	m, err := filepath.Glob(filepath.Join(configDir, Dir, "*.json"))
	if err != nil {
		return nil, err
	}
	for _, f := range m {
		data, err := os.ReadFile(f) //nolint:gosec // G304: impr's own bundle copy
		if err != nil {
			return nil, err
		}
		var b Bundle
		if json.Unmarshal(data, &b) != nil {
			continue
		}
		for _, raw := range b.Profiles {
			var p struct {
				Name string `json:"name"`
			}
			_ = json.Unmarshal(raw, &p)
			out[b.Owner] = append(out[b.Owner], p.Name)
		}
	}
	return out, nil
}

// String names a bundle for messages.
func (b Bundle) String() string {
	return fmt.Sprintf("%s bundle (%d profiles)", b.Owner, len(b.Profiles))
}
