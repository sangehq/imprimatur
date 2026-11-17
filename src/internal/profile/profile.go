// Package profile is the signing-profile domain (companion-imprimatur.md
// §9.1): named, scoped bundles of everything needed to sign and verify for one
// identity. A profile holds no secret: every credential is a reference
// (secret://, env://, keychain://, cert-store://, gpg-agent://) resolved only
// when signing. Each platform pins what verification must find, so "signed by
// someone" never passes.
//
// The JSON shape and the validation rules are the ones sange's
// domain/signing package reads (imprimatur.signing-profile/v1), with a few
// additive, optional fields imprimatur needs to run its backends.
package profile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

// Schema identifies the profile format.
const Schema = "imprimatur.signing-profile/v1"

// Scope is who a profile belongs to: personal, company, team, project or
// client:<name>.
type Scope string

// Scopes.
const (
	ScopePersonal Scope = "personal"
	ScopeCompany  Scope = "company"
	ScopeTeam     Scope = "team"
	ScopeProject  Scope = "project"
	scopeClient         = "client:"
)

// Client returns the client name of a client:<name> scope.
func (s Scope) Client() (string, bool) {
	name, ok := strings.CutPrefix(string(s), scopeClient)
	return name, ok && name != ""
}

// Valid reports whether s is a known scope.
func (s Scope) Valid() bool {
	if _, ok := s.Client(); ok {
		return true
	}
	return s == ScopePersonal || s == ScopeCompany || s == ScopeTeam || s == ScopeProject
}

// Purpose is what a profile may sign.
type Purpose string

// Purposes.
const (
	PurposeRelease  Purpose = "release"
	PurposeTest     Purpose = "test"
	PurposeInternal Purpose = "internal"
)

// Valid reports whether p is known.
func (p Purpose) Valid() bool { return p == PurposeRelease || p == PurposeTest || p == PurposeInternal }

// Platform kinds.
const (
	Windows      = "windows"
	MacOS        = "macos"
	Checksums    = "checksums"
	Containers   = "containers"
	Attestations = "attestations"
)

// AllPlatforms lists every platform kind in a fixed order.
func AllPlatforms() []string { return []string{Windows, MacOS, Checksums, Containers, Attestations} }

// Windows backends.
const (
	BackendAzure     = "azure-artifact-signing"
	BackendCertum    = "certum"
	BackendPFX       = "pfx"
	BackendCertStore = "cert-store"
)

// WindowsBackends lists the Authenticode backends.
func WindowsBackends() []string {
	return []string{BackendAzure, BackendCertum, BackendPFX, BackendCertStore}
}

// Profile is one signing profile.
type Profile struct {
	Schema           string    `json:"schema,omitempty"`
	Name             string    `json:"name"`
	Scope            Scope     `json:"scope"`
	Owner            string    `json:"owner"`
	Purpose          []Purpose `json:"purpose"`
	Platforms        Platforms `json:"platforms"`
	AllowedRepos     []string  `json:"allowedRepos,omitempty"`
	RequiresApproval bool      `json:"requiresApproval,omitempty"`
	// Approval is how a run with requiresApproval is approved: "signed" (the
	// default) by approvers' SSH-signed approvals, or "confirm", typed at a
	// terminal by the person signing.
	Approval string `json:"approval,omitempty"`
	// Managed marks a profile distributed by an organisation; read-only here.
	Managed bool   `json:"managed,omitempty"`
	Notes   string `json:"notes,omitempty"`
}

// Approval modes for a profile with requiresApproval.
const (
	ApprovalSigned  = "signed"
	ApprovalConfirm = "confirm"
)

// ApprovalMode is how a run of this profile is approved: "" when it needs
// none, else signed (the default) or confirm.
func (p Profile) ApprovalMode() string {
	switch {
	case !p.RequiresApproval:
		return ""
	case p.Approval == ApprovalConfirm:
		return ApprovalConfirm
	}
	return ApprovalSigned
}

// Platforms are the per-platform specs.
type Platforms struct {
	Windows      *WindowsSpec     `json:"windows,omitempty"`
	MacOS        *MacOSSpec       `json:"macos,omitempty"`
	Checksums    *ChecksumSpec    `json:"checksums,omitempty"`
	Containers   *ContainerSpec   `json:"containers,omitempty"`
	Attestations *AttestationSpec `json:"attestations,omitempty"`
}

// Names lists the platforms present, in AllPlatforms order.
func (p Platforms) Names() []string {
	var out []string
	if p.Windows != nil {
		out = append(out, Windows)
	}
	if p.MacOS != nil {
		out = append(out, MacOS)
	}
	if p.Checksums != nil {
		out = append(out, Checksums)
	}
	if p.Containers != nil {
		out = append(out, Containers)
	}
	if p.Attestations != nil {
		out = append(out, Attestations)
	}
	return out
}

// Has reports whether the platform is present.
func (p Platforms) Has(name string) bool { return slices.Contains(p.Names(), name) }

// WindowsSpec is Authenticode signing.
type WindowsSpec struct {
	Kind       string `json:"kind"`    // authenticode
	Backend    string `json:"backend"` // azure-artifact-signing | certum | pfx | cert-store
	CertRef    string `json:"certRef,omitempty"`
	Subject    string `json:"subject,omitempty"`    // pinned: exact certificate subject
	Thumbprint string `json:"thumbprint,omitempty"` // pinned: SHA-1 thumbprint
	Timestamp  string `json:"timestamp,omitempty"`
	// DlibPath and MetadataPath locate Azure Artifact Signing's client.
	DlibPath     string `json:"dlibPath,omitempty"`
	MetadataPath string `json:"metadataPath,omitempty"`
	// PasswordRef is the .pfx password (pfx backend), as a reference.
	PasswordRef string `json:"passwordRef,omitempty"`
	// NotAfter is a declared expiry, for certificates this host cannot read.
	NotAfter *time.Time `json:"notAfter,omitempty"`
	// Signers lists several certificates (design ID-07). When present, the
	// fields above that name a certificate stay empty and each file is signed
	// by exactly one signer its selector matches; see Variants and Choose.
	Signers []WindowsSigner `json:"signers,omitempty"`
	// Mode is "select" (the default): one signer per file. "all" (dual
	// signing) is reserved and refused until the backends append signatures.
	Mode string `json:"mode,omitempty"`
}

// WindowsSigner is one certificate of a multi-certificate Windows spec.
type WindowsSigner struct {
	ID           string     `json:"id"`
	Backend      string     `json:"backend"`
	CertRef      string     `json:"certRef,omitempty"`
	Subject      string     `json:"subject,omitempty"`
	Thumbprint   string     `json:"thumbprint,omitempty"`
	Timestamp    string     `json:"timestamp,omitempty"`
	DlibPath     string     `json:"dlibPath,omitempty"`
	MetadataPath string     `json:"metadataPath,omitempty"`
	PasswordRef  string     `json:"passwordRef,omitempty"`
	NotBefore    *time.Time `json:"notBefore,omitempty"`
	NotAfter     *time.Time `json:"notAfter,omitempty"`
	Select       *Selector  `json:"select,omitempty"`
}

// Selector picks the files a signer signs. An empty selector matches every
// file; each list that is set must match.
type Selector struct {
	Arch []string `json:"arch,omitempty"` // PE machine: 386, amd64, arm, arm64
	Glob []string `json:"glob,omitempty"` // matched against the base name and the manifest path
}

// MacOSSpec is Developer ID signing and notarisation.
type MacOSSpec struct {
	Kind     string `json:"kind"`     // developer-id
	TeamID   string `json:"teamId"`   // pinned
	Identity string `json:"identity"` // pinned
	// CertRef holds a .p12 (path or base64) imported into a temporary
	// keychain for one run; empty means the identity is in a keychain.
	CertRef string `json:"certRef,omitempty"`
	// PasswordRef is the .p12's password, as a reference.
	PasswordRef string      `json:"passwordRef,omitempty"`
	Notary      *NotarySpec `json:"notary,omitempty"`
	// Entitlements is a plist path, relative to the signing root.
	Entitlements string     `json:"entitlements,omitempty"`
	NotAfter     *time.Time `json:"notAfter,omitempty"`
}

// NotarySpec is the App Store Connect API key notarytool uses. KeyID and
// Issuer may be literal identifiers or env:// references.
type NotarySpec struct {
	APIKeyRef string `json:"apiKeyRef"`
	Issuer    string `json:"issuer,omitempty"`
	KeyID     string `json:"keyId,omitempty"`
}

// ChecksumSpec signs the checksum file.
type ChecksumSpec struct {
	Kind        string `json:"kind"` // gpg | minisign | ssh
	KeyRef      string `json:"keyRef"`
	Fingerprint string `json:"fingerprint"` // pinned
	// PublicKey is the minisign public key (base64 line); public, not secret.
	PublicKey string `json:"publicKey,omitempty"`
	// Namespace is the ssh-keygen -Y namespace; "file" when empty.
	Namespace string     `json:"namespace,omitempty"`
	NotAfter  *time.Time `json:"notAfter,omitempty"`
	// PasswordRef is the passphrase of a gpg key held in a secret (keyRef
	// secret:// or env://) rather than by gpg-agent.
	PasswordRef string `json:"passwordRef,omitempty"`
}

// ContainerSpec is cosign.
type ContainerSpec struct {
	Kind           string `json:"kind"` // cosign
	Mode           string `json:"mode"` // key | keyless
	KeyRef         string `json:"keyRef,omitempty"`
	KeyFingerprint string `json:"keyFingerprint,omitempty"` // pinned in key mode: sha256 of the public key's DER
	Identity       string `json:"identity,omitempty"`       // pinned in keyless mode
	Issuer         string `json:"issuer,omitempty"`         // pinned in keyless mode
	// PublicKey is the PEM public key file (key mode), used to verify.
	PublicKey   string `json:"publicKey,omitempty"`
	PasswordRef string `json:"passwordRef,omitempty"`
}

// AttestationSpec names who signs in-toto attestations.
type AttestationSpec struct {
	Kind   string `json:"kind"`   // in-toto
	Signer string `json:"signer"` // checksums | cosign
}

// RefSchemes are the reference schemes a profile may use for a credential.
var RefSchemes = []string{"secret://", "env://", "keychain://", "cert-store://", "gpg-agent://", "file://"}

// IsRef reports whether v is a credential reference rather than a value.
func IsRef(v string) bool {
	for _, s := range RefSchemes {
		if strings.HasPrefix(v, s) && len(v) > len(s) {
			return true
		}
	}
	return false
}

var (
	nameRe       = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	thumbprintRe = regexp.MustCompile(`^[0-9A-Fa-f]{40}$`)
	teamIDRe     = regexp.MustCompile(`^[A-Z0-9]{10}$`)
	fprRe        = regexp.MustCompile(`^[0-9A-Fa-f]{16,64}$|^SHA256:[A-Za-z0-9+/=]{20,}$`)
	secretRe     = regexp.MustCompile(`BEGIN [A-Z ]*PRIVATE KEY|"(password|privateKey|pfxPassword|p12)"\s*:`)
)

// ValidName reports whether name is a well-formed profile name.
func ValidName(name string) bool { return nameRe.MatchString(name) }

// Problem is one reason a profile is invalid.
type Problem struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

func (p Problem) String() string { return p.Code + ": " + p.Detail }

// Problems is a list of problems.
type Problems []Problem

func (ps *Problems) add(code, format string, args ...any) {
	*ps = append(*ps, Problem{Code: code, Detail: fmt.Sprintf(format, args...)})
}

// Strings renders the problems.
func (ps Problems) Strings() []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.String())
	}
	return out
}

// HasPurpose reports whether the profile may sign for pu.
func (p Profile) HasPurpose(pu Purpose) bool { return slices.Contains(p.Purpose, pu) }

// Validate checks the profile's shape: a known scope and purposes, never test
// and release together, a release profile naming its repositories, at least
// one platform, credentials as references only, and a pinned identity for
// every platform. It never resolves a reference.
func (p Profile) Validate() Problems {
	var ps Problems
	if !nameRe.MatchString(p.Name) {
		ps.add("profile.name", "%q is not a profile name (lower-case letters, digits, . _ -; up to 64)", p.Name)
	}
	if !p.Scope.Valid() {
		ps.add("profile.scope", "%q is not a scope (personal, company, team, project or client:<name>)", p.Scope)
	}
	if strings.TrimSpace(p.Owner) == "" {
		ps.add("profile.owner", "a profile names its owner")
	}
	if c, ok := p.Scope.Client(); ok && !strings.EqualFold(c, p.Owner) {
		ps.add("profile.owner", "scope client:%s needs owner %q, not %q", c, c, p.Owner)
	}
	if len(p.Purpose) == 0 {
		ps.add("profile.purpose", "a profile names at least one purpose (release, test, internal)")
	}
	switch {
	case p.Approval != "" && !p.RequiresApproval:
		ps.add("profile.approval", "approval is set but requiresApproval is not; set requiresApproval=true or remove approval")
	case p.Approval != "" && p.Approval != ApprovalSigned && p.Approval != ApprovalConfirm:
		ps.add("profile.approval", "%q is not signed or confirm", p.Approval)
	}
	seen := map[Purpose]bool{}
	for _, pu := range p.Purpose {
		if !pu.Valid() {
			ps.add("profile.purpose", "%q is not a purpose", pu)
		}
		if seen[pu] {
			ps.add("profile.purpose", "%q is listed twice", pu)
		}
		seen[pu] = true
	}
	if seen[PurposeTest] && seen[PurposeRelease] {
		ps.add("profile.purpose", "a profile is either for tests or for releases, never both: test certificates must stay out of shipped artifacts")
	}
	if seen[PurposeRelease] && len(p.AllowedRepos) == 0 {
		ps.add("profile.allowedRepos", "a release profile lists the repositories it may sign (allowedRepos)")
	}
	for _, r := range p.AllowedRepos {
		if !repoPatternNarrow(r) {
			ps.add("profile.allowedRepos", "%q is too broad: name the host and owner literally (host/owner/**), as in github.com/acme/**", r)
		}
	}
	if len(p.Platforms.Names()) == 0 {
		ps.add("profile.platforms", "a profile configures at least one platform")
	}
	ref := func(field, v string, required bool) {
		switch {
		case v == "" && required:
			ps.add(field, "missing (a credential reference such as secret://...)")
		case v != "" && !IsRef(v):
			ps.add(field, "must be a reference (%s), never the credential itself", strings.Join(RefSchemes, ", "))
		}
	}
	if w := p.Platforms.Windows; w != nil && len(w.Signers) > 0 {
		if w.Kind != "authenticode" {
			ps.add("platforms.windows.kind", "%q is not authenticode", w.Kind)
		}
		ps = append(ps, w.validateSigners(ref)...)
	} else if w != nil {
		if w.Kind != "authenticode" {
			ps.add("platforms.windows.kind", "%q is not authenticode", w.Kind)
		}
		if w.Mode != "" && w.Mode != "select" {
			ps.add("platforms.windows.mode", "mode %q needs signers", w.Mode)
		}
		if !slices.Contains(WindowsBackends(), w.Backend) {
			ps.add("platforms.windows.backend", "%q is not %s", w.Backend, strings.Join(WindowsBackends(), ", "))
		}
		ref("platforms.windows.certRef", w.CertRef, w.Backend == BackendPFX)
		ref("platforms.windows.passwordRef", w.PasswordRef, false)
		ps = append(ps, azurePaths("platforms.windows", w.Backend, w.DlibPath, w.MetadataPath)...)
		if w.Thumbprint == "" && w.Subject == "" {
			ps.add("platforms.windows.pin", "pin the certificate by thumbprint or exact subject")
		}
		if (w.Backend == BackendCertStore || w.Backend == BackendCertum) && w.Thumbprint == "" {
			// Signing refuses these without a thumbprint (signtool /n would take
			// any matching certificate), so validation says so too (audit N-B7).
			ps.add("platforms.windows.thumbprint", "a %s certificate is pinned by its SHA-1 thumbprint; a subject alone is ambiguous", w.Backend)
		}
		if w.Thumbprint != "" && !thumbprintRe.MatchString(w.Thumbprint) {
			ps.add("platforms.windows.thumbprint", "%q is not a 40-hex SHA-1 thumbprint", w.Thumbprint)
		}
	}
	if m := p.Platforms.MacOS; m != nil {
		if m.Kind != "developer-id" {
			ps.add("platforms.macos.kind", "%q is not developer-id", m.Kind)
		}
		if !teamIDRe.MatchString(m.TeamID) {
			ps.add("platforms.macos.teamId", "%q is not a 10-character Apple team ID", m.TeamID)
		}
		if m.Identity == "" || (m.TeamID != "" && !strings.Contains(m.Identity, "("+m.TeamID+")")) {
			ps.add("platforms.macos.identity", "pin the exact signing identity, which names the team ID in parentheses")
		}
		ref("platforms.macos.certRef", m.CertRef, false)
		ref("platforms.macos.passwordRef", m.PasswordRef, false)
		if m.Notary != nil {
			ref("platforms.macos.notary.apiKeyRef", m.Notary.APIKeyRef, true)
		}
	}
	if c := p.Platforms.Checksums; c != nil {
		if !slices.Contains([]string{"gpg", "minisign", "ssh"}, c.Kind) {
			ps.add("platforms.checksums.kind", "%q is not gpg, minisign or ssh", c.Kind)
		}
		ref("platforms.checksums.keyRef", c.KeyRef, true)
		ref("platforms.checksums.passwordRef", c.PasswordRef, false)
		if !fprRe.MatchString(c.Fingerprint) {
			ps.add("platforms.checksums.fingerprint", "pin the signing key's fingerprint")
		}
		if c.Kind == "minisign" && strings.TrimSpace(c.PublicKey) == "" {
			ps.add("platforms.checksums.publicKey", "minisign verification needs the public key (the base64 line of minisign.pub)")
		}
	}
	if c := p.Platforms.Containers; c != nil {
		if c.Kind != "cosign" {
			ps.add("platforms.containers.kind", "%q is not cosign", c.Kind)
		}
		ref("platforms.containers.passwordRef", c.PasswordRef, false)
		switch c.Mode {
		case "key":
			ref("platforms.containers.keyRef", c.KeyRef, true)
			if c.KeyFingerprint == "" {
				ps.add("platforms.containers.keyFingerprint", "pin the cosign key's fingerprint")
			}
		case "keyless":
			if c.Identity == "" || c.Issuer == "" {
				ps.add("platforms.containers.identity", "keyless cosign pins the certificate identity and issuer")
			}
		default:
			ps.add("platforms.containers.mode", "%q is not key or keyless", c.Mode)
		}
	}
	if a := p.Platforms.Attestations; a != nil {
		if a.Kind != "in-toto" {
			ps.add("platforms.attestations.kind", "%q is not in-toto", a.Kind)
		}
		switch a.Signer {
		case "checksums":
			if p.Platforms.Checksums == nil {
				ps.add("platforms.attestations.signer", "attestations signed by the checksum key need platforms.checksums")
			}
		case "cosign":
			if p.Platforms.Containers == nil {
				ps.add("platforms.attestations.signer", "attestations signed by cosign need platforms.containers")
			}
		default:
			ps.add("platforms.attestations.signer", "%q is not checksums or cosign", a.Signer)
		}
	}
	return ps
}

// Decode reads a profile strictly: an unknown field and anything that looks
// like key material in the text are problems, not silently dropped.
func Decode(b []byte) (Profile, Problems, error) {
	var ps Problems
	if secretRe.Match(b) {
		ps.add("profile.secret", "the profile holds a secret; store it in the OS secret store or a CI secret and reference it")
	}
	var p Profile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			ps.add("profile.unknown", "%s", strings.TrimPrefix(err.Error(), "json: "))
			if err2 := json.Unmarshal(b, &p); err2 != nil {
				return Profile{}, ps, err2
			}
			return p, ps, nil
		}
		return Profile{}, ps, err
	}
	return p, ps, nil
}

// Check decodes and validates.
func Check(b []byte) (Profile, Problems, error) {
	p, ps, err := Decode(b)
	if err != nil {
		return p, ps, err
	}
	return p, append(ps, p.Validate()...), nil
}

// PinnedIdentity is what verification must find for a profile. Its JSON is the
// one sange computes, field for field, so both sides reach the same digest.
type PinnedIdentity struct {
	Profile      string   `json:"profile"`
	Scope        Scope    `json:"scope"`
	Owner        string   `json:"owner"`
	Purpose      []string `json:"purpose"`
	AllowedRepos []string `json:"allowedRepos,omitempty"`
	Windows      string   `json:"windows,omitempty"`
	MacOS        string   `json:"macos,omitempty"`
	Checksums    string   `json:"checksums,omitempty"`
	Containers   string   `json:"containers,omitempty"`
}

// Pinned returns the profile's pinned identity in canonical form.
func (p Profile) Pinned() PinnedIdentity {
	id := PinnedIdentity{Profile: p.Name, Scope: p.Scope, Owner: strings.ToLower(p.Owner)}
	for _, pu := range p.Purpose {
		id.Purpose = append(id.Purpose, string(pu))
	}
	sort.Strings(id.Purpose)
	id.AllowedRepos = append([]string(nil), p.AllowedRepos...)
	sort.Strings(id.AllowedRepos)
	if w := p.Platforms.Windows; w != nil {
		id.Windows = "thumbprint=" + strings.ToUpper(w.Thumbprint) + ";subject=" + w.Subject
		if len(w.Signers) > 0 {
			// A multi-certificate spec pins every signer, in id order. A
			// single-certificate profile keeps the form above, so its digest
			// (which sange computes too) does not change.
			var parts []string
			for _, sg := range w.Signers {
				parts = append(parts, "id="+sg.ID+";thumbprint="+strings.ToUpper(sg.Thumbprint)+";subject="+sg.Subject)
			}
			sort.Strings(parts)
			id.Windows = strings.Join(parts, "|")
		}
	}
	if m := p.Platforms.MacOS; m != nil {
		id.MacOS = "team=" + m.TeamID + ";identity=" + m.Identity
	}
	if c := p.Platforms.Checksums; c != nil {
		id.Checksums = c.Kind + ":" + strings.ToUpper(c.Fingerprint)
	}
	if c := p.Platforms.Containers; c != nil {
		if c.Mode == "keyless" {
			id.Containers = "keyless:" + c.Identity + "@" + c.Issuer
		} else {
			id.Containers = "key:" + c.KeyFingerprint
		}
	}
	return id
}

// Digest is "sha256:<hex>" over the canonical JSON of the pinned identity.
func (id PinnedIdentity) Digest() string {
	b, _ := json.Marshal(id)
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// azurePaths: an Artifact Signing certificate is reached through signtool's
// dlib and a metadata.json naming the account, so a profile names both
// (O-109) instead of failing only when it signs.
func azurePaths(at, backend, dlib, metadata string) Problems {
	var ps Problems
	if backend != BackendAzure {
		return ps
	}
	if dlib == "" {
		ps.add(at+".dlibPath", "Artifact Signing needs the path of Azure.CodeSigning.Dlib.dll (winget install -e --id Microsoft.Azure.ArtifactSigningClientTools)")
	}
	if metadata == "" {
		ps.add(at+".metadataPath", "Artifact Signing needs the path of metadata.json, which names the endpoint, account and certificate profile")
	}
	return ps
}
