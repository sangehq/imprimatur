// Package backend is the signing port: one backend per platform kind, each
// signing and verifying a file for a profile and reporting whether this host
// can do it. Every external tool runs through execx, so the allow-list there
// is the whole of what imprimatur can start.
//
//	authenticode  azure-artifact-signing, certum, cert-store (signtool on Windows); pfx (osslsigncode anywhere)
//	developer-id  codesign, notarytool, stapler (macOS)
//	gpg, minisign, ssh   the checksum file's detached signature
//	cosign        a Sigstore bundle over the checksum file, key or keyless
package backend

import (
	"context"
	"time"

	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/execx"
	"github.com/sangehq/imprimatur/src/internal/profile"
	"github.com/sangehq/imprimatur/src/internal/secrets"
)

// Host is what a backend may use: the OS, the tool runner and the secret
// resolver.
type Host struct {
	GOOS    string
	Runner  execx.Runner
	Secrets secrets.Resolver
	Now     func() time.Time
	// Root is the signing root, which relative profile paths resolve against.
	Root string
}

// preflighter is a backend that can refuse before anything is signed: a pin
// it cannot honour, a credential reference of the wrong shape.
type preflighter interface {
	Preflight(ctx context.Context, p profile.Profile) error
}

// Preflight runs a backend's checks that need no signing, if it has any.
func Preflight(ctx context.Context, b Backend, p profile.Profile) error {
	if pf, ok := b.(preflighter); ok {
		return pf.Preflight(ctx, p)
	}
	return nil
}

// Artifact is one file to sign or verify.
type Artifact struct {
	Path      string // absolute
	Rel       string // as recorded
	Notarized bool   // verify: the run recorded a notarisation ticket
}

// Output is a file a signature created beside the artifact.
type Output struct {
	Path string // absolute
	Kind string // gpg | minisign | ssh | cosign
}

// Signature is what a Sign call did.
type Signature struct {
	Kind      string // authenticode | developer-id | gpg | minisign | ssh | cosign
	Signer    string // the identity that signed, as found
	Timestamp string // the timestamp authority used, when there is one
	Outputs   []Output
}

// Capability says whether a backend works on this host, and why not.
type Capability struct {
	Platform  string   `json:"platform"`
	Kind      string   `json:"kind"`
	Backend   string   `json:"backend,omitempty"`
	Sign      bool     `json:"sign"`
	Verify    bool     `json:"verify"`
	Tools     []string `json:"tools,omitempty"`
	Reason    string   `json:"reason,omitempty"`
	Supported bool     `json:"supported"` // imprimatur implements it at all
}

// CertEntry is one certificate or key a profile uses (impr cert list).
type CertEntry struct {
	Profile     string     `json:"profile"`
	Platform    string     `json:"platform"`
	Subject     string     `json:"subject,omitempty"`
	Thumbprint  string     `json:"thumbprint,omitempty"`
	TeamID      string     `json:"teamId,omitempty"`
	Fingerprint string     `json:"fingerprint,omitempty"`
	NotAfter    *time.Time `json:"notAfter,omitempty"`
	Present     bool       `json:"present"`
	Source      string     `json:"source,omitempty"` // store | keychain | gpg | file | declared | unknown
}

// Backend signs and verifies for one platform of a profile.
type Backend interface {
	// Capability reports whether this host can sign and verify.
	Capability(h Host) Capability
	// Certificate reports the certificate or key the profile pins, as far as
	// this host can read it.
	Certificate(ctx context.Context, p profile.Profile) CertEntry
	// Sign signs the artifact with exactly the profile's pinned identity.
	Sign(ctx context.Context, a Artifact, p profile.Profile) (Signature, error)
	// Verify checks the artifact is signed by exactly the pinned identity.
	Verify(ctx context.Context, a Artifact, p profile.Profile) error
}

// For returns the backend for one platform of a profile.
func For(h Host, p profile.Profile, platform string) (Backend, error) {
	switch platform {
	case profile.Windows:
		if p.Platforms.Windows == nil {
			break
		}
		return &Authenticode{H: h, Spec: *p.Platforms.Windows}, nil
	case profile.MacOS:
		if p.Platforms.MacOS == nil {
			break
		}
		return &Apple{H: h, Spec: *p.Platforms.MacOS}, nil
	case profile.Checksums:
		c := p.Platforms.Checksums
		if c == nil {
			break
		}
		switch c.Kind {
		case "gpg":
			return &GPG{H: h, Spec: *c}, nil
		case "minisign":
			return &Minisign{H: h, Spec: *c}, nil
		case "ssh":
			return &SSH{H: h, Spec: *c}, nil
		}
		return nil, contract.New(contract.Usage, "checksum kind %q is not gpg, minisign or ssh", c.Kind)
	case profile.Containers:
		if p.Platforms.Containers == nil {
			break
		}
		return &Cosign{H: h, Spec: *p.Platforms.Containers}, nil
	case profile.Attestations:
		if p.Platforms.Attestations == nil {
			break
		}
		return Attestation{}, nil
	default:
		return nil, contract.New(contract.Usage, "%q is not a platform (%v)", platform, profile.AllPlatforms())
	}
	return nil, contract.New(contract.Usage, "signing profile %s has no %s configuration", p.Name, platform).
		WithFix("impr profile edit " + p.Name + " --set platforms." + platform + ".kind=...")
}

// Attestation is the in-toto platform, which imprimatur does not sign yet.
type Attestation struct{}

// Capability reports it unsupported.
func (Attestation) Capability(Host) Capability {
	return Capability{Platform: profile.Attestations, Kind: "in-toto", Reason: "in-toto attestations are not implemented yet"}
}

// Certificate has nothing to report.
func (Attestation) Certificate(_ context.Context, p profile.Profile) CertEntry {
	return CertEntry{Profile: p.Name, Platform: profile.Attestations, Source: "unknown"}
}

// Sign refuses.
func (Attestation) Sign(context.Context, Artifact, profile.Profile) (Signature, error) {
	return Signature{}, contract.New(contract.Unavailable, "in-toto attestations are not implemented in imprimatur yet")
}

// Verify refuses.
func (Attestation) Verify(context.Context, Artifact, profile.Profile) error {
	return contract.New(contract.Unavailable, "in-toto attestations are not implemented in imprimatur yet")
}

// tool reports whether the named tools resolve, and the first missing one.
func tool(h Host, names ...string) (bool, string) {
	for _, n := range names {
		if _, err := h.Runner.LookPath(n); err != nil {
			return false, n + " is not installed or not on PATH"
		}
	}
	return true, ""
}
