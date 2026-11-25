package backend

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	macholibre "github.com/anchore/go-macholibre"
	"github.com/anchore/quill/quill/macho"
	"github.com/anchore/quill/quill/pki"
	"github.com/anchore/quill/quill/pki/load"
	"github.com/anchore/quill/quill/sign"
	"github.com/github/smimesign/ietf-cms/timestamp"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/secrets"
)

// Developer ID signing off a Mac (design ID-36, O-140): the PowerShell line's
// GoReleaser template signed and notarised macOS binaries from Windows and
// Linux; impr does it with anchore/quill's code-signing packages (the Mach-O
// code directory, the CMS signature and the .p12 handling) and its own notary
// client (applenotary.go), never the AWS SDK. On a Mac, codesign and
// notarytool are used as before.

// appleTimestampServer is Apple's RFC 3161 time-stamp service, which
// notarisation requires; codesign --timestamp uses the same one. A test sets
// it to "" (no network).
var appleTimestampServer = "http://timestamp.apple.com/ts01"

func init() {
	// smimesign asks the time-stamp server with this client: give it a
	// timeout instead of http.DefaultClient's none.
	timestamp.DefaultHTTPClient = &http.Client{Timeout: 60 * time.Second}
}

// offMacSign reports whether this host signs macOS files in Go: not a Mac,
// with the identity in a .p12 the profile names.
func (a *Apple) offMacSign() bool {
	return a.H.GOOS != "darwin" && a.Spec.CertRef != ""
}

// signingMaterial reads the .p12 and its password through impr's references,
// in memory, and refuses a certificate that is not the pinned identity and
// team before anything is signed.
func (a *Apple) signingMaterial(ctx context.Context) (*pki.SigningMaterial, error) {
	v, err := a.H.Secrets.Resolve(ctx, a.Spec.CertRef)
	if err != nil {
		return nil, err
	}
	der, err := secrets.AsBytes(v, true)
	if err != nil {
		return nil, err
	}
	pw := ""
	if a.Spec.PasswordRef != "" {
		if pw, err = a.H.Secrets.Resolve(ctx, a.Spec.PasswordRef); err != nil {
			return nil, err
		}
	}
	key, cert, _, err := pkcs12.DecodeChain(der, pw)
	if err != nil {
		// pkcs12's message names no secret; keep it out of ours anyway.
		if errors.Is(err, pkcs12.ErrIncorrectPassword) {
			return nil, contract.New(contract.SignFailed, "the .p12 does not open with the password passwordRef names")
		}
		return nil, contract.New(contract.SignFailed, "the .p12 cannot be read").WithDetails(err.Error())
	}
	team := ""
	if len(cert.Subject.OrganizationalUnit) > 0 {
		team = cert.Subject.OrganizationalUnit[0]
	}
	if cert.Subject.CommonName != a.Spec.Identity || team != a.Spec.TeamID {
		return nil, contract.New(contract.SignFailed, "the .p12 holds %q of team %s, not the pinned %q of team %s",
			cert.Subject.CommonName, orNone(team), a.Spec.Identity, a.Spec.TeamID)
	}
	if _, ok := key.(crypto.Signer); !ok {
		return nil, contract.New(contract.SignFailed, "the .p12's key cannot sign")
	}
	issuer, root, err := a.verifyDeveloperID(cert)
	if err != nil {
		return nil, err
	}
	// The verified chain, not the .p12's own, goes into the signature.
	sm, err := pki.NewSigningMaterialFromP12(load.P12Contents{PrivateKey: key, Certificate: cert, Certificates: []*x509.Certificate{issuer, root}}, true)
	if err != nil {
		return nil, contract.New(contract.SignFailed, "the .p12's certificate chain is not one Apple's code signing accepts").WithDetails(err.Error())
	}
	sm.TimestampServer = appleTimestampServer
	return sm, nil
}

// verifyDeveloperID requires the signing certificate to chain to Apple Root CA
// through one of the Developer ID CAs (appleTrust), to carry the code-signing
// extended key usage, and to be within its validity period now. The .p12's own
// chain is ignored: only appleTrust's issuers can complete it, so a
// certificate from any other CA, Apple's included, is refused.
func (a *Apple) verifyDeveloperID(cert *x509.Certificate) (issuer, root *x509.Certificate, err error) {
	now := time.Now()
	if a.H.Now != nil {
		now = a.H.Now()
	}
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, nil, contract.New(contract.SignFailed, "the .p12's certificate is not valid now: it is valid from %s to %s, so it has expired or is not yet valid",
			cert.NotBefore.UTC().Format(time.DateOnly), cert.NotAfter.UTC().Format(time.DateOnly))
	}
	inter := x509.NewCertPool()
	for _, c := range appleTrust.issuers {
		inter.AddCert(c)
	}
	// Apple marks Developer ID certificates with critical extensions Go does
	// not know (devid_execute, devid_kernel); check a copy without them, as
	// quill does.
	leaf := *cert
	leaf.UnhandledCriticalExtensions = nil
	for _, ex := range cert.UnhandledCriticalExtensions {
		if s := ex.String(); s != "1.2.840.113635.100.6.1.13" && s != "1.2.840.113635.100.6.1.18" {
			leaf.UnhandledCriticalExtensions = append(leaf.UnhandledCriticalExtensions, ex)
		}
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: appleTrust.roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}})
	if err != nil {
		return nil, nil, contract.New(contract.SignFailed, "the .p12's certificate is not a Developer ID certificate Apple issued for code signing").
			WithDetails(err.Error()).
			WithFix("export the Developer ID Application certificate and its key from the Apple developer account as a .p12")
	}
	for _, ch := range chains {
		if len(ch) == 3 {
			for _, want := range appleTrust.issuers {
				if ch[1].Equal(want) {
					return ch[1], ch[2], nil
				}
			}
		}
	}
	return nil, nil, contract.New(contract.SignFailed, "the .p12's certificate was not issued by a Developer ID Certification Authority")
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// signOffMac signs one Mach-O file, or each slice of a universal one, with
// the hardened runtime and a secure timestamp, as codesign --options runtime
// --timestamp does.
func (a *Apple) signOffMac(ctx context.Context, art Artifact) (Signature, error) {
	sm, err := a.signingMaterial(ctx)
	if err != nil {
		return Signature{}, err
	}
	ent := ""
	if a.Spec.Entitlements != "" {
		p := a.Spec.Entitlements
		if !filepath.IsAbs(p) {
			p = filepath.Join(a.H.Root, filepath.FromSlash(p))
		}
		b, err := os.ReadFile(p) //nolint:gosec // G304: the entitlements plist the profile names, under the signing root
		if err != nil {
			return Signature{}, contract.New(contract.Usage, "the entitlements file %s cannot be read", a.Spec.Entitlements)
		}
		ent = string(b)
	}
	id := filepath.Base(art.Path)
	if err := signMachOFile(art.Path, id, *sm, ent); err != nil {
		return Signature{}, contract.New(contract.SignFailed, "%s could not be signed", art.Rel).WithDetails(err.Error())
	}
	return Signature{Kind: "developer-id", Signer: a.Spec.Identity, Timestamp: timestampHost(sm.TimestampServer)}, nil
}

func timestampHost(u string) string {
	u = strings.TrimPrefix(strings.TrimPrefix(u, "http://"), "https://")
	host, _, _ := strings.Cut(u, "/")
	return host
}

// signMachOFile signs path in place: a universal binary slice by slice in a
// private folder, then packed again; a thin one directly.
func signMachOFile(path, id string, sm pki.SigningMaterial, ent string) error {
	f, err := os.Open(path) //nolint:gosec // G304: a manifest file under the signing root
	if err != nil {
		return err
	}
	universal := macholibre.IsUniversalMachoBinary(f)
	_ = f.Close()
	if !universal {
		return signThin(path, id, sm, ent)
	}
	dir, err := os.MkdirTemp("", "impr-macho-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	f, err = os.Open(path) //nolint:gosec // G304: as above
	if err != nil {
		return err
	}
	slices, err := macholibre.Extract(f, dir)
	_ = f.Close()
	if err != nil {
		return fmt.Errorf("split the universal binary: %w", err)
	}
	var paths []string
	for _, s := range slices {
		if err := signThin(s.Path, id, sm, ent); err != nil {
			return err
		}
		paths = append(paths, s.Path)
	}
	return macholibre.Package(path, paths...)
}

// signThin is quill's single-binary signing, written out with its packages:
// drop an old signature, add an empty LC_CODE_SIGNATURE, size the signature,
// fix the offsets, sign again with the final layout, and patch it in.
func signThin(path, id string, sm pki.SigningMaterial, ent string) error {
	m, err := macho.NewFile(path)
	if err != nil {
		return err
	}
	if m.HasCodeSigningCmd() {
		if err := m.RemoveSigningContent(); err != nil {
			return fmt.Errorf("remove the old signature: %w", err)
		}
	}
	if err := m.AddEmptyCodeSigningCmd(); err != nil {
		return err
	}
	size, sb, err := sign.GenerateSigningSuperBlob(id, m, sm, ent, 0)
	if err != nil {
		return fmt.Errorf("size the signature: %w", err)
	}
	if err := sign.UpdateSuperBlobOffsetReferences(m, uint64(len(sb))); err != nil {
		return fmt.Errorf("place the signature: %w", err)
	}
	if _, sb, err = sign.GenerateSigningSuperBlob(id, m, sm, ent, size); err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	cmd, _, err := m.CodeSigningCmd()
	if err != nil {
		return err
	}
	return m.Patch(sb, len(sb), uint64(cmd.DataOffset))
}
