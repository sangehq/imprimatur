package backend

import (
	"context"
	"crypto/sha1" //nolint:gosec // G505: certificate thumbprints are SHA-1 identifiers, not a security check
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/execx"
	"github.com/sangehq/imprimatur/src/internal/profile"
	"github.com/sangehq/imprimatur/src/internal/secrets"
)

// Authenticode signs Windows files. azure-artifact-signing, certum and
// cert-store run signtool on Windows; pfx runs osslsigncode on any host, so
// the .pfx password goes in a file, never on a command line.
type Authenticode struct {
	H    Host
	Spec profile.WindowsSpec
}

// defaultTimestamps are the timestamp servers tried in turn when the profile
// names none, per backend (the PowerShell line's lists).
var defaultTimestamps = map[string][]string{
	profile.BackendCertStore: {"http://timestamp.digicert.com", "http://timestamp.sectigo.com", "http://timestamp.globalsign.com/tsa/r6advanced1"},
	profile.BackendCertum:    {"http://time.certum.pl", "http://timestamp.digicert.com"},
	profile.BackendAzure:     {"http://timestamp.acs.microsoft.com"},
	profile.BackendPFX:       {"http://timestamp.digicert.com", "http://timestamp.sectigo.com"},
}

func (a *Authenticode) signTool() string {
	if a.Spec.Backend == profile.BackendPFX {
		return "osslsigncode"
	}
	return "signtool"
}

func (a *Authenticode) verifyTool() string {
	if a.H.GOOS == "windows" {
		if _, err := a.H.Runner.LookPath("signtool"); err == nil {
			return "signtool"
		}
	}
	return "osslsigncode"
}

// Capability: signtool backends need Windows; pfx needs osslsigncode.
func (a *Authenticode) Capability(h Host) Capability {
	c := Capability{Platform: profile.Windows, Kind: "authenticode", Backend: a.Spec.Backend, Supported: true, Tools: []string{a.signTool()}}
	switch {
	case a.Spec.Backend != profile.BackendPFX && h.GOOS != "windows":
		c.Reason = a.Spec.Backend + " signs with signtool, which needs a Windows host"
	default:
		if ok, why := tool(h, a.signTool()); ok {
			c.Sign = true
		} else {
			c.Reason = why
		}
	}
	if ok, _ := tool(h, a.verifyTool()); ok {
		c.Verify = true
	} else if c.Reason == "" {
		c.Reason = "verification needs signtool (Windows) or osslsigncode"
	}
	return c
}

// Certificate reports the pinned certificate: a declared expiry, and on
// Windows whether the pinned thumbprint is in the user's store.
func (a *Authenticode) Certificate(ctx context.Context, p profile.Profile) CertEntry {
	e := CertEntry{Profile: p.Name, Platform: profile.Windows, Subject: a.Spec.Subject, Thumbprint: strings.ToUpper(a.Spec.Thumbprint),
		Source: "unknown", NotAfter: a.Spec.NotAfter}
	switch a.Spec.Backend {
	case profile.BackendAzure:
		// A cloud key: present when the client is configured; its expiry is declared.
		e.Present = fileExists(a.Spec.DlibPath) && fileExists(a.Spec.MetadataPath)
		e.Source = "declared"
	case profile.BackendPFX:
		// Present when the reference resolves; the .pfx is not written to a
		// temporary file just to say so (audit N-B10).
		if v, err := a.H.Secrets.Resolve(ctx, a.Spec.CertRef); err == nil {
			e.Present = strings.TrimSpace(v) != ""
		}
		e.Source = "file"
	default:
		if a.H.GOOS == "windows" && a.Spec.Thumbprint != "" {
			e.Source = "store"
			if r, err := a.H.Runner.Run(ctx, execx.Cmd{Tool: "certutil", Args: []string{"-user", "-verifystore", "My", a.Spec.Thumbprint}}); err == nil {
				e.Present = r.ExitCode == 0
			}
			if e.Present {
				if na := a.storeNotAfter(ctx); na != nil {
					e.NotAfter = na
				}
			}
		}
	}
	if a.Spec.NotAfter != nil && e.Source == "unknown" {
		e.Source = "declared"
	}
	return e
}

var azureEndpoint = regexp.MustCompile(`^https://[a-z0-9]+\.codesigning\.azure\.net/?$`)

// signArgs returns the backend's signtool arguments, refusing an ambiguous
// certificate choice: cert-store and Certum sign only with a pinned
// thumbprint, never the first certificate whose subject matches.
func (a *Authenticode) signArgs() ([]string, error) {
	switch a.Spec.Backend {
	case profile.BackendCertStore, profile.BackendCertum:
		if a.Spec.Thumbprint == "" {
			return nil, contract.New(contract.SignFailed, "the %s certificate is pinned by subject only; imprimatur will not pick a certificate by name", a.Spec.Backend).
				WithDetails("signtool /n signs with any certificate whose subject matches, which is the ambiguity the profile pin exists to remove.").
				WithFix("pin it: impr profile edit <name> --set platforms.windows.thumbprint=<SHA-1 thumbprint>")
		}
		return []string{"/sha1", strings.ToUpper(a.Spec.Thumbprint)}, nil
	case profile.BackendAzure:
		if !fileExists(a.Spec.DlibPath) {
			return nil, contract.New(contract.Unavailable, "the Azure Artifact Signing client (dlib) was not found at %q", a.Spec.DlibPath).
				WithFix("install it: winget install -e --id Microsoft.Azure.ArtifactSigningClientTools",
					"then: impr profile edit <name> --set platforms.windows.dlibPath=<path>\\Azure.CodeSigning.Dlib.dll")
		}
		b, err := os.ReadFile(a.Spec.MetadataPath)
		if err != nil {
			return nil, contract.Wrap(contract.Unavailable, err, "metadata.json for Artifact Signing was not found at %q", a.Spec.MetadataPath).
				WithFix(`create it with { "Endpoint": "https://<region>.codesigning.azure.net", "CodeSigningAccountName": "<account>", "CertificateProfileName": "<profile>" }`)
		}
		var meta map[string]string
		if err := json.Unmarshal(b, &meta); err != nil {
			return nil, contract.Wrap(contract.Usage, err, "metadata.json is not valid JSON: %s", a.Spec.MetadataPath)
		}
		for _, k := range []string{"Endpoint", "CodeSigningAccountName", "CertificateProfileName"} {
			if meta[k] == "" {
				return nil, contract.New(contract.Usage, "metadata.json is missing %s", k)
			}
		}
		if !azureEndpoint.MatchString(meta["Endpoint"]) {
			return nil, contract.New(contract.Usage, "the Endpoint in metadata.json looks wrong: %s", meta["Endpoint"]).
				WithDetails("It must be the region endpoint of your Artifact Signing account; a wrong region fails with 403 Forbidden.")
		}
		return []string{"/dlib", a.Spec.DlibPath, "/dmdf", a.Spec.MetadataPath}, nil
	}
	return nil, contract.New(contract.Usage, "%q is not a signtool backend", a.Spec.Backend)
}

func (a *Authenticode) timestamps() []string {
	if a.Spec.Timestamp != "" {
		return []string{a.Spec.Timestamp}
	}
	return defaultTimestamps[a.Spec.Backend]
}

// Sign signs in place, trying each timestamp server in turn, then verifies
// the result against the pin.
func (a *Authenticode) Sign(ctx context.Context, art Artifact, p profile.Profile) (Signature, error) {
	if c := a.Capability(a.H); !c.Sign {
		return Signature{}, contract.New(contract.Unavailable, "Authenticode signing (%s) is not available here: %s", a.Spec.Backend, c.Reason)
	}
	var used string
	var failures []string
	if a.Spec.Backend == profile.BackendPFX {
		ts, err := a.signPFX(ctx, art)
		if err != nil {
			return Signature{}, err
		}
		used = ts
	} else {
		extra, err := a.signArgs()
		if err != nil {
			return Signature{}, err
		}
		for _, ts := range a.timestamps() {
			args := append([]string{"sign", "/fd", "SHA256", "/td", "SHA256", "/tr", ts}, extra...)
			r, err := a.H.Runner.Run(ctx, execx.Cmd{Tool: "signtool", Args: append(args, art.Path)})
			if err != nil {
				return Signature{}, contract.Wrap(contract.Unavailable, err, "signtool could not run")
			}
			if r.ExitCode == 0 {
				used = ts
				break
			}
			failures = append(failures, "with "+ts+": "+firstLine(r.Output()))
		}
		if used == "" {
			return Signature{}, contract.New(contract.SignFailed, "signtool could not sign %s", art.Rel).WithDetails(failures...).
				WithFix("check the certificate is available (Certum: SimplySign Desktop logged in; Artifact Signing: az login)",
					"if every timestamp server failed, check the network or name one: --set platforms.windows.timestamp=<url>")
		}
	}
	signer, err := a.check(ctx, art, p)
	if err != nil {
		return Signature{}, err
	}
	return Signature{Kind: "authenticode", Signer: signer, Timestamp: hostOf(used)}, nil
}

func (a *Authenticode) signPFX(ctx context.Context, art Artifact) (string, error) {
	v, err := a.H.Secrets.Resolve(ctx, a.Spec.CertRef)
	if err != nil {
		return "", err
	}
	keyArgs, closeKey, err := osslKeyArgs(v)
	if err != nil {
		return "", err
	}
	defer closeKey()
	var pass secrets.File
	if a.Spec.PasswordRef != "" {
		pw, err := a.H.Secrets.Resolve(ctx, a.Spec.PasswordRef)
		if err != nil {
			return "", err
		}
		if pass, err = secrets.TempText(pw); err != nil {
			return "", err
		}
		defer pass.Close()
	}
	out := art.Path + ".impr-signed"
	defer func() { _ = os.Remove(out) }()
	var failures []string
	for _, ts := range a.timestamps() {
		_ = os.Remove(out)
		args := append([]string{"sign"}, keyArgs...)
		if pass.Path != "" {
			args = append(args, "-readpass", pass.Path)
		}
		args = append(args, "-h", "sha256", "-ts", ts, "-in", art.Path, "-out", out)
		r, err := a.H.Runner.Run(ctx, execx.Cmd{Tool: "osslsigncode", Args: args})
		if err != nil {
			return "", contract.Wrap(contract.Unavailable, err, "osslsigncode could not run")
		}
		if r.ExitCode == 0 {
			if err := os.Rename(out, art.Path); err != nil {
				return "", contract.Wrap(contract.SignFailed, err, "replace %s with its signed copy", art.Rel)
			}
			return ts, nil
		}
		failures = append(failures, "with "+ts+": "+firstLine(r.Output()))
	}
	return "", contract.New(contract.SignFailed, "osslsigncode could not sign %s", art.Rel).WithDetails(failures...)
}

// Verify checks the file is validly signed (the platform tool) by exactly the
// pinned certificate, with a timestamp. A test profile also accepts a
// signature whose only fault is an untrusted test root.
func (a *Authenticode) Verify(ctx context.Context, art Artifact, p profile.Profile) error {
	_, err := a.check(ctx, art, p)
	return err
}

func (a *Authenticode) check(ctx context.Context, art Artifact, p profile.Profile) (string, error) {
	s, err := ReadPESigner(art.Path)
	if err != nil {
		return "", contract.Wrap(contract.VerifyFailed, err, "%s is not Authenticode-signed", art.Rel)
	}
	if a.Spec.Thumbprint != "" && !strings.EqualFold(s.Thumbprint, a.Spec.Thumbprint) {
		return "", contract.New(contract.VerifyFailed, "%s is signed by certificate %s, not the pinned %s", art.Rel, s.Thumbprint, strings.ToUpper(a.Spec.Thumbprint))
	}
	if a.Spec.Subject != "" && !SubjectsEqual(s.Subject, a.Spec.Subject) && !SubjectsEqual(s.SubjectRFC, a.Spec.Subject) {
		return "", contract.New(contract.VerifyFailed, "%s is signed by %q, not the pinned %q", art.Rel, s.Subject, a.Spec.Subject)
	}
	if !s.Timestamped {
		return "", contract.New(contract.VerifyFailed, "%s has no timestamp: its signature stops being valid when the certificate expires", art.Rel)
	}
	vt := a.verifyTool()
	if ok, why := tool(a.H, vt); !ok {
		return "", contract.New(contract.Unavailable, "Authenticode signatures cannot be verified here: %s", why)
	}
	args := []string{"verify", "/pa", art.Path}
	if vt == "osslsigncode" {
		args = []string{"verify", "-in", art.Path}
	}
	r, err := a.H.Runner.Run(ctx, execx.Cmd{Tool: vt, Args: args})
	if err != nil {
		return "", contract.Wrap(contract.Unavailable, err, "%s could not run", vt)
	}
	if r.ExitCode != 0 {
		out := r.Output()
		untrustedRoot := untrustedRootOnly(out)
		if !p.HasPurpose(profile.PurposeTest) || !untrustedRoot {
			return "", contract.New(contract.VerifyFailed, "the signature on %s did not verify", art.Rel).WithDetails(firstLine(out))
		}
	}
	return s.Subject, nil
}

func fileExists(p string) bool {
	if p == "" {
		return false
	}
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func firstLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			return l
		}
	}
	return "(no output)"
}

func hostOf(u string) string {
	u = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	h, _, _ := strings.Cut(u, "/")
	return h
}

// Preflight refuses an ambiguous or unusable certificate choice before
// anything is signed.
func (a *Authenticode) Preflight(ctx context.Context, _ profile.Profile) error {
	if a.Spec.Backend == profile.BackendPFX {
		v, err := a.H.Secrets.Resolve(ctx, a.Spec.CertRef)
		if err != nil {
			return err
		}
		f, err := secrets.AsFile(v, true)
		if err != nil {
			return err
		}
		f.Close()
		return nil
	}
	if _, err := a.signArgs(); err != nil {
		return err
	}
	if a.Spec.Backend == profile.BackendAzure {
		return a.azureSignedIn(ctx)
	}
	return nil
}

// azureSignedIn checks the Azure CLI is signed in when it is the credential
// Artifact Signing will use: az is installed and no service-principal or
// managed-identity variables are set. Without az, or with those variables,
// the client authenticates another way and this check does not apply.
func (a *Authenticode) azureSignedIn(ctx context.Context) error {
	for _, v := range []string{"AZURE_CLIENT_ID", "AZURE_FEDERATED_TOKEN_FILE", "IDENTITY_ENDPOINT", "MSI_ENDPOINT"} {
		if a.H.Secrets.Getenv != nil && a.H.Secrets.Getenv(v) != "" {
			return nil
		}
	}
	if ok, _ := tool(a.H, "az"); !ok {
		return nil
	}
	r, err := a.H.Runner.Run(ctx, execx.Cmd{Tool: "az", Args: []string{"account", "show", "--output", "none"}})
	if err != nil || r.ExitCode != 0 {
		return contract.New(contract.Unavailable, "the Azure CLI is not signed in, so Artifact Signing cannot get a token; nothing was signed").
			WithFix("az login", "or set AZURE_CLIENT_ID, AZURE_TENANT_ID and AZURE_CLIENT_SECRET for a service principal")
	}
	return nil
}

// untrustedRootMessages are the exact reports of a chain that ends in a root
// this host does not trust, which is all a test certificate is allowed to
// fail on. Anything else in a failing verify stays a failure (audit N-B13).
var untrustedRootMessages = []string{
	"terminated in a root certificate which is not trusted by the trust provider", // signtool
	"self-signed certificate in certificate chain",                                // osslsigncode / OpenSSL
	"self signed certificate in certificate chain",
	"unable to get local issuer certificate",
}

// untrustedRootOnly reports whether a failing verify's output is an
// untrusted root and nothing worse: no digest mismatch, no bad signature, no
// expiry or revocation.
func untrustedRootOnly(out string) bool {
	low := strings.ToLower(out)
	for _, bad := range []string{"mismatch", "invalid", "revoked", "expired", "bad signature", "not signed", "no signature"} {
		if strings.Contains(low, bad) {
			return false
		}
	}
	for _, m := range untrustedRootMessages {
		if strings.Contains(low, m) {
			return true
		}
	}
	return false
}

// osslKeyArgs turns the pfx backend's resolved certRef into osslsigncode
// arguments: a .pfx (path or base64) is -pkcs12; a PEM bundle holding the
// certificate and its private key (what impr cert create writes) is split
// into owner-only temporary files and passed as -certs and -key.
func osslKeyArgs(v string) ([]string, func(), error) {
	text := v
	if b, err := os.ReadFile(v); err == nil { //nolint:gosec // G304: the profile's own certificate file
		text = string(b)
	}
	if strings.Contains(text, "-----BEGIN CERTIFICATE-----") && strings.Contains(text, "PRIVATE KEY-----") {
		var certs, keys []byte
		rest := []byte(text)
		for {
			var blk *pem.Block
			if blk, rest = pem.Decode(rest); blk == nil {
				break
			}
			if blk.Type == "CERTIFICATE" {
				certs = append(certs, pem.EncodeToMemory(blk)...)
			} else if strings.HasSuffix(blk.Type, "PRIVATE KEY") {
				keys = append(keys, pem.EncodeToMemory(blk)...)
			}
		}
		cf, err := secrets.TempText(string(certs))
		if err != nil {
			return nil, func() {}, err
		}
		kf, err := secrets.TempText(string(keys))
		if err != nil {
			cf.Close()
			return nil, func() {}, err
		}
		return []string{"-certs", cf.Path, "-key", kf.Path}, func() { cf.Close(); kf.Close() }, nil
	}
	pfx, err := secrets.AsFile(v, true)
	if err != nil {
		return nil, func() {}, err
	}
	return []string{"-pkcs12", pfx.Path}, pfx.Close, nil
}

// storeNotAfter reads the pinned certificate's real expiry from the Windows
// store: certutil exports it to a file, and the DER is parsed here, so no
// locale-dependent date text is ever read. Nil when it cannot be read.
func (a *Authenticode) storeNotAfter(ctx context.Context) *time.Time {
	dir, err := os.MkdirTemp("", "impr-cert-")
	if err != nil {
		return nil
	}
	defer func() { _ = os.RemoveAll(dir) }()
	out := filepath.Join(dir, "pinned.cer")
	r, err := a.H.Runner.Run(ctx, execx.Cmd{Tool: "certutil", Args: []string{"-user", "-store", "My", a.Spec.Thumbprint, out}})
	if err != nil || r.ExitCode != 0 {
		return nil
	}
	b, err := os.ReadFile(out) //nolint:gosec // G304: the file certutil just wrote
	if err != nil {
		return nil
	}
	if blk, _ := pem.Decode(b); blk != nil {
		b = blk.Bytes
	}
	c, err := x509.ParseCertificate(b)
	if err != nil || !strings.EqualFold(sha1Hex(c.Raw), a.Spec.Thumbprint) {
		return nil
	}
	na := c.NotAfter.UTC()
	return &na
}

func sha1Hex(b []byte) string {
	s := sha1.Sum(b) //nolint:gosec // G401: a certificate thumbprint is a SHA-1 identifier, not a security check
	return hex.EncodeToString(s[:])
}
