package cli

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // G505: a certificate thumbprint is a SHA-1 identifier
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/profile"
)

var certCreateFlags = flagSpec{"json": boolFlag, "name": stringFlag, "subject": stringFlag, "days": stringFlag}

// CertCreated is `impr cert create --json`.
type CertCreated struct {
	Contract   int    `json:"contract"`
	Profile    string `json:"profile"`
	Thumbprint string `json:"thumbprint"`
	Subject    string `json:"subject"`
	Bundle     string `json:"bundle"`
	PublicCert string `json:"publicCert"`
}

// cmdCertCreate makes a self-signed code-signing certificate for tests and a
// test-purpose profile that signs with it through osslsigncode, on any host.
// The PowerShell toolkit put it in the Windows store; this keeps the key in an
// owner-only file under the config dir and writes the public .cer next to it
// for trusting on test machines. A test profile can never sign a release.
func cmdCertCreate(_ context.Context, a *App, args []string) (int, error) {
	p, err := parse(args, certCreateFlags)
	if err != nil {
		return 0, err
	}
	name := orDefault(p.str("name"), "test-signer")
	if !profile.ValidName(name) {
		return 0, contract.New(contract.Usage, "%q is not a profile name", name)
	}
	days := 365
	if v := p.str("days"); v != "" {
		if days, err = strconv.Atoi(v); err != nil || days < 1 || days > 825 {
			return 0, contract.New(contract.Usage, "--days is 1 to 825")
		}
	}
	cn := orDefault(p.str("subject"), "impr test signing ("+orDefault(a.User, "user")+")")
	cn = strings.TrimPrefix(cn, "CN=")
	s, err := a.store()
	if err != nil {
		return 0, err
	}
	if _, ok, _ := s.Get(name); ok {
		return 0, contract.New(contract.Usage, "a profile named %s exists; nothing was created", name).WithFix("impr cert create --name OTHER")
	}
	d, err := a.dirs()
	if err != nil {
		return 0, err
	}
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return 0, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	if err != nil {
		return 0, err
	}
	now := a.Now()
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: cn}, NotBefore: now.Add(-5 * 60e9),
		NotAfter: now.AddDate(0, 0, days), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return 0, err
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return 0, err
	}
	dir := filepath.Join(d.Config, "test-certs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, err
	}
	bundle := filepath.Join(dir, name+".pem")
	cer := filepath.Join(dir, name+".cer")
	data := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})...)
	if err := os.WriteFile(bundle, data, 0o600); err != nil {
		return 0, err
	}
	if err := os.WriteFile(cer, der, 0o644); err != nil { //nolint:gosec // G306: a public certificate to trust on test machines
		return 0, err
	}
	sum := sha1.Sum(der) //nolint:gosec // G401: the thumbprint Windows shows and impr pins
	thumb := strings.ToUpper(hex.EncodeToString(sum[:]))
	na := tpl.NotAfter.UTC()
	prof := profile.Profile{Schema: profile.Schema, Name: name, Scope: profile.ScopePersonal, Owner: orDefault(a.User, "me"),
		Purpose: []profile.Purpose{profile.PurposeTest},
		Platforms: profile.Platforms{Windows: &profile.WindowsSpec{Kind: "authenticode", Backend: profile.BackendPFX,
			CertRef: "file://" + bundle, Thumbprint: thumb, Subject: "CN=" + cn, NotAfter: &na}},
		Notes: "Created by impr cert create: a self-signed test certificate. It can never sign a release."}
	if err := s.Save(prof, false); err != nil {
		_ = os.Remove(bundle)
		_ = os.Remove(cer)
		return 0, err
	}
	out := CertCreated{Contract: contract.Version, Profile: name, Thumbprint: thumb, Subject: "CN=" + cn, Bundle: bundle, PublicCert: cer}
	if p.on("json") {
		a.json(out)
		return 0, nil
	}
	a.say("cert      created profile %s (test only), thumbprint %s, expires %s", name, thumb, na.Format("2006-01-02"))
	a.say("cert      to trust it on a Windows test machine: certutil -user -addstore Root %s && certutil -user -addstore TrustedPublisher %s", cer, cer)
	return 0, nil
}
