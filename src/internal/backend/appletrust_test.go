package backend

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"io/fs"
	"math/big"
	"strings"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/execx"
	"github.com/sangehq/imprimatur/src/internal/profile"
)

// devIDCA is a test stand-in for Apple Root CA and a Developer ID CA.
type devIDCA struct {
	root, inter       *x509.Certificate
	rootKey, interKey *ecdsa.PrivateKey
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

var serial int64

func nextSerial() *big.Int { serial++; return big.NewInt(time.Now().UnixNano() + serial) }

func mustCert(t *testing.T, tmpl, parent *x509.Certificate, pub, signer any) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newDevIDCA(t *testing.T) *devIDCA {
	t.Helper()
	ca := &devIDCA{rootKey: newKey(t), interKey: newKey(t)}
	now := time.Now()
	rt := &x509.Certificate{SerialNumber: nextSerial(), Subject: pkix.Name{CommonName: "Test Apple Root CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	ca.root = mustCert(t, rt, rt, &ca.rootKey.PublicKey, ca.rootKey)
	it := &x509.Certificate{SerialNumber: nextSerial(), Subject: pkix.Name{CommonName: "Test Developer ID Certification Authority"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	ca.inter = mustCert(t, it, ca.root, &ca.interKey.PublicKey, ca.rootKey)
	return ca
}

// useTestAppleTrust swaps the test CA in for Apple's for the rest of the test.
func useTestAppleTrust(t *testing.T, ca *devIDCA) {
	t.Helper()
	old := appleTrust
	pool := x509.NewCertPool()
	pool.AddCert(ca.root)
	appleTrust = appleTrustStore{roots: pool, issuers: []*x509.Certificate{ca.inter}}
	t.Cleanup(func() { appleTrust = old })
}

type leafOpts struct {
	cn, team   string
	eku        []x509.ExtKeyUsage
	notAfter   time.Time
	selfSigned bool
	byRoot     bool // issued straight by the root, not by a Developer ID CA
}

// p12 issues a leaf and packs it, with the intermediate, as a .p12 under a
// password generated for this run.
func (ca *devIDCA) p12(t *testing.T, o leafOpts) (p12 []byte, password string) {
	t.Helper()
	key := newKey(t)
	if o.eku == nil {
		o.eku = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	}
	if o.notAfter.IsZero() {
		o.notAfter = time.Now().Add(24 * time.Hour)
	}
	tmpl := &x509.Certificate{SerialNumber: nextSerial(),
		Subject:   pkix.Name{CommonName: o.cn, OrganizationalUnit: []string{o.team}, Organization: []string{"Example"}},
		NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: o.notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: o.eku, BasicConstraintsValid: true}
	var leaf *x509.Certificate
	var chain []*x509.Certificate
	switch {
	case o.selfSigned:
		leaf = mustCert(t, tmpl, tmpl, &key.PublicKey, key)
	case o.byRoot:
		leaf = mustCert(t, tmpl, ca.root, &key.PublicKey, ca.rootKey)
	default:
		leaf = mustCert(t, tmpl, ca.inter, &key.PublicKey, ca.interKey)
		chain = []*x509.Certificate{ca.inter}
	}
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	password = base64.RawURLEncoding.EncodeToString(b)
	p12, err := pkcs12.Modern.Encode(key, leaf, chain, password)
	if err != nil {
		t.Fatal(err)
	}
	return p12, password
}

const (
	pinnedCN   = "Developer ID Application: Example (TEAM123456)"
	pinnedTeam = "TEAM123456"
)

// material runs the certificate checks alone, on a host that is not a Mac.
func material(t *testing.T, p12 []byte, pw string) error {
	t.Helper()
	h := fakeHost("linux", execx.NewFake(), map[string]string{"P12": base64.StdEncoding.EncodeToString(p12), "P12PW": pw})
	a := &Apple{H: h, Spec: profile.MacOSSpec{Kind: "developer-id", TeamID: pinnedTeam, Identity: pinnedCN,
		CertRef: "env://P12", PasswordRef: "env://P12PW"}}
	_, err := a.signingMaterial(context.Background())
	if err != nil && strings.Contains(err.Error(), pw) {
		t.Fatal("the error names the password")
	}
	return err
}

func TestAppleOffAMacAcceptsADeveloperIDChain(t *testing.T) {
	ca := newDevIDCA(t)
	useTestAppleTrust(t, ca)
	p12, pw := ca.p12(t, leafOpts{cn: pinnedCN, team: pinnedTeam})
	if err := material(t, p12, pw); err != nil {
		t.Fatalf("a certificate a Developer ID CA issued was refused: %v", err)
	}
}

func TestAppleOffAMacRefusesASelfSignedCertificate(t *testing.T) {
	useTestAppleTrust(t, newDevIDCA(t))
	p12, pw := newDevIDCA(t).p12(t, leafOpts{cn: pinnedCN, team: pinnedTeam, selfSigned: true})
	err := material(t, p12, pw)
	wantCode(t, err, contract.SignFailed)
	if !strings.Contains(err.Error(), "Developer ID") {
		t.Fatalf("the refusal does not say why: %v", err)
	}
}

func TestAppleOffAMacRefusesAnotherCAsCertificate(t *testing.T) {
	useTestAppleTrust(t, newDevIDCA(t))
	p12, pw := newDevIDCA(t).p12(t, leafOpts{cn: pinnedCN, team: pinnedTeam})
	wantCode(t, material(t, p12, pw), contract.SignFailed)
}

func TestAppleOffAMacRefusesACertificateTheRootIssuedDirectly(t *testing.T) {
	ca := newDevIDCA(t)
	useTestAppleTrust(t, ca)
	p12, pw := ca.p12(t, leafOpts{cn: pinnedCN, team: pinnedTeam, byRoot: true})
	wantCode(t, material(t, p12, pw), contract.SignFailed)
}

func TestAppleOffAMacRefusesTheWrongEKU(t *testing.T) {
	ca := newDevIDCA(t)
	useTestAppleTrust(t, ca)
	p12, pw := ca.p12(t, leafOpts{cn: pinnedCN, team: pinnedTeam, eku: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	wantCode(t, material(t, p12, pw), contract.SignFailed)
}

func TestAppleOffAMacRefusesAnExpiredCertificate(t *testing.T) {
	ca := newDevIDCA(t)
	useTestAppleTrust(t, ca)
	p12, pw := ca.p12(t, leafOpts{cn: pinnedCN, team: pinnedTeam, notAfter: time.Now().Add(-time.Hour)})
	err := material(t, p12, pw)
	wantCode(t, err, contract.SignFailed)
	if !strings.Contains(err.Error(), "expired") && !strings.Contains(strings.Join(contractDetails(err), " "), "expired") {
		t.Fatalf("the refusal does not say the certificate expired: %v", err)
	}
}

func TestAppleOffAMacRefusesTheRightNameOfAnotherTeam(t *testing.T) {
	ca := newDevIDCA(t)
	useTestAppleTrust(t, ca)
	p12, pw := ca.p12(t, leafOpts{cn: pinnedCN, team: "OTHER12345"})
	wantCode(t, material(t, p12, pw), contract.SignFailed)
}

func TestAppleOffAMacRefusesAnotherNameOfTheRightTeam(t *testing.T) {
	ca := newDevIDCA(t)
	useTestAppleTrust(t, ca)
	p12, pw := ca.p12(t, leafOpts{cn: "Developer ID Application: Someone Else (TEAM123456)", team: pinnedTeam})
	wantCode(t, material(t, p12, pw), contract.SignFailed)
}

// Without the seam, the embedded Apple certificates decide: a test CA's
// certificate, however well named, is refused.
func TestAppleOffAMacTrustsOnlyAppleByDefault(t *testing.T) {
	p12, pw := newDevIDCA(t).p12(t, leafOpts{cn: pinnedCN, team: pinnedTeam})
	wantCode(t, material(t, p12, pw), contract.SignFailed)
}

func TestEmbeddedAppleCertificatesMatchTheirPins(t *testing.T) {
	names, err := fs.Glob(appleCertFS, "applecerts/*.pem")
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 3 || len(appleCertSHA256) != 3 {
		t.Fatalf("want 3 embedded certificates and 3 pins, got %d and %d", len(names), len(appleCertSHA256))
	}
	for _, n := range names {
		b, _ := appleCertFS.ReadFile(n)
		blk, _ := pem.Decode(b)
		sum := sha256.Sum256(blk.Bytes)
		if got := hex.EncodeToString(sum[:]); got != appleCertSHA256[n] {
			t.Errorf("%s: SHA-256 %s, pinned %s", n, got, appleCertSHA256[n])
		}
	}
	tr, err := embeddedAppleTrust()
	if err != nil {
		t.Fatal(err)
	}
	if len(tr.issuers) != 2 {
		t.Fatalf("want the two Developer ID CAs, got %d", len(tr.issuers))
	}
	for _, c := range tr.issuers {
		if c.Subject.CommonName != "Developer ID Certification Authority" || c.Issuer.CommonName != "Apple Root CA" {
			t.Errorf("unexpected issuer %s from %s", c.Subject, c.Issuer)
		}
	}
}

func contractDetails(err error) []string {
	if e, ok := err.(*contract.Error); ok {
		return e.Details
	}
	return nil
}
