package backend

import (
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/pem"
	"fmt"
)

// Apple's public certificates that a Developer ID signing certificate must
// chain to when impr signs off a Mac (threat model I-25). They are copied
// verbatim from anchore/quill v0.7.1 (quill/pki/apple/certs), which took them
// from https://www.apple.com/certificateauthority/; the Apple Root CA
// fingerprint was also checked against macOS's
// /System/Library/Keychains/SystemRootCertificates.keychain on 2026-11-25.
//
//	applecerts/apple-root-ca.pem        Apple Root CA
//	  SHA-256 B0B1730ECBC7FF4505142C49F1295E6EDA6BCAED7E2C68C5BE91B5A11001F024
//	applecerts/developer-id-ca-g1.pem   Developer ID Certification Authority (until 2027-02-01)
//	  SHA-256 7AFC9D01A62F03A2DE9637936D4AFE68090D2DE18D03F29C88CFB0B1BA63587F
//	applecerts/developer-id-ca-g2.pem   Developer ID Certification Authority, OU G2 (until 2031-09-17)
//	  SHA-256 F16CD3C54C7F83CEA4BF1A3E6A0819C8AAA8E4A1528FD144715F350643D2DF3A
//
//go:embed applecerts/*.pem
var appleCertFS embed.FS

// appleCertSHA256 pins each embedded file; embeddedAppleTrust refuses one
// that differs, and a test checks the same list.
var appleCertSHA256 = map[string]string{
	"applecerts/apple-root-ca.pem":      "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024",
	"applecerts/developer-id-ca-g1.pem": "7afc9d01a62f03a2de9637936d4afe68090d2de18d03f29c88cfb0b1ba63587f",
	"applecerts/developer-id-ca-g2.pem": "f16cd3c54c7f83cea4bf1a3e6a0819c8aaa8e4a1528fd144715f350643d2df3a",
}

// appleTrustStore is what a signing certificate is checked against: the
// roots, and the only CAs allowed to have issued it.
type appleTrustStore struct {
	roots   *x509.CertPool
	issuers []*x509.Certificate
}

// appleTrust is Apple's Root CA and the Developer ID CAs. It is the test seam:
// only a test replaces it (useTestAppleTrust), never configuration.
var appleTrust = mustAppleTrust()

func mustAppleTrust() appleTrustStore {
	t, err := embeddedAppleTrust()
	if err != nil {
		panic(err)
	}
	return t
}

func embeddedAppleTrust() (appleTrustStore, error) {
	load := func(name string) (*x509.Certificate, error) {
		b, err := appleCertFS.ReadFile(name)
		if err != nil {
			return nil, err
		}
		blk, _ := pem.Decode(b)
		if blk == nil || blk.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%s is not a PEM certificate", name)
		}
		sum := sha256.Sum256(blk.Bytes)
		if hex.EncodeToString(sum[:]) != appleCertSHA256[name] {
			return nil, fmt.Errorf("%s does not match its pinned SHA-256", name)
		}
		return x509.ParseCertificate(blk.Bytes)
	}
	root, err := load("applecerts/apple-root-ca.pem")
	if err != nil {
		return appleTrustStore{}, err
	}
	t := appleTrustStore{roots: x509.NewCertPool()}
	t.roots.AddCert(root)
	for _, n := range []string{"applecerts/developer-id-ca-g1.pem", "applecerts/developer-id-ca-g2.pem"} {
		c, err := load(n)
		if err != nil {
			return appleTrustStore{}, err
		}
		t.issuers = append(t.issuers, c)
	}
	return t, nil
}
