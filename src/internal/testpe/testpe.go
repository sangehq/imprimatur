// Package testpe builds minimal Authenticode-signed PE files for tests: a
// PE32+ header whose certificate table holds a PKCS#7 SignedData naming a
// leaf certificate issued by a test CA. Only tests import it.
package testpe

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"debug/pe"
	"encoding/asn1"
	"encoding/binary"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// CA is a test certificate authority.
type CA struct {
	Cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// NewCA makes a self-signed CA.
func NewCA(t *testing.T, cn string) CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return CA{Cert: c, key: key}
}

type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type signerInfo struct {
	Version         int
	IssuerAndSerial issuerAndSerial
	DigestAlgorithm asn1.RawValue
	DigestEncAlg    asn1.RawValue
	EncryptedDigest []byte
}

type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	ContentInfo      asn1.RawValue
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

// signature is a PKCS#7 SignedData naming a leaf with the given subject,
// issued by ca, with both certificates, as a PE certificate table carries.
func signature(t *testing.T, subject pkix.Name, ca CA) ([]byte, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{SerialNumber: serial, Subject: subject, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.Cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	must := func(v any) []byte {
		b, err := asn1.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	alg := must(pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}})
	si := signerInfo{Version: 1, IssuerAndSerial: issuerAndSerial{Issuer: asn1.RawValue{FullBytes: leaf.RawIssuer}, Serial: leaf.SerialNumber},
		DigestAlgorithm: asn1.RawValue{FullBytes: alg}, DigestEncAlg: asn1.RawValue{FullBytes: alg}, EncryptedDigest: []byte{1, 2, 3}}
	sd := signedData{Version: 1, DigestAlgorithms: asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Bytes: alg},
		ContentInfo:  asn1.RawValue{FullBytes: must(struct{ T asn1.ObjectIdentifier }{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}})},
		Certificates: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: append(append([]byte{}, leaf.Raw...), ca.Cert.Raw...)},
		SignerInfos:  []signerInfo{si}}
	pkcs7 := must(struct {
		T asn1.ObjectIdentifier
		C asn1.RawValue
	}{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: must(sd)}})
	return pkcs7, leaf
}

// SignFile attaches such a signature to an existing PE32+ file (a real Go
// build, say), so tests can read signer and version information together.
func SignFile(t *testing.T, path string, subject pkix.Name, ca CA) *x509.Certificate {
	t.Helper()
	pkcs7, leaf := signature(t, subject, ca)
	b, err := os.ReadFile(path) //nolint:gosec // G304: a test file the caller made
	if err != nil {
		t.Fatal(err)
	}
	for len(b)%8 != 0 {
		b = append(b, 0)
	}
	at := len(b)
	win := make([]byte, 8)
	binary.LittleEndian.PutUint32(win[0:], uint32(8+len(pkcs7))) //nolint:gosec // G115: a small test blob
	binary.LittleEndian.PutUint16(win[4:], 0x0200)
	binary.LittleEndian.PutUint16(win[6:], 2)
	b = append(append(b, win...), pkcs7...)
	oh := int(binary.LittleEndian.Uint32(b[0x3c:])) + 24
	if binary.LittleEndian.Uint16(b[oh:]) != 0x20b {
		t.Fatalf("%s is not a PE32+ file", path)
	}
	dd := oh + 112 + 4*8                                          // DataDirectory[4], the certificate table
	binary.LittleEndian.PutUint32(b[dd:], uint32(at))             //nolint:gosec // G115: a small test file
	binary.LittleEndian.PutUint32(b[dd+4:], uint32(8+len(pkcs7))) //nolint:gosec // G115: a small test blob
	if err := os.WriteFile(path, b, 0o600); err != nil {          //nolint:gosec // G703: a test file the caller made
		t.Fatal(err)
	}
	return leaf
}

// Signed writes dir/name as a PE whose signature names a leaf with the given
// subject, issued by ca, with both certificates in the signature. It returns
// the path and the leaf.
func Signed(t *testing.T, dir, name string, subject pkix.Name, ca CA) (string, *x509.Certificate) {
	t.Helper()
	pkcs7, leaf := signature(t, subject, ca)
	var buf bytes.Buffer
	dos := make([]byte, 64)
	copy(dos, "MZ")
	binary.LittleEndian.PutUint32(dos[0x3c:], 64)
	buf.Write(dos)
	buf.WriteString("PE\x00\x00")
	fh := pe.FileHeader{Machine: pe.IMAGE_FILE_MACHINE_AMD64, SizeOfOptionalHeader: 240, Characteristics: 0x22}
	oh := pe.OptionalHeader64{Magic: 0x20b, NumberOfRvaAndSizes: 16}
	at := uint32(buf.Len() + binary.Size(fh) + binary.Size(oh)) //nolint:gosec // G115: a small test file
	win := make([]byte, 8)
	binary.LittleEndian.PutUint32(win[0:], uint32(8+len(pkcs7))) //nolint:gosec // G115: a small test blob
	binary.LittleEndian.PutUint16(win[4:], 0x0200)
	binary.LittleEndian.PutUint16(win[6:], 2)
	oh.DataDirectory[4] = pe.DataDirectory{VirtualAddress: at, Size: uint32(8 + len(pkcs7))} //nolint:gosec // G115: a small test blob
	_ = binary.Write(&buf, binary.LittleEndian, fh)
	_ = binary.Write(&buf, binary.LittleEndian, oh)
	buf.Write(win)
	buf.Write(pkcs7)
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, leaf
}
