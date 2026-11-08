package backend

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // G505: the thumbprint under test is SHA-1 by definition
	"crypto/x509"
	"crypto/x509/pkix"
	"debug/pe"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// signedPE writes a minimal PE32+ file whose certificate table holds a
// PKCS#7 SignedData naming a certificate generated for this run, with or
// without a timestamp, and returns its path and the certificate's thumbprint.
func signedPE(t *testing.T, dir string, subject pkix.Name, timestamped bool) (path, thumbprint string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: subject, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	mustMarshal := func(v any) []byte {
		b, err := asn1.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	alg := mustMarshal(pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}})
	si := signerInfo{Version: 1, IssuerAndSerial: issuerAndSerial{Issuer: asn1.RawValue{FullBytes: cert.RawIssuer}, Serial: cert.SerialNumber},
		DigestAlgorithm: asn1.RawValue{FullBytes: alg}, DigestEncAlg: asn1.RawValue{FullBytes: alg}, EncryptedDigest: []byte{1, 2, 3}}
	if timestamped {
		attr := mustMarshal(attribute{Type: oidRFC3161, Values: asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Bytes: mustMarshal(asn1.NullRawValue)}})
		si.UnauthAttrs = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: attr}
	}
	sd := signedData{Version: 1,
		DigestAlgorithms: asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Bytes: alg},
		ContentInfo:      asn1.RawValue{FullBytes: mustMarshal(struct{ T asn1.ObjectIdentifier }{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}})},
		Certificates:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: cert.Raw},
		SignerInfos:      []signerInfo{si}}
	pkcs7 := mustMarshal(struct {
		T asn1.ObjectIdentifier
		C asn1.RawValue
	}{oidSignedData, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: mustMarshal(sd)}})

	var buf bytes.Buffer
	dos := make([]byte, 64)
	copy(dos, "MZ")
	binary.LittleEndian.PutUint32(dos[0x3c:], 64)
	buf.Write(dos)
	buf.WriteString("PE\x00\x00")
	fh := pe.FileHeader{Machine: pe.IMAGE_FILE_MACHINE_AMD64, SizeOfOptionalHeader: 240, Characteristics: 0x22}
	oh := pe.OptionalHeader64{Magic: 0x20b, NumberOfRvaAndSizes: 16}
	tableAt := uint32(buf.Len() + binary.Size(fh) + binary.Size(oh)) //nolint:gosec // G115: a small test file
	win := make([]byte, 8)
	binary.LittleEndian.PutUint32(win[0:], uint32(8+len(pkcs7))) //nolint:gosec // G115: a small test blob
	binary.LittleEndian.PutUint16(win[4:], 0x0200)
	binary.LittleEndian.PutUint16(win[6:], 2)
	oh.DataDirectory[4] = pe.DataDirectory{VirtualAddress: tableAt, Size: uint32(8 + len(pkcs7))} //nolint:gosec // G115: a small test blob
	_ = binary.Write(&buf, binary.LittleEndian, fh)
	_ = binary.Write(&buf, binary.LittleEndian, oh)
	buf.Write(win)
	buf.Write(pkcs7)
	path = filepath.Join(dir, "tool.exe")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha1.Sum(cert.Raw) //nolint:gosec // G401: see the import
	return path, strings.ToUpper(hex.EncodeToString(sum[:]))
}

func TestReadPESigner(t *testing.T) {
	subject := pkix.Name{CommonName: "Acme Ltd", Organization: []string{"Acme Ltd"}, Locality: []string{"London"}, Country: []string{"GB"}}
	path, thumb := signedPE(t, t.TempDir(), subject, true)
	s, err := ReadPESigner(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.Thumbprint != thumb || !s.Timestamped {
		t.Fatalf("signer: %+v, want thumbprint %s", s, thumb)
	}
	if s.Subject != "CN=Acme Ltd, O=Acme Ltd, L=London, C=GB" {
		t.Fatalf("subject as Windows shows it: %q", s.Subject)
	}
	path, _ = signedPE(t, t.TempDir(), subject, false)
	if s, err := ReadPESigner(path); err != nil || s.Timestamped {
		t.Fatalf("an untimestamped signature read as timestamped: %+v %v", s, err)
	}
	plain := filepath.Join(t.TempDir(), "plain.exe")
	if err := os.WriteFile(plain, []byte("MZ not a pe"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPESigner(plain); err == nil {
		t.Fatal("a file with no signature read as signed")
	}
}

func TestSubjectsEqual(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"CN=Acme Ltd, O=Acme Ltd, C=GB", "CN=Acme Ltd,O=Acme Ltd,C=GB", true},
		{`CN="Open Source Developer, Pat Doe", C=PL`, `CN=Open Source Developer\, Pat Doe,C=PL`, true},
		{"CN=Acme Ltd, O=Acme Ltd, C=GB", "CN=Acme Ltd", false},
		{"CN=Acme Ltd", "CN=acme ltd", false},
		{"", "", false},
	}
	for _, c := range cases {
		if got := SubjectsEqual(c.a, c.b); got != c.want {
			t.Errorf("SubjectsEqual(%q, %q) = %v", c.a, c.b, got)
		}
	}
}
