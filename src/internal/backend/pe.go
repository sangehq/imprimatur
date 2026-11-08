package backend

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // G505: the Authenticode thumbprint is SHA-1 by definition; it identifies, it does not protect
	"crypto/x509"
	"crypto/x509/pkix"
	"debug/pe"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
)

// PESigner is what the embedded Authenticode signature of a PE file names.
type PESigner struct {
	Thumbprint  string // SHA-1 of the leaf certificate, upper-case hex
	Subject     string // the leaf's subject, as Windows shows it
	SubjectRFC  string // the leaf's subject, RFC 2253
	Leaf        *x509.Certificate
	Timestamped bool
}

var (
	oidSignedData      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidCounterSig      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 6}
	oidRFC3161         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 3, 3, 1}
	errNotSigned       = errors.New("the file carries no Authenticode signature")
	errNoSignerInCerts = errors.New("the signature's signer certificate is not in the file")
)

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	ContentInfo      asn1.RawValue
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type signerInfo struct {
	Version         int
	IssuerAndSerial issuerAndSerial
	DigestAlgorithm asn1.RawValue
	AuthAttrs       asn1.RawValue `asn1:"optional,tag:0"`
	DigestEncAlg    asn1.RawValue
	EncryptedDigest []byte
	UnauthAttrs     asn1.RawValue `asn1:"optional,tag:1"`
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

// ReadPESigner reads the Authenticode signature embedded in a PE file: the
// leaf certificate that signed it and whether it carries a timestamp. It
// identifies the signer; the cryptographic check is the platform tool's.
func ReadPESigner(path string) (PESigner, error) {
	f, err := os.Open(path) //nolint:gosec // G304: an artifact resolved under the signing root
	if err != nil {
		return PESigner{}, err
	}
	defer func() { _ = f.Close() }()
	pf, err := pe.NewFile(f)
	if err != nil {
		return PESigner{}, fmt.Errorf("not a PE file: %w", err)
	}
	var dir pe.DataDirectory
	switch oh := pf.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if oh.NumberOfRvaAndSizes > 4 {
			dir = oh.DataDirectory[4]
		}
	case *pe.OptionalHeader64:
		if oh.NumberOfRvaAndSizes > 4 {
			dir = oh.DataDirectory[4]
		}
	}
	if dir.VirtualAddress == 0 || dir.Size < 8 {
		return PESigner{}, errNotSigned
	}
	buf := make([]byte, dir.Size)
	if _, err := f.ReadAt(buf, int64(dir.VirtualAddress)); err != nil && !errors.Is(err, io.EOF) {
		return PESigner{}, fmt.Errorf("read the certificate table: %w", err)
	}
	// WIN_CERTIFICATE: dwLength, wRevision, wCertificateType (2 = PKCS#7), bCertificate.
	length := binary.LittleEndian.Uint32(buf[0:4])
	if typ := binary.LittleEndian.Uint16(buf[6:8]); typ != 2 || length < 8 || int(length) > len(buf) {
		return PESigner{}, errNotSigned
	}
	return parsePKCS7(buf[8:length])
}

func parsePKCS7(der []byte) (PESigner, error) {
	var ci contentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return PESigner{}, fmt.Errorf("the signature is not PKCS#7: %w", err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return PESigner{}, errNotSigned
	}
	var sd signedData
	inner := ci.Content.FullBytes
	if ci.Content.Class == asn1.ClassContextSpecific {
		inner = ci.Content.Bytes // the [0] wrapper was kept
	}
	if _, err := asn1.Unmarshal(inner, &sd); err != nil {
		return PESigner{}, fmt.Errorf("the signature is not PKCS#7 SignedData: %w", err)
	}
	if len(sd.SignerInfos) != 1 {
		return PESigner{}, fmt.Errorf("the signature has %d signers; Authenticode has exactly one", len(sd.SignerInfos))
	}
	certs, err := x509.ParseCertificates(sd.Certificates.Bytes)
	if err != nil {
		return PESigner{}, fmt.Errorf("the signature's certificates do not parse: %w", err)
	}
	si := sd.SignerInfos[0]
	var leaf *x509.Certificate
	for _, c := range certs {
		if bytes.Equal(c.RawIssuer, si.IssuerAndSerial.Issuer.FullBytes) && c.SerialNumber.Cmp(si.IssuerAndSerial.Serial) == 0 {
			leaf = c
			break
		}
	}
	if leaf == nil {
		return PESigner{}, errNoSignerInCerts
	}
	sum := sha1.Sum(leaf.Raw) //nolint:gosec // G401: thumbprint, see the import
	out := PESigner{Thumbprint: strings.ToUpper(hex.EncodeToString(sum[:])), Leaf: leaf,
		Subject: WindowsName(leaf.RawSubject), SubjectRFC: leaf.Subject.String()}
	rest := si.UnauthAttrs.Bytes
	for len(rest) > 0 {
		var a attribute
		r, err := asn1.Unmarshal(rest, &a)
		if err != nil {
			break
		}
		rest = r
		if a.Type.Equal(oidCounterSig) || a.Type.Equal(oidRFC3161) {
			out.Timestamped = true
		}
	}
	return out, nil
}

var attrNames = map[string]string{
	"2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "S", "2.5.4.9": "STREET", "2.5.4.10": "O",
	"2.5.4.11": "OU", "2.5.4.5": "SERIALNUMBER", "1.2.840.113549.1.9.1": "E", "2.5.4.4": "SN", "2.5.4.42": "G",
	"2.5.4.12": "T", "0.9.2342.19200300.100.1.25": "DC", "1.3.6.1.4.1.311.60.2.1.3": "OID.1.3.6.1.4.1.311.60.2.1.3",
	"2.5.4.15": "OID.2.5.4.15",
}

// WindowsName renders a DER subject the way Windows shows it: most specific
// first, ", " between parts, a value with a separator in it quoted.
func WindowsName(rawSubject []byte) string {
	var rdns pkix.RDNSequence
	if _, err := asn1.Unmarshal(rawSubject, &rdns); err != nil {
		return ""
	}
	var parts []string
	for i := len(rdns) - 1; i >= 0; i-- {
		for _, atv := range rdns[i] {
			key, ok := attrNames[atv.Type.String()]
			if !ok {
				key = "OID." + atv.Type.String()
			}
			v := fmt.Sprint(atv.Value)
			if strings.ContainsAny(v, ",+=\"\n<>#;") {
				v = `"` + strings.ReplaceAll(v, `"`, `""`) + `"`
			}
			parts = append(parts, key+"="+v)
		}
	}
	return strings.Join(parts, ", ")
}

// SubjectsEqual compares two distinguished names part by part, ignoring the
// spacing around separators and how a value with a comma is quoted or
// escaped. Values compare exactly.
func SubjectsEqual(a, b string) bool {
	pa, pb := dnParts(a), dnParts(b)
	if len(pa) == 0 || len(pa) != len(pb) {
		return false
	}
	for i := range pa {
		if pa[i] != pb[i] {
			return false
		}
	}
	return true
}

// dnParts splits "CN=a, O=\"b, c\"" or "CN=a,O=b\, c" into "CN=a", "O=b, c".
func dnParts(s string) []string {
	var parts []string
	var cur strings.Builder
	quoted, escaped := false, false
	flush := func() {
		p := strings.TrimSpace(cur.String())
		if k, v, ok := strings.Cut(p, "="); ok {
			p = strings.ToUpper(strings.TrimSpace(k)) + "=" + strings.TrimSpace(v)
		}
		if p != "" {
			parts = append(parts, p)
		}
		cur.Reset()
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case escaped:
			cur.WriteByte(c)
			escaped = false
		case c == '\\':
			escaped = true
		case c == '"':
			if quoted && i+1 < len(s) && s[i+1] == '"' {
				cur.WriteByte('"')
				i++
				continue
			}
			quoted = !quoted
		case (c == ',' || c == ';') && !quoted:
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return parts
}
