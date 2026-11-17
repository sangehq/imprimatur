package backend

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	_ "crypto/sha1"   //nolint:gosec // G505: SHA-1 Authenticode digests still exist; checking one is not trusting SHA-1 for anything new
	_ "crypto/sha256" // digestHashes needs each hash linked in
	_ "crypto/sha512"
	"crypto/x509/pkix"
	"debug/pe"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

var (
	oidSpcIndirectData = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}
	oidMessageDigest   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	digestHashes       = map[string]crypto.Hash{
		"1.3.14.3.2.26":          crypto.SHA1,
		"2.16.840.1.101.3.4.2.1": crypto.SHA256,
		"2.16.840.1.101.3.4.2.2": crypto.SHA384,
		"2.16.840.1.101.3.4.2.3": crypto.SHA512,
	}
	// ErrTampered is a PE file whose bytes no longer match its signature.
	ErrTampered = errors.New("the file was changed after it was signed")
)

type spcIndirectDataContent struct {
	Data          asn1.RawValue
	MessageDigest struct {
		Algorithm pkix.AlgorithmIdentifier
		Digest    []byte
	}
}

// VerifyAuthenticode checks that a signed PE file is intact: the file's
// Authenticode hash equals the one the signature carries, that content's
// digest equals the signed messageDigest attribute, and the leaf's key made
// the signature (O-173). It does not judge whether the certificate is
// trusted; Windows and the rules' pins do that.
func VerifyAuthenticode(path string) error {
	b, err := os.ReadFile(path) //nolint:gosec // G304: a file the caller named for rules
	if err != nil {
		return err
	}
	f, err := pe.NewFile(bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("not a PE file: %w", err)
	}
	oh, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	var dir pe.DataDirectory
	optOff := int(binary.LittleEndian.Uint32(b[0x3c:])) + 24
	dirOff := optOff + 144 // PE32+: the data directories start at 112; the certificate table is the fifth
	if ok {
		dir = oh.DataDirectory[4]
	} else if oh32, ok32 := f.OptionalHeader.(*pe.OptionalHeader32); ok32 {
		dir, dirOff = oh32.DataDirectory[4], optOff+128
	} else {
		return errors.New("the PE file has no optional header")
	}
	start, end := int(dir.VirtualAddress), int(dir.VirtualAddress)+int(dir.Size)
	if dir.Size < 8 || start < dirOff+8 || end > len(b) {
		return errNotSigned
	}
	s, err := ReadPESigner(path)
	if err != nil {
		return err
	}
	sd, si, err := signedParts(b[start+8 : end])
	if err != nil {
		return err
	}
	// The SpcIndirectDataContent holds the digest of the image.
	var ci struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"explicit,optional,tag:0"`
	}
	if _, err := asn1.Unmarshal(sd.ContentInfo.FullBytes, &ci); err != nil || !ci.Type.Equal(oidSpcIndirectData) {
		return errors.New("the signature does not hold Authenticode content")
	}
	val := ci.Content
	if val.Class == asn1.ClassContextSpecific { // the [0] wrapper was kept
		if _, err := asn1.Unmarshal(val.Bytes, &val); err != nil {
			return fmt.Errorf("the Authenticode content does not parse: %w", err)
		}
	}
	var spc spcIndirectDataContent
	if _, err := asn1.Unmarshal(val.FullBytes, &spc); err != nil {
		return fmt.Errorf("the Authenticode content does not parse: %w", err)
	}
	h, ok := digestHashes[spc.MessageDigest.Algorithm.Algorithm.String()]
	if !ok {
		return fmt.Errorf("digest algorithm %s is not supported", spc.MessageDigest.Algorithm.Algorithm)
	}
	img := h.New()
	writePEImage(img, b, optOff+64, dirOff, start, end)
	if !bytes.Equal(img.Sum(nil), spc.MessageDigest.Digest) {
		return ErrTampered
	}
	// The signed messageDigest attribute is over the content's value, without
	// its SEQUENCE tag and length (Authenticode's rule).
	sh, ok := digestHashes[pkixAlg(si.DigestAlgorithm).String()]
	if !ok {
		return fmt.Errorf("signer digest algorithm %s is not supported", pkixAlg(si.DigestAlgorithm))
	}
	if len(si.AuthAttrs.Bytes) == 0 {
		return errors.New("the signature has no signed attributes")
	}
	var md []byte
	for rest := si.AuthAttrs.Bytes; len(rest) > 0; {
		var a attribute
		if rest, err = asn1.Unmarshal(rest, &a); err != nil {
			return fmt.Errorf("the signed attributes do not parse: %w", err)
		}
		if a.Type.Equal(oidMessageDigest) {
			if _, err := asn1.Unmarshal(a.Values.Bytes, &md); err != nil {
				return fmt.Errorf("the messageDigest attribute does not parse: %w", err)
			}
		}
	}
	cd := sh.New()
	cd.Write(val.Bytes)
	if md == nil || !bytes.Equal(cd.Sum(nil), md) {
		return ErrTampered
	}
	// The signature is over the signed attributes, re-tagged as a SET.
	signed := append([]byte{}, si.AuthAttrs.FullBytes...)
	signed[0] = 0x31
	ad := sh.New()
	ad.Write(signed)
	switch pub := s.Leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		if rsa.VerifyPKCS1v15(pub, sh, ad.Sum(nil), si.EncryptedDigest) != nil {
			return ErrTampered
		}
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, ad.Sum(nil), si.EncryptedDigest) {
			return ErrTampered
		}
	default:
		return fmt.Errorf("a %T signing key is not supported", pub)
	}
	return nil
}

func pkixAlg(raw asn1.RawValue) asn1.ObjectIdentifier {
	var a pkix.AlgorithmIdentifier
	if _, err := asn1.Unmarshal(raw.FullBytes, &a); err != nil {
		return nil
	}
	return a.Algorithm
}

// signedParts parses the PKCS#7 SignedData of a certificate table entry.
func signedParts(der []byte) (signedData, signerInfo, error) {
	var ci contentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil || !ci.ContentType.Equal(oidSignedData) {
		return signedData{}, signerInfo{}, errNotSigned
	}
	inner := ci.Content.FullBytes
	if ci.Content.Class == asn1.ClassContextSpecific {
		inner = ci.Content.Bytes
	}
	var sd signedData
	if _, err := asn1.Unmarshal(inner, &sd); err != nil || len(sd.SignerInfos) != 1 {
		return signedData{}, signerInfo{}, errors.New("the signature is not one-signer PKCS#7 SignedData")
	}
	return sd, sd.SignerInfos[0], nil
}

// writePEImage feeds the Authenticode image hash: every byte of the file
// except the checksum, the certificate table's directory entry and the
// certificate table itself, in file order (the form osslsigncode and
// signtool compute for a table at the end of the file).
func writePEImage(w io.Writer, b []byte, sumOff, dirOff, start, end int) {
	_, _ = w.Write(b[:sumOff])
	_, _ = w.Write(b[sumOff+4 : dirOff])
	_, _ = w.Write(b[dirOff+8 : start])
	_, _ = w.Write(b[end:])
}
