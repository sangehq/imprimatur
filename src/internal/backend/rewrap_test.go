package backend

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sangehq/imprimatur/src/internal/execx"
)

// TestRewrapWithRealOpenSSL re-wraps an AES-encrypted .p12 (OpenSSL 3's
// default) with the openssl on this host, and checks the result opens with
// the one-time password, still holds the key, and that the decrypted PEM is
// gone afterwards.
func TestRewrapWithRealOpenSSL(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("real openssl: not installed")
	}
	dir := t.TempDir()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "impr rewrap test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalPKCS8PrivateKey(k)
	in := filepath.Join(dir, "in.pem")
	b := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd})...)
	if err := os.WriteFile(in, b, 0o600); err != nil {
		t.Fatal(err)
	}
	pw := randHex(t, 8)
	p12 := filepath.Join(dir, "id.p12")
	cmd := exec.Command("openssl", "pkcs12", "-export", "-in", in, "-out", p12, "-passout", "env:TEST_PW")
	cmd.Env = append(os.Environ(), "TEST_PW="+pw)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("make the .p12: %v %s", err, out)
	}

	work := t.TempDir()
	otp := randHex(t, 12)
	a := &Apple{H: Host{GOOS: runtime.GOOS, Runner: execx.OS{Timeout: time.Minute}, Now: time.Now}}
	got, err := a.rewrap(context.Background(), work, p12, pw, otp)
	if err != nil {
		t.Fatalf("rewrap: %v", err)
	}
	if _, err := os.Stat(filepath.Join(work, "identity.pem")); !os.IsNotExist(err) {
		t.Fatal("the decrypted PEM was left behind")
	}
	check := exec.Command("openssl", "pkcs12", "-in", got, "-nodes", "-passin", "env:TEST_PW")
	check.Env = append(os.Environ(), "TEST_PW="+otp)
	out, err := check.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "PRIVATE KEY") || !strings.Contains(string(out), "impr rewrap test") {
		t.Fatalf("the re-wrapped .p12 does not open with the one-time password: %v %s", err, out)
	}
	// The wrong password is refused, as a wrong passwordRef should be.
	if _, err := a.rewrap(context.Background(), t.TempDir(), p12, "wrong", otp); err == nil {
		t.Fatal("a wrong .p12 password was accepted")
	}
}
