package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/sangehq/imprimatur/src/internal/config"
)

type issued struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

// issue makes a certificate signed by parent (self-signed when parent is nil).
func issue(t *testing.T, cn string, parent *issued, isCA bool, usage x509.ExtKeyUsage) issued {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: isCA, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	if !isCA {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{usage}
	}
	signer, signerKey := tpl, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return issued{cert: c, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func keyPEM(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	b, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
}

func TestRemoteListenNeedsAllowRemoteAndTLS(t *testing.T) {
	d := filepath.ToSlash(t.TempDir())
	tlsFiles := &config.ServerTLS{CertFile: d + "/c.pem", KeyFile: d + "/k.pem", ClientCAFile: d + "/ca.pem"}
	for _, c := range []struct {
		s  config.Server
		ok bool
	}{
		{config.Server{Listen: "127.0.0.1:8743"}, true},
		{config.Server{Listen: "0.0.0.0:8743"}, false},
		{config.Server{Listen: "10.0.0.5:8743", AllowRemote: true}, false},
		{config.Server{Listen: "10.0.0.5:8743", TLS: tlsFiles}, false},
		{config.Server{Listen: "10.0.0.5:8743", AllowRemote: true, TLS: tlsFiles}, true},
		{config.Server{Listen: "127.0.0.1:8743", TLS: &config.ServerTLS{CertFile: "c.pem", KeyFile: d + "/k", ClientCAFile: d + "/ca"}}, false},
	} {
		ps := (config.Config{Schema: config.Schema, Server: c.s}).Validate()
		if (len(ps) == 0) != c.ok {
			t.Errorf("%+v: problems %v", c.s, ps)
		}
	}
}

// TestMutualTLS: a client without a certificate from the configured CA is
// refused during the handshake; one with it reaches the API.
func TestMutualTLS(t *testing.T) {
	dir := t.TempDir()
	ca := issue(t, "impr test CA", nil, true, 0)
	srv := issue(t, "impr", &ca, false, x509.ExtKeyUsageServerAuth)
	client := issue(t, "caller", &ca, false, x509.ExtKeyUsageClientAuth)
	other := issue(t, "other CA", nil, true, 0)
	stranger := issue(t, "stranger", &other, false, x509.ExtKeyUsageClientAuth)
	files := map[string][]byte{"cert.pem": srv.pem, "key.pem": keyPEM(t, srv.key), "ca.pem": ca.pem}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.ServerTLS{CertFile: filepath.Join(dir, "cert.pem"), KeyFile: filepath.Join(dir, "key.pem"), ClientCAFile: filepath.Join(dir, "ca.pem")}
	tc, err := serverTLS(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" { // Windows has no group or other mode bits
		if err := os.Chmod(cfg.KeyFile, 0o644); err != nil { //nolint:gosec // G302: the unsafe mode under test
			t.Fatal(err)
		}
		if _, err := serverTLS(cfg); err == nil {
			t.Fatal("a key file others can read was accepted")
		}
		if err := os.Chmod(cfg.KeyFile, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen here: %v", err)
	}
	hs := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = hs.Serve(tls.NewListener(ln, tc)) }()
	defer func() { _ = hs.Close() }()
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	get := func(c *issued) error {
		cc := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
		if c != nil {
			cc.Certificates = []tls.Certificate{{Certificate: [][]byte{c.cert.Raw}, PrivateKey: c.key}}
		}
		resp, err := (&http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: cc}}).Get("https://" + ln.Addr().String() + "/")
		if err == nil {
			_ = resp.Body.Close()
		}
		return err
	}
	if err := get(nil); err == nil {
		t.Fatal("a client with no certificate was served")
	}
	if err := get(&stranger); err == nil {
		t.Fatal("a client certificate from another CA was served")
	}
	if err := get(&client); err != nil {
		t.Fatalf("a client with the right certificate: %v", err)
	}
}
