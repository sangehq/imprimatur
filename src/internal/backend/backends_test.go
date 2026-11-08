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
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/execx"
	"github.com/sangehq/imprimatur/src/internal/profile"
	"github.com/sangehq/imprimatur/src/internal/secrets"
)

func randHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return strings.ToUpper(hex.EncodeToString(b))
}

func fakeHost(goos string, f *execx.Fake, env map[string]string) Host {
	get := func(k string) string { return env[k] }
	return Host{GOOS: goos, Runner: f, Now: time.Now, Secrets: secrets.Resolver{Runner: f, Getenv: get, GOOS: goos}}
}

func wantCode(t *testing.T, err error, code contract.Code) {
	t.Helper()
	if contract.CodeOf(err) != code {
		t.Fatalf("want exit %d (%s), got %v (%d)", code, code, err, contract.CodeOf(err))
	}
}

// ---- Authenticode ------------------------------------------------------------

func winProfile(spec profile.WindowsSpec, purpose profile.Purpose) profile.Profile {
	return profile.Profile{Name: "win", Scope: profile.ScopePersonal, Owner: "me", Purpose: []profile.Purpose{purpose},
		Platforms: profile.Platforms{Windows: &spec}}
}

func TestAuthenticodeCertStoreSignsOnlyWithThePinnedThumbprint(t *testing.T) {
	subject := pkix.Name{CommonName: "Pat Doe Code Signing (Test)"}
	path, thumb := signedPE(t, t.TempDir(), subject, true)
	f := execx.NewFake("signtool")
	h := fakeHost("windows", f, nil)
	spec := profile.WindowsSpec{Kind: "authenticode", Backend: profile.BackendCertStore, Thumbprint: thumb}
	a := &Authenticode{H: h, Spec: spec}
	sig, err := a.Sign(context.Background(), Artifact{Path: path, Rel: "tool.exe"}, winProfile(spec, profile.PurposeTest))
	if err != nil {
		t.Fatal(err)
	}
	if !f.Called("signtool", "/sha1 "+thumb) || sig.Signer != "CN=Pat Doe Code Signing (Test)" {
		t.Fatalf("calls %+v, signer %q", f.Calls, sig.Signer)
	}

	// Subject only: refused before signtool runs.
	f2 := execx.NewFake("signtool")
	b := &Authenticode{H: fakeHost("windows", f2, nil), Spec: profile.WindowsSpec{Kind: "authenticode", Backend: profile.BackendCertum, Subject: "CN=x"}}
	_, err = b.Sign(context.Background(), Artifact{Path: path, Rel: "tool.exe"}, winProfile(b.Spec, profile.PurposeTest))
	wantCode(t, err, contract.SignFailed)
	if len(f2.Calls) != 0 {
		t.Fatal("signtool ran for a subject-only pin")
	}

	// Another certificate than the pin: verification fails.
	c := &Authenticode{H: h, Spec: profile.WindowsSpec{Kind: "authenticode", Backend: profile.BackendCertStore, Thumbprint: randHex(t, 20)}}
	wantCode(t, c.Verify(context.Background(), Artifact{Path: path, Rel: "tool.exe"}, winProfile(c.Spec, profile.PurposeTest)), contract.VerifyFailed)

	// signtool off Windows: unavailable.
	d := &Authenticode{H: fakeHost("darwin", execx.NewFake(), nil), Spec: spec}
	_, err = d.Sign(context.Background(), Artifact{Path: path, Rel: "tool.exe"}, winProfile(spec, profile.PurposeTest))
	wantCode(t, err, contract.Unavailable)
}

func TestAuthenticodeVerifyAcceptsAnUntrustedRootOnlyForTests(t *testing.T) {
	path, thumb := signedPE(t, t.TempDir(), pkix.Name{CommonName: "Test"}, true)
	f := execx.NewFake("osslsigncode")
	f.Handle = func(c execx.Cmd) execx.Result {
		return execx.Result{ExitCode: 1, Stderr: []byte("unable to get local issuer certificate")}
	}
	spec := profile.WindowsSpec{Kind: "authenticode", Backend: profile.BackendPFX, CertRef: "env://PFX", Thumbprint: thumb}
	a := &Authenticode{H: fakeHost("linux", f, nil), Spec: spec}
	if err := a.Verify(context.Background(), Artifact{Path: path, Rel: "tool.exe"}, winProfile(spec, profile.PurposeTest)); err != nil {
		t.Fatalf("a test profile should accept an untrusted test root: %v", err)
	}
	wantCode(t, a.Verify(context.Background(), Artifact{Path: path, Rel: "tool.exe"}, winProfile(spec, profile.PurposeInternal)), contract.VerifyFailed)
	untimed, _ := signedPE(t, t.TempDir(), pkix.Name{CommonName: "Test"}, false)
	wantCode(t, a.Verify(context.Background(), Artifact{Path: untimed, Rel: "tool.exe"}, winProfile(spec, profile.PurposeTest)), contract.VerifyFailed)
}

func TestAuthenticodePFXPasswordNeverReachesTheCommandLine(t *testing.T) {
	dir := t.TempDir()
	signed, thumb := signedPE(t, dir, pkix.Name{CommonName: "Acme"}, true)
	signedBytes, _ := os.ReadFile(signed)
	unsigned := filepath.Join(dir, "app.exe")
	if err := os.WriteFile(unsigned, []byte("MZ unsigned"), 0o600); err != nil {
		t.Fatal(err)
	}
	pfx := filepath.Join(dir, "cert.pfx")
	if err := os.WriteFile(pfx, []byte(randHex(t, 16)), 0o600); err != nil {
		t.Fatal(err)
	}
	password := randHex(t, 12)
	f := execx.NewFake("osslsigncode")
	f.Handle = func(c execx.Cmd) execx.Result {
		if c.Args[0] == "sign" {
			out := c.Args[len(c.Args)-1]
			_ = os.WriteFile(out, signedBytes, 0o600)
		}
		return execx.Result{}
	}
	spec := profile.WindowsSpec{Kind: "authenticode", Backend: profile.BackendPFX, CertRef: "env://IMPR_PFX", PasswordRef: "env://IMPR_PFX_PW", Thumbprint: thumb}
	a := &Authenticode{H: fakeHost("darwin", f, map[string]string{"IMPR_PFX": pfx, "IMPR_PFX_PW": password}), Spec: spec}
	if _, err := a.Sign(context.Background(), Artifact{Path: unsigned, Rel: "app.exe"}, winProfile(spec, profile.PurposeInternal)); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Calls {
		if strings.Contains(strings.Join(c.Args, " "), password) {
			t.Fatal("the pfx password was passed on a command line")
		}
	}
	if !f.Called("osslsigncode", "-readpass") {
		t.Fatal("the password was not passed by file")
	}
}

// ---- Apple ---------------------------------------------------------------------

func macSpec() profile.MacOSSpec {
	return profile.MacOSSpec{Kind: "developer-id", TeamID: "ABCDE12345", Identity: "Developer ID Application: Acme Ltd (ABCDE12345)",
		Notary: &profile.NotarySpec{APIKeyRef: "env://IMPR_NOTARY_KEY", KeyID: "env://IMPR_NOTARY_KEY_ID", Issuer: "env://IMPR_NOTARY_ISSUER"}}
}

func TestAppleChecksThePinnedTeamAndIdentity(t *testing.T) {
	file := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(file, []byte{0xcf, 0xfa, 0xed, 0xfe}, 0o600); err != nil {
		t.Fatal(err)
	}
	team := "ABCDE12345"
	f := execx.NewFake("codesign", "xcrun", "ditto", "spctl")
	f.Handle = func(c execx.Cmd) execx.Result {
		if c.Tool == "codesign" && c.Args[0] == "-d" {
			return execx.Result{Stderr: []byte("Authority=Developer ID Application: Acme Ltd (ABCDE12345)\nTeamIdentifier=" + team + "\n")}
		}
		if c.Tool == "xcrun" && c.Args[0] == "notarytool" {
			return execx.Result{Stdout: []byte(`{"id":"sub-123","status":"Accepted"}`)}
		}
		return execx.Result{}
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte(randHex(t, 16))})
	env := map[string]string{"IMPR_NOTARY_KEY": string(keyPEM), "IMPR_NOTARY_KEY_ID": randHex(t, 5), "IMPR_NOTARY_ISSUER": randHex(t, 8)}
	a := &Apple{H: fakeHost("darwin", f, env), Spec: macSpec()}
	p := profile.Profile{Name: "mac", Platforms: profile.Platforms{MacOS: &a.Spec}}
	art := Artifact{Path: file, Rel: "tool"}
	if _, err := a.Sign(context.Background(), art, p); err != nil {
		t.Fatal(err)
	}
	if !f.Called("codesign", "--options runtime --timestamp --sign Developer ID Application: Acme Ltd (ABCDE12345)") {
		t.Fatalf("codesign calls: %+v", f.Calls)
	}
	ticket, err := a.Notarize(context.Background(), []Artifact{art})
	if err != nil || ticket != "sub-123" {
		t.Fatalf("ticket %q, %v", ticket, err)
	}
	for _, c := range f.Calls {
		if strings.Contains(strings.Join(c.Args, " "), "PRIVATE KEY") {
			t.Fatal("the notary key reached a command line")
		}
	}
	team = "ZZZZZ99999"
	wantCode(t, a.Verify(context.Background(), art, p), contract.VerifyFailed)
	f.Handle = func(c execx.Cmd) execx.Result {
		if c.Tool == "xcrun" {
			return execx.Result{ExitCode: 1, Stdout: []byte(`{"id":"sub-9","status":"Invalid"}`)}
		}
		return execx.Result{}
	}
	_, err = a.Notarize(context.Background(), []Artifact{art})
	wantCode(t, err, contract.SignFailed)
}

// TestAppleRealCodesign runs the real codesign against this test binary,
// which the Go linker signs ad hoc on Apple silicon: it has no team, so the
// pinned team check must fail.
func TestAppleRealCodesign(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("real codesign: not a macOS host")
	}
	if _, err := exec.LookPath("codesign"); err != nil {
		t.Skip("real codesign: codesign is not installed")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	h := Host{GOOS: "darwin", Runner: execx.OS{Timeout: time.Minute}, Now: time.Now}
	a := &Apple{H: h, Spec: macSpec()}
	err = a.Verify(context.Background(), Artifact{Path: self, Rel: "test binary"}, profile.Profile{})
	if runtime.GOARCH == "arm64" {
		wantCode(t, err, contract.VerifyFailed)
		if !strings.Contains(err.Error(), "not the pinned ABCDE12345") {
			t.Fatalf("want the team mismatch, got %v", err)
		}
	} else if err == nil {
		t.Fatal("an unsigned binary verified")
	}
	// The pinned identity is not in any keychain here: not present.
	if e := a.Certificate(context.Background(), profile.Profile{Name: "mac"}); e.Present {
		t.Fatalf("a made-up identity was found in the keychain: %+v", e)
	}
}

// ---- SSH (real ssh-keygen) -----------------------------------------------------

func sshKey(t *testing.T, dir, name string) (path, fingerprint string) {
	t.Helper()
	path = filepath.Join(dir, name)
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "impr-test", "-f", path).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v %s", err, out)
	}
	out, err := exec.Command("ssh-keygen", "-l", "-E", "sha256", "-f", path).Output()
	if err != nil {
		t.Fatal(err)
	}
	return path, strings.Fields(string(out))[1]
}

func TestSSHRealSignAndVerify(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("real ssh-keygen: not installed")
	}
	dir := t.TempDir()
	key, fp := sshKey(t, dir, "release")
	other, otherFP := sshKey(t, dir, "other")
	sums := filepath.Join(dir, "SHA256SUMS")
	if err := os.WriteFile(sums, []byte(randHex(t, 32)+"  build/tool\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"IMPR_SSH_KEY": key, "IMPR_OTHER_KEY": other}
	h := Host{GOOS: runtime.GOOS, Runner: execx.OS{Timeout: time.Minute}, Now: time.Now,
		Secrets: secrets.Resolver{Getenv: func(k string) string { return env[k] }}}
	spec := profile.ChecksumSpec{Kind: "ssh", KeyRef: "env://IMPR_SSH_KEY", Fingerprint: fp}
	s := &SSH{H: h, Spec: spec}
	art := Artifact{Path: sums, Rel: "SHA256SUMS"}
	sig, err := s.Sign(context.Background(), art, profile.Profile{Name: "ssh"})
	if err != nil {
		t.Fatal(err)
	}
	if len(sig.Outputs) != 1 || sig.Signer != fp {
		t.Fatalf("signature: %+v", sig)
	}
	if e := s.Certificate(context.Background(), profile.Profile{Name: "ssh"}); !e.Present {
		t.Fatal("the pinned key was not reported present")
	}

	// A key that is not the pinned one: refused before signing.
	wrong := &SSH{H: h, Spec: profile.ChecksumSpec{Kind: "ssh", KeyRef: "env://IMPR_OTHER_KEY", Fingerprint: fp}}
	_, err = wrong.Sign(context.Background(), art, profile.Profile{Name: "ssh"})
	wantCode(t, err, contract.SignFailed)

	// The pinned key's signature does not verify for a profile pinning another.
	wantCode(t, (&SSH{H: h, Spec: profile.ChecksumSpec{Kind: "ssh", Fingerprint: otherFP}}).Verify(context.Background(), art, profile.Profile{}), contract.VerifyFailed)

	// A changed file does not verify.
	if err := os.WriteFile(sums, []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantCode(t, s.Verify(context.Background(), art, profile.Profile{}), contract.VerifyFailed)
}

// ---- GPG, minisign, cosign: fake runner, real tool when present ------------------

func TestGPGVerifiesThePinnedKey(t *testing.T) {
	fpr := randHex(t, 20)
	f := execx.NewFake("gpg")
	f.Handle = func(c execx.Cmd) execx.Result {
		if slicesContains(c.Args, "--verify") {
			return execx.Result{Stdout: []byte(fmt.Sprintf("[GNUPG:] GOODSIG X\n[GNUPG:] VALIDSIG %s 2026-11-07 1 0 4 0 1 10 00 %s\n", fpr, fpr))}
		}
		return execx.Result{}
	}
	spec := profile.ChecksumSpec{Kind: "gpg", KeyRef: "gpg-agent://" + fpr, Fingerprint: fpr}
	g := &GPG{H: fakeHost("linux", f, nil), Spec: spec}
	if _, err := g.Sign(context.Background(), Artifact{Path: "/x/SHA256SUMS", Rel: "SHA256SUMS"}, profile.Profile{Name: "g"}); err != nil {
		t.Fatal(err)
	}
	if !f.Called("gpg", "--local-user "+fpr) {
		t.Fatal("gpg was not told to use the pinned key")
	}
	g.Spec.Fingerprint = randHex(t, 20)
	wantCode(t, g.Verify(context.Background(), Artifact{Path: "/x/SHA256SUMS"}, profile.Profile{}), contract.VerifyFailed)
	g.Spec.KeyRef = "env://GPG_KEY"
	_, err := g.Sign(context.Background(), Artifact{Path: "/x/SHA256SUMS"}, profile.Profile{Name: "g"})
	wantCode(t, err, contract.Usage)
}

func slicesContains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func TestMinisignKeyIDAndPin(t *testing.T) {
	raw := make([]byte, 42)
	copy(raw, "Ed")
	id := uint64(0x0123456789ABCDEF)
	binary.LittleEndian.PutUint64(raw[2:10], id)
	if _, err := rand.Read(raw[10:]); err != nil {
		t.Fatal(err)
	}
	pub := base64.StdEncoding.EncodeToString(raw)
	got, err := MinisignKeyID(pub)
	if err != nil || got != "0123456789ABCDEF" {
		t.Fatalf("key id %q %v", got, err)
	}
	m := &Minisign{H: fakeHost("linux", execx.NewFake("minisign"), nil), Spec: profile.ChecksumSpec{Kind: "minisign", PublicKey: pub, Fingerprint: randHex(t, 8)}}
	wantCode(t, m.Preflight(context.Background(), profile.Profile{}), contract.SignFailed)
	m.Spec.Fingerprint = got
	if err := m.Preflight(context.Background(), profile.Profile{}); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("minisign"); err != nil {
		t.Log("real minisign: not installed; covered through the fake runner only")
	}
}

func TestCosignKeyPinAndKeylessArgs(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pubPath := filepath.Join(t.TempDir(), "cosign.pub")
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	f := execx.NewFake("cosign")
	c := &Cosign{H: fakeHost("linux", f, map[string]string{"COSIGN_KEY": "x"}),
		Spec: profile.ContainerSpec{Kind: "cosign", Mode: "key", KeyRef: "env://COSIGN_KEY", KeyFingerprint: hex.EncodeToString(sum[:]), PublicKey: pubPath}}
	if _, err := c.Sign(context.Background(), Artifact{Path: "/x/SHA256SUMS"}, profile.Profile{}); err != nil {
		t.Fatal(err)
	}
	if !f.Called("cosign", "--key env://COSIGN_KEY") || !f.Called("cosign", "verify-blob --bundle /x/SHA256SUMS.sigstore.json --key "+pubPath) {
		t.Fatalf("calls: %+v", f.Calls)
	}
	c.Spec.KeyFingerprint = randHex(t, 32)
	wantCode(t, c.Preflight(context.Background(), profile.Profile{}), contract.SignFailed)

	k := &Cosign{H: fakeHost("linux", f, nil), Spec: profile.ContainerSpec{Kind: "cosign", Mode: "keyless", Identity: "release@acme.example", Issuer: "https://token.actions.githubusercontent.com"}}
	if err := k.Verify(context.Background(), Artifact{Path: "/x/SHA256SUMS"}, profile.Profile{}); err != nil {
		t.Fatal(err)
	}
	if !f.Called("cosign", "--certificate-identity release@acme.example --certificate-oidc-issuer https://token.actions.githubusercontent.com") {
		t.Fatal("keyless verification does not pin the identity and issuer")
	}
	if _, err := exec.LookPath("cosign"); err != nil {
		t.Log("real cosign: not installed; covered through the fake runner only")
	}
}

func TestAttestationsAreUnavailable(t *testing.T) {
	b, err := For(Host{}, profile.Profile{Platforms: profile.Platforms{Attestations: &profile.AttestationSpec{Kind: "in-toto", Signer: "checksums"}}}, profile.Attestations)
	if err != nil {
		t.Fatal(err)
	}
	if b.Capability(Host{}).Sign {
		t.Fatal("in-toto claims it can sign")
	}
	_, err = b.Sign(context.Background(), Artifact{}, profile.Profile{})
	wantCode(t, err, contract.Unavailable)
}

// ---- real tools that may be absent: each skips with the reason ----------------

func realTool(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("real %s: not installed on this host; the backend is covered through the fake runner", name)
	}
}

func TestGPGReal(t *testing.T) {
	realTool(t, "gpg")
	home := t.TempDir()
	t.Setenv("GNUPGHOME", home)
	if out, err := exec.Command("gpg", "--batch", "--passphrase", "", "--quick-gen-key", "impr-test@example.invalid", "ed25519", "sign", "1d").CombinedOutput(); err != nil {
		t.Skipf("real gpg: cannot make a throwaway key here: %v %s", err, out)
	}
	out, _ := exec.Command("gpg", "--batch", "--with-colons", "--list-secret-keys").Output()
	var fpr string
	for _, l := range strings.Split(string(out), "\n") {
		if f := strings.Split(l, ":"); len(f) > 9 && f[0] == "fpr" && fpr == "" {
			fpr = f[9]
		}
	}
	sums := filepath.Join(t.TempDir(), "SHA256SUMS")
	_ = os.WriteFile(sums, []byte(randHex(t, 32)+"  tool\n"), 0o600)
	g := &GPG{H: Host{GOOS: runtime.GOOS, Runner: execx.OS{Timeout: time.Minute}, Now: time.Now}, Spec: profile.ChecksumSpec{Kind: "gpg", KeyRef: "gpg-agent://" + fpr, Fingerprint: fpr}}
	if _, err := g.Sign(context.Background(), Artifact{Path: sums, Rel: "SHA256SUMS"}, profile.Profile{Name: "g"}); err != nil {
		t.Fatal(err)
	}
	if e := g.Certificate(context.Background(), profile.Profile{Name: "g"}); !e.Present || e.NotAfter == nil {
		t.Fatalf("certificate: %+v", e)
	}
}

func TestMinisignReal(t *testing.T) {
	realTool(t, "minisign")
	dir := t.TempDir()
	pub, sec := filepath.Join(dir, "k.pub"), filepath.Join(dir, "k.key")
	if out, err := exec.Command("minisign", "-G", "-W", "-p", pub, "-s", sec).CombinedOutput(); err != nil {
		t.Fatalf("minisign -G: %v %s", err, out)
	}
	b, _ := os.ReadFile(pub)
	line := strings.TrimSpace(strings.Split(string(b), "\n")[1])
	id, _ := MinisignKeyID(line)
	sums := filepath.Join(dir, "SHA256SUMS")
	_ = os.WriteFile(sums, []byte(randHex(t, 32)+"  tool\n"), 0o600)
	env := map[string]string{"IMPR_MINISIGN_KEY": sec}
	m := &Minisign{H: Host{GOOS: runtime.GOOS, Runner: execx.OS{Timeout: time.Minute}, Now: time.Now, Secrets: secrets.Resolver{Getenv: func(k string) string { return env[k] }}},
		Spec: profile.ChecksumSpec{Kind: "minisign", KeyRef: "env://IMPR_MINISIGN_KEY", Fingerprint: id, PublicKey: line}}
	if _, err := m.Sign(context.Background(), Artifact{Path: sums, Rel: "SHA256SUMS"}, profile.Profile{}); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(sums, []byte("tampered\n"), 0o600)
	wantCode(t, m.Verify(context.Background(), Artifact{Path: sums, Rel: "SHA256SUMS"}, profile.Profile{}), contract.VerifyFailed)
}

func TestCosignReal(t *testing.T) {
	realTool(t, "cosign")
	t.Skip("real cosign: a key-mode run uploads to the public transparency log; not run from unit tests")
}
