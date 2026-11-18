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
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
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
	g.Spec.KeyRef = "keychain://GPG_KEY" // not gpg-agent://, secret:// or env://
	_, err := g.Sign(context.Background(), Artifact{Path: "/x/SHA256SUMS"}, profile.Profile{Name: "g"})
	wantCode(t, err, contract.Usage)

	// A revoked key, an expired signature or a non-zero exit fails even with
	// a VALIDSIG line for the pinned key; a longer fingerprint that merely ends
	// in a full pin does not match.
	g.Spec = spec
	for name, out := range map[string]execx.Result{
		"revoked key":   {Stdout: []byte(fmt.Sprintf("[GNUPG:] REVKEYSIG X\n[GNUPG:] VALIDSIG %s x\n", fpr))},
		"expired sig":   {Stdout: []byte(fmt.Sprintf("[GNUPG:] EXPSIG X\n[GNUPG:] VALIDSIG %s x\n", fpr))},
		"non-zero exit": {Stdout: []byte(fmt.Sprintf("[GNUPG:] VALIDSIG %s x\n", fpr)), ExitCode: 2},
		"suffix only":   {Stdout: []byte(fmt.Sprintf("[GNUPG:] VALIDSIG %s x\n", "AB"+fpr))},
	} {
		f.Handle = func(execx.Cmd) execx.Result { return out }
		if err := g.Verify(context.Background(), Artifact{Path: "/x/SHA256SUMS", Rel: "SHA256SUMS"}, profile.Profile{}); contract.CodeOf(err) != contract.VerifyFailed {
			t.Errorf("%s: %v, want verification failed", name, err)
		}
	}
}

func TestPEOversizedCertificateTableIsRefused(t *testing.T) {
	// A minimal PE32+ whose security directory claims 1 GiB at offset 0x200.
	b := make([]byte, 0x400)
	copy(b, "MZ")
	binary.LittleEndian.PutUint32(b[0x3c:], 0x80)
	copy(b[0x80:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(b[0x84:], 0x8664) // machine
	binary.LittleEndian.PutUint16(b[0x94:], 240)    // SizeOfOptionalHeader
	opt := 0x98
	binary.LittleEndian.PutUint16(b[opt:], 0x20b)           // PE32+
	binary.LittleEndian.PutUint32(b[opt+108:], 16)          // NumberOfRvaAndSizes
	binary.LittleEndian.PutUint32(b[opt+112+4*8:], 0x200)   // security dir VirtualAddress
	binary.LittleEndian.PutUint32(b[opt+112+4*8+4:], 1<<30) // and Size
	path := filepath.Join(t.TempDir(), "big.exe")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPESigner(path); err == nil || !strings.Contains(err.Error(), "does not fit") {
		t.Fatalf("want a size refusal, got %v", err)
	}
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

// Audit N-B5: two files with the same base name in different directories
// are both staged for notarisation, not one over the other.
func TestNotarizeStagesSameNamedFilesApart(t *testing.T) {
	root := t.TempDir()
	var arts []Artifact
	for _, d := range []string{"amd64", "arm64"} {
		p := filepath.Join(root, d, "tool")
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte{0xcf, 0xfa, 0xed, 0xfe, d[0], d[1]}, 0o600); err != nil {
			t.Fatal(err)
		}
		arts = append(arts, Artifact{Path: p, Rel: d + "/tool"})
	}
	staged := 0
	f := execx.NewFake("ditto", "xcrun")
	f.Handle = func(c execx.Cmd) execx.Result {
		if c.Tool == "ditto" {
			_ = filepath.WalkDir(c.Args[3], func(_ string, de os.DirEntry, _ error) error {
				if de != nil && de.Type().IsRegular() {
					staged++
				}
				return nil
			})
		}
		if c.Tool == "xcrun" {
			return execx.Result{Stdout: []byte(`{"id":"sub-1","status":"Accepted"}`)}
		}
		return execx.Result{}
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte(randHex(t, 16))})
	a := &Apple{H: fakeHost("darwin", f, map[string]string{"IMPR_NOTARY_KEY": string(keyPEM), "IMPR_NOTARY_KEY_ID": randHex(t, 5), "IMPR_NOTARY_ISSUER": randHex(t, 8)}), Spec: macSpec()}
	if _, err := a.Notarize(context.Background(), arts); err != nil {
		t.Fatal(err)
	}
	if staged != 2 {
		t.Fatalf("staged %d files, want 2", staged)
	}
}

// Audit N-B4: Gatekeeper is asked the question that fits each format.
func TestSpctlArgsPerFormat(t *testing.T) {
	for path, want := range map[string]string{
		"/x/tool": "-a -t exec -vv /x/tool", "/x/App.dmg": "-a -t open --context context:primary-signature -vv /x/App.dmg",
		"/x/Setup.PKG": "-a -t install -vv /x/Setup.PKG",
	} {
		if got := strings.Join(spctlArgs(path), " "); got != want {
			t.Errorf("%s: %s", path, got)
		}
	}
}

// Audit N-B16: a relative cosign public key resolves against the signing root.
func TestCosignPublicKeyIsRootRelative(t *testing.T) {
	c := &Cosign{H: Host{Root: "/builds/tool"}, Spec: profile.ContainerSpec{PublicKey: "keys/cosign.pub"}}
	if got := c.publicKey(); got != filepath.Join("/builds/tool", "keys", "cosign.pub") {
		t.Fatalf("publicKey %s", got)
	}
	abs := filepath.Join(t.TempDir(), "cosign.pub")
	c.Spec.PublicKey = abs
	if c.publicKey() != abs {
		t.Fatal("an absolute path changed")
	}
}

// Audit N-B10: an SSH key's fingerprint for `cert list` is read from the
// OpenSSH header in Go and equals ssh-keygen's, so the key need not be
// written anywhere to report it present.
func TestOpenSSHPublicFingerprintMatchesSSHKeygen(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("real ssh-keygen: not installed")
	}
	key := filepath.Join(t.TempDir(), "k")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	out, _ := exec.Command("ssh-keygen", "-l", "-E", "sha256", "-f", key).Output()
	want := strings.Fields(string(out))[1]
	text, _ := os.ReadFile(key)
	got, err := OpenSSHPublicFingerprint(string(text))
	if err != nil || got != want {
		t.Fatalf("fingerprint %s %v, ssh-keygen %s", got, err, want)
	}
	if _, err := OpenSSHPublicFingerprint("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"); err == nil {
		t.Fatal("a truncated key was read")
	}
}

// Audit N-B13: a test certificate may fail verification only on an
// untrusted root, never on a digest mismatch, expiry or revocation.
func TestUntrustedRootOnly(t *testing.T) {
	for out, want := range map[string]bool{
		"SignTool Error: A certificate chain processed, but terminated in a root certificate which is not trusted by the trust provider.": true,
		"Signature verification: failed\nself-signed certificate in certificate chain":                                                    true,
		"Message digest MISMATCH; self-signed certificate in certificate chain":                                                           false,
		"the certificate has expired; unable to get local issuer certificate":                                                             false,
		"SignTool Error: The signature is invalid.":                                                                                       false,
		"untrusted": false,
	} {
		if got := untrustedRootOnly(out); got != want {
			t.Errorf("%q: %v, want %v", out, got, want)
		}
	}
}

// A gpg key held in a secret is imported into a throwaway gpg home for the
// run: every gpg call names that home, the key goes in on stdin, the
// passphrase through a file, and the home is gone afterwards.
func TestGPGKeyFromASecretUsesAThrowawayHome(t *testing.T) {
	fpr := strings.ToUpper(randHex(t, 20))
	var homes []string
	var importedKey string
	f := execx.NewFake("gpg")
	f.Handle = func(c execx.Cmd) execx.Result {
		if len(c.Args) > 1 && c.Args[0] == "--homedir" {
			homes = append(homes, c.Args[1])
		}
		switch {
		case slicesContains(c.Args, "--import"):
			importedKey = string(c.Stdin)
		case slicesContains(c.Args, "--verify"):
			return execx.Result{Stdout: []byte("[GNUPG:] VALIDSIG " + fpr + " x\n")}
		}
		return execx.Result{}
	}
	key := "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" + randHex(t, 16) + "\n-----END PGP PRIVATE KEY BLOCK-----\n"
	g := &GPG{H: fakeHost("linux", f, map[string]string{"IMPR_GPG": key, "IMPR_GPG_PW": randHex(t, 8)}),
		Spec: profile.ChecksumSpec{Kind: "gpg", KeyRef: "env://IMPR_GPG", PasswordRef: "env://IMPR_GPG_PW", Fingerprint: fpr}}
	if _, err := g.Sign(context.Background(), Artifact{Path: "/x/SHA256SUMS", Rel: "SHA256SUMS"}, profile.Profile{Name: "g"}); err != nil {
		t.Fatal(err)
	}
	if importedKey != key {
		t.Fatal("the key did not reach gpg on stdin")
	}
	if len(homes) < 3 {
		t.Fatalf("gpg calls outside the throwaway home: %v", f.Calls)
	}
	for _, h := range homes {
		if h != homes[0] {
			t.Fatalf("more than one home: %v", homes)
		}
	}
	if _, err := os.Stat(homes[0]); err == nil {
		t.Fatal("the throwaway gpg home was left behind")
	}
	if !f.Called("gpg", "--pinentry-mode loopback --passphrase-file") {
		t.Fatalf("the passphrase was not given through a file: %+v", f.Calls)
	}
	for _, c := range f.Calls {
		if strings.Contains(strings.Join(c.Args, " "), "PRIVATE KEY") {
			t.Fatal("the key reached a command line")
		}
	}
}

// A .p12 in certRef is signed from a temporary keychain that is deleted
// afterwards, also when a step fails.
func TestAppleTemporaryKeychain(t *testing.T) {
	file := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(file, []byte{0xcf, 0xfa, 0xed, 0xfe}, 0o600); err != nil {
		t.Fatal(err)
	}
	p12 := filepath.Join(t.TempDir(), "id.p12")
	if err := os.WriteFile(p12, []byte(randHex(t, 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	failImport := false
	pw := randHex(t, 6)
	f := execx.NewFake("codesign", "security", "spctl", "xcrun", "ditto", "openssl")
	f.Handle = func(c execx.Cmd) execx.Result {
		if c.Tool == "security" && c.Args[0] == "import" && failImport {
			return execx.Result{ExitCode: 1, Stderr: []byte("bad password")}
		}
		if c.Tool == "codesign" && c.Args[0] == "-d" {
			return execx.Result{Stderr: []byte("Authority=Developer ID Application: Acme Ltd (ABCDE12345)\nTeamIdentifier=ABCDE12345\n")}
		}
		return execx.Result{}
	}
	spec := macSpec()
	spec.CertRef, spec.PasswordRef = "env://IMPR_P12", "env://IMPR_P12_PW"
	a := &Apple{H: fakeHost("darwin", f, map[string]string{"IMPR_P12": p12, "IMPR_P12_PW": pw}), Spec: spec}
	if _, err := a.Sign(context.Background(), Artifact{Path: file, Rel: "tool"}, profile.Profile{Name: "mac"}); err != nil {
		t.Fatal(err)
	}
	if !f.Called("openssl", "-passin env:IMPR_P12_IN") || !f.Called("openssl", "-export") || !f.Called("security", "create-keychain") ||
		!f.Called("security", "identity.p12 -k") || f.Called("security", "import "+p12) || !f.Called("codesign", "--keychain") ||
		!f.Called("security", "delete-keychain") {
		t.Fatalf("calls: %+v", f.Calls)
	}
	// The real password reaches openssl through its environment only, and no
	// command line anywhere.
	sawEnv := false
	for _, c := range f.Calls {
		if strings.Contains(strings.Join(c.Args, " "), pw) {
			t.Fatalf("the .p12 password is on a command line: %s %v", c.Tool, c.Args)
		}
		if c.Tool == "openssl" && slices.Contains(c.Env, "IMPR_P12_IN="+pw) {
			sawEnv = true
		}
	}
	if !sawEnv {
		t.Fatal("openssl was not given the password in its environment")
	}
	f.Calls = nil
	failImport = true
	_, err := a.Sign(context.Background(), Artifact{Path: file, Rel: "tool"}, profile.Profile{Name: "mac"})
	wantCode(t, err, contract.SignFailed)
	if !f.Called("security", "delete-keychain") || f.Called("codesign", "--sign") {
		t.Fatalf("a failed import must delete the keychain and sign nothing: %+v", f.Calls)
	}
}

func selfSigned(t *testing.T) (der []byte, notAfter time.Time) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	na := time.Now().Add(400 * 24 * time.Hour).UTC().Truncate(time.Second)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "store test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: na}
	der, err = x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return der, na
}

// The Windows store certificate's real expiry is read from the file
// certutil exports, not from locale-dependent text.
func TestStoreNotAfterIsReadFromTheExportedCertificate(t *testing.T) {
	der, na := selfSigned(t)
	f := execx.NewFake("certutil", "signtool")
	f.Handle = func(c execx.Cmd) execx.Result {
		if c.Args[1] == "-store" {
			_ = os.WriteFile(c.Args[len(c.Args)-1], der, 0o600)
		}
		return execx.Result{}
	}
	a := &Authenticode{H: fakeHost("windows", f, nil), Spec: profile.WindowsSpec{Kind: "authenticode", Backend: profile.BackendCertStore, Thumbprint: strings.ToUpper(sha1Hex(der))}}
	e := a.Certificate(context.Background(), profile.Profile{Name: "w"})
	if !e.Present || e.NotAfter == nil || !e.NotAfter.Equal(na) {
		t.Fatalf("entry %+v, want notAfter %s", e, na)
	}
	a.Spec.Thumbprint = strings.Repeat("A", 40) // the exported certificate is not the pinned one
	if e := a.Certificate(context.Background(), profile.Profile{Name: "w"}); e.NotAfter != nil {
		t.Fatalf("a different certificate's expiry was reported: %v", e.NotAfter)
	}
}

// Artifact Signing checks the Azure CLI is signed in when it is the
// credential, and skips the check for a service principal.
func TestAzureSignInCheck(t *testing.T) {
	dir := t.TempDir()
	dlib := filepath.Join(dir, "Azure.CodeSigning.Dlib.dll")
	meta := filepath.Join(dir, "metadata.json")
	_ = os.WriteFile(dlib, []byte("x"), 0o600)
	_ = os.WriteFile(meta, []byte(`{"Endpoint":"https://eus.codesigning.azure.net","CodeSigningAccountName":"a","CertificateProfileName":"p"}`), 0o600)
	exit := 1
	f := execx.NewFake("signtool", "az")
	f.Handle = func(c execx.Cmd) execx.Result {
		if c.Tool == "az" {
			return execx.Result{ExitCode: exit}
		}
		return execx.Result{}
	}
	spec := profile.WindowsSpec{Kind: "authenticode", Backend: profile.BackendAzure, Subject: "CN=Acme", DlibPath: dlib, MetadataPath: meta}
	a := &Authenticode{H: fakeHost("windows", f, nil), Spec: spec}
	wantCode(t, a.Preflight(context.Background(), profile.Profile{}), contract.Unavailable)
	exit = 0
	if err := a.Preflight(context.Background(), profile.Profile{}); err != nil {
		t.Fatal(err)
	}
	f.Calls, exit = nil, 1
	a = &Authenticode{H: fakeHost("windows", f, map[string]string{"AZURE_CLIENT_ID": "x"}), Spec: spec}
	if err := a.Preflight(context.Background(), profile.Profile{}); err != nil || f.Called("az", "account") {
		t.Fatalf("with a service principal: %v, calls %+v", err, f.Calls)
	}
}

func TestOsslKeyArgsSplitsAPEMBundle(t *testing.T) {
	der, _ := selfSigned(t)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kd, _ := x509.MarshalPKCS8PrivateKey(k)
	bundle := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) + string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}))
	args, done, err := osslKeyArgs(bundle)
	if err != nil || len(args) != 4 || args[0] != "-certs" || args[2] != "-key" {
		t.Fatalf("%v %v", args, err)
	}
	c, _ := os.ReadFile(args[1])
	kf, _ := os.ReadFile(args[3])
	if !strings.Contains(string(c), "CERTIFICATE") || strings.Contains(string(c), "PRIVATE") || !strings.Contains(string(kf), "PRIVATE KEY") {
		t.Fatal("the bundle was not split into certificate and key")
	}
	done()
	if _, err := os.Stat(args[3]); err == nil {
		t.Fatal("the key file was left behind")
	}
}

// Old security finding 2: the untrusted-root allowance of a test profile is
// taken only when the certificate is pinned by thumbprint. A subject alone
// is a name anyone can put in a self-signed certificate.
func TestAuthenticodeUntrustedRootNeedsAThumbprintPin(t *testing.T) {
	path, _ := signedPE(t, t.TempDir(), pkix.Name{CommonName: "Test"}, true)
	f := execx.NewFake("osslsigncode")
	f.Handle = func(c execx.Cmd) execx.Result {
		return execx.Result{ExitCode: 1, Stderr: []byte("unable to get local issuer certificate")}
	}
	spec := profile.WindowsSpec{Kind: "authenticode", Backend: profile.BackendPFX, CertRef: "env://PFX", Subject: "CN=Test"}
	a := &Authenticode{H: fakeHost("linux", f, nil), Spec: spec}
	err := a.Verify(context.Background(), Artifact{Path: path, Rel: "tool.exe"}, winProfile(spec, profile.PurposeTest))
	wantCode(t, err, contract.VerifyFailed)
	if !strings.Contains(err.Error(), "thumbprint") {
		t.Fatalf("the refusal does not say a thumbprint is needed: %v", err)
	}
}

// ID-22, O-136: a profile's timestamp may list several servers, comma
// separated; they are tried in order, as the PowerShell --timestamp list was.
func TestAuthenticodeTriesTheProfilesTimestampListInOrder(t *testing.T) {
	path, thumb := signedPE(t, t.TempDir(), pkix.Name{CommonName: "Acme"}, true)
	f := execx.NewFake("signtool")
	var tried []string
	f.Handle = func(c execx.Cmd) execx.Result {
		for i, a := range c.Args {
			if a == "/tr" {
				tried = append(tried, c.Args[i+1])
				if c.Args[i+1] == "http://ts-a.example" {
					return execx.Result{ExitCode: 1, Stderr: []byte("timestamp server unreachable")}
				}
			}
		}
		return execx.Result{}
	}
	spec := profile.WindowsSpec{Kind: "authenticode", Backend: profile.BackendCertStore, Thumbprint: thumb,
		Timestamp: "http://ts-a.example, http://ts-b.example,http://ts-c.example"}
	a := &Authenticode{H: fakeHost("windows", f, nil), Spec: spec}
	sig, err := a.Sign(context.Background(), Artifact{Path: path, Rel: "tool.exe"}, winProfile(spec, profile.PurposeTest))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(tried, " ") != "http://ts-a.example http://ts-b.example" || sig.Timestamp != "ts-b.example" {
		t.Fatalf("tried %v, used %q", tried, sig.Timestamp)
	}
}

// O-127: signtool failures the PowerShell toolkit explained are explained
// here too: a certificate in the store without its private key, and no
// certificate with the pinned thumbprint at all.
func TestAuthenticodeExplainsSigntoolFailures(t *testing.T) {
	path, thumb := signedPE(t, t.TempDir(), pkix.Name{CommonName: "Acme"}, true)
	for _, c := range []struct{ out, want string }{
		{"SignTool Error: The specified private key is not available.", "has no private key here"},
		{"SignTool Error: No certificates were found that met all the given criteria.", "no certificate with thumbprint " + thumb},
	} {
		f := execx.NewFake("signtool")
		f.Handle = func(execx.Cmd) execx.Result { return execx.Result{ExitCode: 1, Stderr: []byte(c.out)} }
		spec := profile.WindowsSpec{Kind: "authenticode", Backend: profile.BackendCertStore, Thumbprint: thumb, Timestamp: "http://ts.example"}
		a := &Authenticode{H: fakeHost("windows", f, nil), Spec: spec}
		_, err := a.Sign(context.Background(), Artifact{Path: path, Rel: "tool.exe"}, winProfile(spec, profile.PurposeTest))
		wantCode(t, err, contract.SignFailed)
		if !strings.Contains(contract.Text(err), c.want) {
			t.Errorf("%q: the error does not say %q:\n%s", c.out, c.want, contract.Text(err))
		}
	}
}

// W2: minisign signs and verifies through the runner (never run before),
// refuses a signature by another key, and reports its key as present when
// the reference resolves.
func TestMinisignSignVerifyAndCertificate(t *testing.T) {
	keyLine := func(id uint64) string {
		raw := make([]byte, 74)
		copy(raw, "Ed")
		binary.LittleEndian.PutUint64(raw[2:10], id)
		return base64.StdEncoding.EncodeToString(raw)
	}
	const id = uint64(0x1122334455667788)
	sigID := id
	f := execx.NewFake("minisign")
	f.Handle = func(c execx.Cmd) execx.Result {
		if c.Args[0] == "-S" {
			out := c.Args[len(c.Args)-1]
			_ = os.WriteFile(out, []byte("untrusted comment: test\n"+keyLine(sigID)+"\ntrusted comment: x\nAAAA\n"), 0o600)
		}
		return execx.Result{}
	}
	dir := t.TempDir()
	art := Artifact{Path: filepath.Join(dir, "SHA256SUMS"), Rel: "SHA256SUMS"}
	if err := os.WriteFile(art.Path, []byte("x  y\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "minisign.key")
	if err := os.WriteFile(keyFile, []byte("untrusted comment: minisign secret key\nRWQ"+randHex(t, 20)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := &Minisign{H: fakeHost("linux", f, map[string]string{"MK": keyFile}),
		Spec: profile.ChecksumSpec{Kind: "minisign", KeyRef: "env://MK", PublicKey: keyLine(id), Fingerprint: fmt.Sprintf("%016X", id)}}
	sig, err := m.Sign(context.Background(), art, profile.Profile{})
	if err != nil || sig.Kind != "minisign" || len(sig.Outputs) != 1 {
		t.Fatalf("sign: %+v %v", sig, err)
	}
	if !f.Called("minisign", "-V -P") {
		t.Fatal("sign did not verify with the pinned public key")
	}
	if c := m.Certificate(context.Background(), profile.Profile{Name: "p"}); !c.Present || c.Fingerprint != fmt.Sprintf("%016X", id) {
		t.Fatalf("certificate: %+v", c)
	}
	sigID = 0x99 // the next signature is by another key
	_, err = m.Sign(context.Background(), art, profile.Profile{})
	wantCode(t, err, contract.VerifyFailed)
	m.Spec.KeyRef = "env://UNSET"
	if c := m.Certificate(context.Background(), profile.Profile{Name: "p"}); c.Present {
		t.Fatal("an unresolved key reads as present")
	}
}

// W2: cosign's certificate entry: a key is declared by fingerprint, keyless
// names the identity and issuer.
func TestCosignCertificate(t *testing.T) {
	c := &Cosign{H: fakeHost("linux", execx.NewFake("cosign"), nil), Spec: profile.ContainerSpec{Kind: "cosign", Mode: "keyless",
		Identity: "release@acme.example", Issuer: "https://token.actions.githubusercontent.com"}}
	if e := c.Certificate(context.Background(), profile.Profile{Name: "p"}); !e.Present || e.Subject != "release@acme.example@https://token.actions.githubusercontent.com" {
		t.Fatalf("keyless: %+v", e)
	}
	c.Spec = profile.ContainerSpec{Kind: "cosign", Mode: "key", KeyRef: "env://NOPE", KeyFingerprint: "ab"}
	if e := c.Certificate(context.Background(), profile.Profile{Name: "p"}); e.Fingerprint != "ab" || e.Platform != profile.Containers {
		t.Fatalf("key: %+v", e)
	}
}

// O-133 to O-135: with no timestamp in the profile, each backend tries the
// PowerShell line's servers, in order.
func TestDefaultTimestampServersPerBackend(t *testing.T) {
	path, thumb := signedPE(t, t.TempDir(), pkix.Name{CommonName: "Acme"}, true)
	dir := t.TempDir()
	dlib, meta := filepath.Join(dir, "Azure.CodeSigning.Dlib.dll"), filepath.Join(dir, "metadata.json")
	_ = os.WriteFile(dlib, []byte("x"), 0o600)
	_ = os.WriteFile(meta, []byte(`{"Endpoint":"https://weu.codesigning.azure.net","CodeSigningAccountName":"a","CertificateProfileName":"p"}`), 0o600)
	for backend, want := range defaultTimestamps {
		var tried []string
		f := execx.NewFake("signtool", "osslsigncode")
		f.Handle = func(c execx.Cmd) execx.Result {
			for i, a := range c.Args {
				if a == "/tr" || a == "-ts" {
					tried = append(tried, c.Args[i+1])
				}
			}
			return execx.Result{ExitCode: 1, Stderr: []byte("timestamp server unreachable")}
		}
		spec := profile.WindowsSpec{Kind: "authenticode", Backend: backend, Thumbprint: thumb, Subject: "CN=Acme",
			CertRef: "env://PFX", DlibPath: dlib, MetadataPath: meta}
		a := &Authenticode{H: fakeHost("windows", f, map[string]string{"PFX": path}), Spec: spec}
		_, _ = a.Sign(context.Background(), Artifact{Path: path, Rel: "tool.exe"}, winProfile(spec, profile.PurposeTest))
		if strings.Join(tried, " ") != strings.Join(want, " ") {
			t.Errorf("%s tried %v, want %v", backend, tried, want)
		}
	}
	if len(defaultTimestamps) != 4 {
		t.Fatalf("inspected %d backends, want 4", len(defaultTimestamps))
	}
}

// O-129: Artifact Signing's dlib and metadata.json are checked before
// signtool runs, and passed to it as /dlib and /dmdf.
func TestAzureMetadataIsChecked(t *testing.T) {
	dir := t.TempDir()
	dlib, meta := filepath.Join(dir, "Azure.CodeSigning.Dlib.dll"), filepath.Join(dir, "metadata.json")
	a := &Authenticode{H: fakeHost("windows", execx.NewFake("signtool"), nil),
		Spec: profile.WindowsSpec{Kind: "authenticode", Backend: profile.BackendAzure, DlibPath: dlib, MetadataPath: meta}}
	_, err := a.signArgs()
	wantCode(t, err, contract.Unavailable) // no dlib
	_ = os.WriteFile(dlib, []byte("x"), 0o600)
	_, err = a.signArgs()
	wantCode(t, err, contract.Unavailable) // no metadata.json
	for body, code := range map[string]contract.Code{
		`{"Endpoint":"https://weu.codesigning.azure.net","CodeSigningAccountName":"a"}`:                     contract.Usage,
		`{"Endpoint":"https://evil.example.com","CodeSigningAccountName":"a","CertificateProfileName":"p"}`: contract.Usage,
		`not json`: contract.Usage,
	} {
		_ = os.WriteFile(meta, []byte(body), 0o600)
		_, err = a.signArgs()
		wantCode(t, err, code)
	}
	_ = os.WriteFile(meta, []byte(`{"Endpoint":"https://weu.codesigning.azure.net","CodeSigningAccountName":"a","CertificateProfileName":"p"}`), 0o600)
	args, err := a.signArgs()
	if err != nil || strings.Join(args, " ") != "/dlib "+dlib+" /dmdf "+meta {
		t.Fatalf("args %v %v", args, err)
	}
}

// O-132: a macOS certificate's expiry is read from the keychain: of the
// certificates matching the identity, only an exact name counts, and of
// several the one that lasts longest.
func TestAppleCertificateExpiryFromKeychain(t *testing.T) {
	ident := "Developer ID Application: Acme Ltd (ABCDE12345)"
	mk := func(cn string, d time.Duration) []byte {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(d).Truncate(time.Second)}
		der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	old, renewed, nearMiss := mk(ident, 10*24*time.Hour), mk(ident, 400*24*time.Hour), mk(ident+" Extra", 900*24*time.Hour)
	f := execx.NewFake("security")
	f.Handle = func(execx.Cmd) execx.Result {
		return execx.Result{Stdout: append(append(append([]byte{}, old...), nearMiss...), renewed...)}
	}
	a := &Apple{H: fakeHost("darwin", f, nil), Spec: macSpec()}
	e := a.Certificate(context.Background(), profile.Profile{Name: "mac"})
	block, _ := pem.Decode(renewed)
	want, _ := x509.ParseCertificate(block.Bytes)
	if !e.Present || e.Source != "keychain" || e.NotAfter == nil || !e.NotAfter.Equal(want.NotAfter) {
		t.Fatalf("certificate entry: %+v, want expiry %s", e, want.NotAfter)
	}
}

// Old security finding 7: with notary.keychainProfile, notarytool reads the
// App Store Connect credentials from the login keychain, so impr never
// resolves, writes or passes the .p8 key.
func TestNotarizeWithAKeychainProfile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(file, []byte{0xcf, 0xfa, 0xed, 0xfe}, 0o600); err != nil {
		t.Fatal(err)
	}
	f := execx.NewFake("xcrun", "ditto")
	f.Handle = func(c execx.Cmd) execx.Result {
		if c.Tool == "xcrun" && c.Args[0] == "notarytool" {
			return execx.Result{Stdout: []byte(`{"id":"sub-7","status":"Accepted"}`)}
		}
		return execx.Result{}
	}
	spec := macSpec()
	spec.Notary = &profile.NotarySpec{KeychainProfile: "acme-notary"}
	a := &Apple{H: fakeHost("darwin", f, nil), Spec: spec}
	ticket, err := a.Notarize(context.Background(), []Artifact{{Path: file, Rel: "tool"}})
	if err != nil || ticket != "sub-7" {
		t.Fatalf("ticket %q %v", ticket, err)
	}
	if !f.Called("xcrun", "--keychain-profile acme-notary") {
		t.Fatalf("calls: %+v", f.Calls)
	}
	for _, c := range f.Calls {
		for _, a := range c.Args {
			if a == "--key" || a == "--issuer" || a == "--key-id" {
				t.Fatalf("a keychain-profile run passed %s: %v", a, c.Args)
			}
		}
	}
}
