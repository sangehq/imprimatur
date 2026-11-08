package backend

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/execx"
	"github.com/sangehq/imprimatur/src/internal/profile"
	"github.com/sangehq/imprimatur/src/internal/secrets"
)

// ---- GPG -----------------------------------------------------------------------

// GPG signs the checksum file with the pinned key held by the gpg agent.
type GPG struct {
	H    Host
	Spec profile.ChecksumSpec
}

// Capability: gpg on PATH.
func (g *GPG) Capability(h Host) Capability {
	c := Capability{Platform: profile.Checksums, Kind: "gpg", Supported: true, Tools: []string{"gpg"}}
	if ok, why := tool(h, "gpg"); ok {
		c.Sign, c.Verify = true, true
	} else {
		c.Reason = why
	}
	return c
}

func (g *GPG) fpr() string { return strings.ToUpper(g.Spec.Fingerprint) }

// Certificate lists the pinned secret key and its expiry.
func (g *GPG) Certificate(ctx context.Context, p profile.Profile) CertEntry {
	e := CertEntry{Profile: p.Name, Platform: profile.Checksums, Fingerprint: g.fpr(), Source: "unknown", NotAfter: g.Spec.NotAfter}
	if ok, _ := tool(g.H, "gpg"); !ok {
		return e
	}
	e.Source = "gpg"
	r, err := g.H.Runner.Run(ctx, execx.Cmd{Tool: "gpg", Args: []string{"--batch", "--with-colons", "--list-secret-keys", g.fpr()}})
	if err != nil || r.ExitCode != 0 {
		return e
	}
	for _, line := range strings.Split(string(r.Stdout), "\n") {
		f := strings.Split(line, ":")
		if len(f) > 6 && f[0] == "sec" {
			e.Present = true
			if n, err := strconv.ParseInt(f[6], 10, 64); err == nil && n > 0 {
				t := time.Unix(n, 0).UTC()
				e.NotAfter = &t
			}
		}
	}
	return e
}

// Sign makes a detached signature with --local-user set to the pinned
// fingerprint, so no other key can sign, then verifies it.
func (g *GPG) Sign(ctx context.Context, art Artifact, p profile.Profile) (Signature, error) {
	if err := g.Preflight(ctx, p); err != nil {
		return Signature{}, err
	}
	sig := art.Path + ".sig"
	_ = os.Remove(sig)
	r, err := g.H.Runner.Run(ctx, execx.Cmd{Tool: "gpg", Args: []string{"--batch", "--yes", "--local-user", g.fpr(), "--detach-sign", "--output", sig, art.Path}})
	if err != nil {
		return Signature{}, contract.Wrap(contract.Unavailable, err, "gpg could not run")
	}
	if r.ExitCode != 0 {
		return Signature{}, contract.New(contract.SignFailed, "gpg could not sign %s", art.Rel).WithDetails(firstLine(r.Output()))
	}
	if err := g.Verify(ctx, art, p); err != nil {
		return Signature{}, err
	}
	return Signature{Kind: "gpg", Signer: g.fpr(), Outputs: []Output{{Path: sig, Kind: "gpg"}}}, nil
}

// Verify requires a good signature (VALIDSIG) by the pinned key.
func (g *GPG) Verify(ctx context.Context, art Artifact, _ profile.Profile) error {
	r, err := g.H.Runner.Run(ctx, execx.Cmd{Tool: "gpg", Args: []string{"--batch", "--status-fd", "1", "--verify", art.Path + ".sig", art.Path}})
	if err != nil {
		return contract.Wrap(contract.Unavailable, err, "gpg could not run")
	}
	for _, line := range strings.Split(string(r.Stdout), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] != "[GNUPG:]" || f[1] != "VALIDSIG" {
			continue
		}
		cands := []string{f[2]}
		if len(f) > 11 {
			cands = append(cands, f[11]) // the primary key's fingerprint
		}
		for _, c := range cands {
			if strings.HasSuffix(strings.ToUpper(c), g.fpr()) {
				return nil
			}
		}
		return contract.New(contract.VerifyFailed, "%s is signed by %s, not the pinned key %s", art.Rel, f[2], g.fpr())
	}
	return contract.New(contract.VerifyFailed, "%s.sig is not a good signature by the pinned key %s", art.Rel, g.fpr()).WithDetails(firstLine(r.Output()))
}

// ---- minisign ------------------------------------------------------------------

// Minisign signs the checksum file with a minisign key.
type Minisign struct {
	H    Host
	Spec profile.ChecksumSpec
}

// Capability: minisign on PATH.
func (m *Minisign) Capability(h Host) Capability {
	c := Capability{Platform: profile.Checksums, Kind: "minisign", Supported: true, Tools: []string{"minisign"}}
	if ok, why := tool(h, "minisign"); ok {
		c.Sign, c.Verify = true, true
	} else {
		c.Reason = why
	}
	return c
}

// Certificate: a minisign key has no expiry; it is present when its
// reference resolves.
func (m *Minisign) Certificate(ctx context.Context, p profile.Profile) CertEntry {
	e := CertEntry{Profile: p.Name, Platform: profile.Checksums, Fingerprint: strings.ToUpper(m.Spec.Fingerprint), Source: "file", NotAfter: m.Spec.NotAfter}
	if v, err := m.H.Secrets.Resolve(ctx, m.Spec.KeyRef); err == nil {
		f, err := secrets.AsFile(v, false)
		e.Present = err == nil
		f.Close()
	}
	return e
}

// MinisignKeyID returns the key id ("%016X") of a minisign public key line
// or signature line: two algorithm bytes, then the 8-byte key number.
func MinisignKeyID(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(raw) < 10 {
		return "", fmt.Errorf("not a minisign key or signature line")
	}
	return fmt.Sprintf("%016X", binary.LittleEndian.Uint64(raw[2:10])), nil
}

func (m *Minisign) checkPin() error {
	id, err := MinisignKeyID(m.Spec.PublicKey)
	if err != nil {
		return contract.New(contract.Usage, "platforms.checksums.publicKey is not a minisign public key")
	}
	if !strings.EqualFold(id, m.Spec.Fingerprint) {
		return contract.New(contract.SignFailed, "the minisign public key is %s, not the pinned %s", id, strings.ToUpper(m.Spec.Fingerprint))
	}
	return nil
}

// Sign signs with the referenced secret key (an unencrypted key: CI has no
// terminal to type a password into), then verifies against the pinned key.
func (m *Minisign) Sign(ctx context.Context, art Artifact, p profile.Profile) (Signature, error) {
	if err := m.checkPin(); err != nil {
		return Signature{}, err
	}
	v, err := m.H.Secrets.Resolve(ctx, m.Spec.KeyRef)
	if err != nil {
		return Signature{}, err
	}
	key, err := secrets.AsFile(v, false)
	if err != nil {
		return Signature{}, err
	}
	defer key.Close()
	sig := art.Path + ".minisig"
	_ = os.Remove(sig)
	r, err := m.H.Runner.Run(ctx, execx.Cmd{Tool: "minisign", Args: []string{"-S", "-s", key.Path, "-m", art.Path, "-x", sig}, Stdin: []byte{}})
	if err != nil {
		return Signature{}, contract.Wrap(contract.Unavailable, err, "minisign could not run")
	}
	if r.ExitCode != 0 {
		return Signature{}, contract.New(contract.SignFailed, "minisign could not sign %s", art.Rel).WithDetails(firstLine(r.Output()))
	}
	if err := m.Verify(ctx, art, p); err != nil {
		return Signature{}, err
	}
	return Signature{Kind: "minisign", Signer: strings.ToUpper(m.Spec.Fingerprint), Outputs: []Output{{Path: sig, Kind: "minisign"}}}, nil
}

// Verify checks the signature's key id is the pinned one and that minisign
// verifies it with the pinned public key.
func (m *Minisign) Verify(ctx context.Context, art Artifact, _ profile.Profile) error {
	if err := m.checkPin(); err != nil {
		return err
	}
	sig := art.Path + ".minisig"
	b, err := os.ReadFile(sig) //nolint:gosec // G304: the signature beside the checksum file
	if err != nil {
		return contract.Wrap(contract.VerifyFailed, err, "%s has no minisign signature", art.Rel)
	}
	lines := strings.Split(string(b), "\n")
	if len(lines) < 2 {
		return contract.New(contract.VerifyFailed, "%s.minisig is not a minisign signature", art.Rel)
	}
	if id, err := MinisignKeyID(lines[1]); err != nil || !strings.EqualFold(id, m.Spec.Fingerprint) {
		return contract.New(contract.VerifyFailed, "%s.minisig is signed by key %s, not the pinned %s", art.Rel, id, strings.ToUpper(m.Spec.Fingerprint))
	}
	r, err := m.H.Runner.Run(ctx, execx.Cmd{Tool: "minisign", Args: []string{"-V", "-P", strings.TrimSpace(m.Spec.PublicKey), "-m", art.Path, "-x", sig}})
	if err != nil {
		return contract.Wrap(contract.Unavailable, err, "minisign could not run")
	}
	if r.ExitCode != 0 {
		return contract.New(contract.VerifyFailed, "%s.minisig does not verify", art.Rel).WithDetails(firstLine(r.Output()))
	}
	return nil
}

// ---- SSH -----------------------------------------------------------------------

// SSH signs the checksum file with ssh-keygen -Y sign.
type SSH struct {
	H    Host
	Spec profile.ChecksumSpec
}

func (s *SSH) namespace() string {
	if s.Spec.Namespace != "" {
		return s.Spec.Namespace
	}
	return "file"
}

// Capability: ssh-keygen on PATH.
func (s *SSH) Capability(h Host) Capability {
	c := Capability{Platform: profile.Checksums, Kind: "ssh", Supported: true, Tools: []string{"ssh-keygen"}}
	if ok, why := tool(h, "ssh-keygen"); ok {
		c.Sign, c.Verify = true, true
	} else {
		c.Reason = why
	}
	return c
}

var sshFprRe = regexp.MustCompile(`SHA256:[A-Za-z0-9+/=]+`)

// keyFingerprint asks ssh-keygen for a key file's SHA256 fingerprint.
func (s *SSH) keyFingerprint(ctx context.Context, path string) (string, error) {
	r, err := s.H.Runner.Run(ctx, execx.Cmd{Tool: "ssh-keygen", Args: []string{"-l", "-E", "sha256", "-f", path}})
	if err != nil {
		return "", contract.Wrap(contract.Unavailable, err, "ssh-keygen could not run")
	}
	fp := sshFprRe.FindString(string(r.Stdout))
	if r.ExitCode != 0 || fp == "" {
		return "", contract.New(contract.SignFailed, "the SSH signing key could not be read").WithDetails(firstLine(r.Output()))
	}
	return fp, nil
}

// Certificate: an SSH key has no expiry; present when its reference
// resolves to a key with the pinned fingerprint.
func (s *SSH) Certificate(ctx context.Context, p profile.Profile) CertEntry {
	e := CertEntry{Profile: p.Name, Platform: profile.Checksums, Fingerprint: s.Spec.Fingerprint, Source: "file", NotAfter: s.Spec.NotAfter}
	v, err := s.H.Secrets.Resolve(ctx, s.Spec.KeyRef)
	if err != nil {
		return e
	}
	f, err := secrets.AsFile(v, false)
	if err != nil {
		return e
	}
	defer f.Close()
	if fp, err := s.keyFingerprint(ctx, f.Path); err == nil {
		e.Present = fp == s.Spec.Fingerprint
	}
	return e
}

// Sign checks the referenced key is the pinned one, signs, then verifies.
func (s *SSH) Sign(ctx context.Context, art Artifact, p profile.Profile) (Signature, error) {
	v, err := s.H.Secrets.Resolve(ctx, s.Spec.KeyRef)
	if err != nil {
		return Signature{}, err
	}
	key, err := secrets.AsFile(v, false)
	if err != nil {
		return Signature{}, err
	}
	defer key.Close()
	fp, err := s.keyFingerprint(ctx, key.Path)
	if err != nil {
		return Signature{}, err
	}
	if fp != s.Spec.Fingerprint {
		return Signature{}, contract.New(contract.SignFailed, "the SSH key %s references is %s, not the pinned %s", s.Spec.KeyRef, fp, s.Spec.Fingerprint).
			WithFix("point keyRef at the pinned key, or re-pin: impr profile edit " + p.Name + " --set platforms.checksums.fingerprint=" + fp)
	}
	sig := art.Path + ".sig"
	_ = os.Remove(sig)
	r, err := s.H.Runner.Run(ctx, execx.Cmd{Tool: "ssh-keygen", Args: []string{"-Y", "sign", "-f", key.Path, "-n", s.namespace(), art.Path}})
	if err != nil {
		return Signature{}, contract.Wrap(contract.Unavailable, err, "ssh-keygen could not run")
	}
	if r.ExitCode != 0 {
		return Signature{}, contract.New(contract.SignFailed, "ssh-keygen could not sign %s", art.Rel).WithDetails(firstLine(r.Output()))
	}
	if err := s.Verify(ctx, art, p); err != nil {
		return Signature{}, err
	}
	return Signature{Kind: "ssh", Signer: s.Spec.Fingerprint, Outputs: []Output{{Path: sig, Kind: "ssh"}}}, nil
}

// SSHSigKey returns the public key embedded in an armored SSH signature
// (PROTOCOL.sshsig): its type and wire blob.
func SSHSigKey(armored []byte) (keyType string, blob []byte, err error) {
	text := string(armored)
	start := strings.Index(text, "-----BEGIN SSH SIGNATURE-----")
	end := strings.Index(text, "-----END SSH SIGNATURE-----")
	if start < 0 || end < start {
		return "", nil, fmt.Errorf("not an SSH signature")
	}
	body := strings.Join(strings.Fields(text[start+len("-----BEGIN SSH SIGNATURE-----"):end]), "")
	raw, err := base64.StdEncoding.DecodeString(body)
	if err != nil || len(raw) < 10 || string(raw[:6]) != "SSHSIG" {
		return "", nil, fmt.Errorf("not an SSH signature")
	}
	rest := raw[10:] // magic, uint32 version
	if len(rest) < 4 {
		return "", nil, fmt.Errorf("truncated SSH signature")
	}
	n := binary.BigEndian.Uint32(rest[:4])
	if int64(n) > int64(len(rest)-4) {
		return "", nil, fmt.Errorf("truncated SSH signature")
	}
	blob = rest[4 : 4+n]
	if len(blob) < 4 {
		return "", nil, fmt.Errorf("truncated public key")
	}
	tn := binary.BigEndian.Uint32(blob[:4])
	if int64(tn) > int64(len(blob)-4) {
		return "", nil, fmt.Errorf("truncated public key")
	}
	return string(blob[4 : 4+tn]), blob, nil
}

// SSHFingerprint is OpenSSH's SHA256 fingerprint of a public key blob.
func SSHFingerprint(blob []byte) string {
	h := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(h[:])
}

// Verify reads the key the signature names, requires it to be the pinned
// one, and has ssh-keygen verify the signature against exactly that key.
func (s *SSH) Verify(ctx context.Context, art Artifact, _ profile.Profile) error {
	sigPath := art.Path + ".sig"
	b, err := os.ReadFile(sigPath) //nolint:gosec // G304: the signature beside the checksum file
	if err != nil {
		return contract.Wrap(contract.VerifyFailed, err, "%s has no SSH signature", art.Rel)
	}
	kt, blob, err := SSHSigKey(b)
	if err != nil {
		return contract.Wrap(contract.VerifyFailed, err, "%s.sig", art.Rel)
	}
	if fp := SSHFingerprint(blob); fp != s.Spec.Fingerprint {
		return contract.New(contract.VerifyFailed, "%s.sig is signed by %s, not the pinned %s", art.Rel, fp, s.Spec.Fingerprint)
	}
	dir, err := os.MkdirTemp("", "impr-ssh-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	allowed := filepath.Join(dir, "allowed_signers")
	line := "imprimatur namespaces=\"" + s.namespace() + "\" " + kt + " " + base64.StdEncoding.EncodeToString(blob) + "\n"
	if err := os.WriteFile(allowed, []byte(line), 0o600); err != nil { //nolint:gosec // G703: a fixed name in a fresh temporary directory
		return err
	}
	data, err := os.ReadFile(art.Path) //nolint:gosec // G703: the checksum file resolved under the signing root
	if err != nil {
		return err
	}
	r, err := s.H.Runner.Run(ctx, execx.Cmd{Tool: "ssh-keygen", Args: []string{"-Y", "verify", "-f", allowed, "-I", "imprimatur", "-n", s.namespace(), "-s", sigPath}, Stdin: data})
	if err != nil {
		return contract.Wrap(contract.Unavailable, err, "ssh-keygen could not run")
	}
	if r.ExitCode != 0 {
		return contract.New(contract.VerifyFailed, "%s.sig does not verify", art.Rel).WithDetails(firstLine(r.Output()))
	}
	return nil
}

// Preflight checks the key reference names the pinned key.
func (g *GPG) Preflight(_ context.Context, p profile.Profile) error {
	if s, n, _ := secrets.Scheme(g.Spec.KeyRef); s != "gpg-agent" || !strings.EqualFold(n, g.Spec.Fingerprint) {
		return contract.New(contract.Usage, "a gpg checksum key is referenced as gpg-agent://<the pinned fingerprint>, not %q", g.Spec.KeyRef).
			WithFix("impr profile edit " + p.Name + " --set platforms.checksums.keyRef=gpg-agent://" + g.fpr())
	}
	return nil
}

// Preflight checks the public key is the pinned one.
func (m *Minisign) Preflight(context.Context, profile.Profile) error { return m.checkPin() }
