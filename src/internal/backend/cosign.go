package backend

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"strings"

	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/execx"
	"github.com/sangehq/imprimatur/src/internal/profile"
	"github.com/sangehq/imprimatur/src/internal/secrets"
)

// Cosign makes a Sigstore bundle (<file>.sigstore.json) over the checksum
// file: with a key (pinned by the sha256 of its public key) or keyless (pinned
// by certificate identity and OIDC issuer).
type Cosign struct {
	H    Host
	Spec profile.ContainerSpec
}

// Capability: cosign on PATH.
func (c *Cosign) Capability(h Host) Capability {
	cp := Capability{Platform: profile.Containers, Kind: "cosign", Backend: c.Spec.Mode, Supported: true, Tools: []string{"cosign"}}
	if ok, why := tool(h, "cosign"); ok {
		cp.Sign, cp.Verify = true, true
	} else {
		cp.Reason = why
	}
	return cp
}

// Certificate: a cosign key has no expiry; keyless certificates are issued
// per run.
func (c *Cosign) Certificate(ctx context.Context, p profile.Profile) CertEntry {
	e := CertEntry{Profile: p.Name, Platform: profile.Containers, Fingerprint: c.Spec.KeyFingerprint, Source: "declared"}
	if c.Spec.Mode == "keyless" {
		e.Subject, e.Present = c.Spec.Identity+"@"+c.Spec.Issuer, true
		return e
	}
	e.Source = "file"
	if _, err := c.H.Secrets.Resolve(ctx, c.Spec.KeyRef); err == nil {
		e.Present = true
	}
	return e
}

// PublicKeyFingerprint is the lower-case hex sha256 of a PEM public key's DER.
func PublicKeyFingerprint(pemBytes []byte) (string, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return "", contract.New(contract.Usage, "the cosign public key is not PEM")
	}
	if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		return "", contract.Wrap(contract.Usage, err, "the cosign public key does not parse")
	}
	h := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(h[:]), nil
}

func (c *Cosign) checkKeyPin() error {
	if c.Spec.PublicKey == "" {
		return contract.New(contract.SignFailed, "key-mode cosign needs platforms.containers.publicKey, so the pinned key can be checked").
			WithFix("cosign public-key --key <key> > cosign.pub, then --set platforms.containers.publicKey=<path to cosign.pub>")
	}
	b, err := os.ReadFile(c.Spec.PublicKey)
	if err != nil {
		return contract.Wrap(contract.Unavailable, err, "the cosign public key %s cannot be read", c.Spec.PublicKey)
	}
	fp, err := PublicKeyFingerprint(b)
	if err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimPrefix(c.Spec.KeyFingerprint, "sha256:"), fp) {
		return contract.New(contract.SignFailed, "the cosign public key is %s, not the pinned %s", fp, c.Spec.KeyFingerprint)
	}
	return nil
}

// Sign makes the bundle, then verifies it against the pin.
func (c *Cosign) Sign(ctx context.Context, art Artifact, p profile.Profile) (Signature, error) {
	bundle := art.Path + ".sigstore.json"
	_ = os.Remove(bundle)
	args := []string{"sign-blob", "--yes", "--bundle", bundle}
	var env []string
	signer := "keyless:" + c.Spec.Identity + "@" + c.Spec.Issuer
	if c.Spec.Mode == "key" {
		if err := c.checkKeyPin(); err != nil {
			return Signature{}, err
		}
		keyArg := c.Spec.KeyRef // cosign reads env://NAME itself
		if s, _, _ := secrets.Scheme(c.Spec.KeyRef); s != "env" {
			v, err := c.H.Secrets.Resolve(ctx, c.Spec.KeyRef)
			if err != nil {
				return Signature{}, err
			}
			f, err := secrets.AsFile(v, false)
			if err != nil {
				return Signature{}, err
			}
			defer f.Close()
			keyArg = f.Path
		}
		args = append(args, "--key", keyArg)
		if c.Spec.PasswordRef != "" {
			pw, err := c.H.Secrets.Resolve(ctx, c.Spec.PasswordRef)
			if err != nil {
				return Signature{}, err
			}
			env = append(env, "COSIGN_PASSWORD="+pw)
		}
		signer = "key:" + c.Spec.KeyFingerprint
	}
	r, err := c.H.Runner.Run(ctx, execx.Cmd{Tool: "cosign", Args: append(args, art.Path), Env: env})
	if err != nil {
		return Signature{}, contract.Wrap(contract.Unavailable, err, "cosign could not run")
	}
	if r.ExitCode != 0 {
		return Signature{}, contract.New(contract.SignFailed, "cosign could not sign %s", art.Rel).WithDetails(firstLine(r.Output()))
	}
	if err := c.Verify(ctx, art, p); err != nil {
		return Signature{}, err
	}
	return Signature{Kind: "cosign", Signer: signer, Outputs: []Output{{Path: bundle, Kind: "cosign"}}}, nil
}

// Verify checks the bundle against exactly the pinned key, or the pinned
// identity and issuer.
func (c *Cosign) Verify(ctx context.Context, art Artifact, _ profile.Profile) error {
	bundle := art.Path + ".sigstore.json"
	args := []string{"verify-blob", "--bundle", bundle}
	if c.Spec.Mode == "key" {
		if err := c.checkKeyPin(); err != nil {
			return contract.New(contract.VerifyFailed, "%s", err.Error())
		}
		args = append(args, "--key", c.Spec.PublicKey)
	} else {
		args = append(args, "--certificate-identity", c.Spec.Identity, "--certificate-oidc-issuer", c.Spec.Issuer)
	}
	r, err := c.H.Runner.Run(ctx, execx.Cmd{Tool: "cosign", Args: append(args, art.Path)})
	if err != nil {
		return contract.Wrap(contract.Unavailable, err, "cosign could not run")
	}
	if r.ExitCode != 0 {
		return contract.New(contract.VerifyFailed, "%s.sigstore.json does not verify against the pinned identity", art.Rel).WithDetails(firstLine(r.Output()))
	}
	return nil
}

// Preflight checks a key-mode public key is the pinned one.
func (c *Cosign) Preflight(context.Context, profile.Profile) error {
	if c.Spec.Mode == "key" {
		return c.checkKeyPin()
	}
	return nil
}
