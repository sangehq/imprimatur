package backend

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/execx"
	"github.com/sangehq/imprimatur/src/internal/profile"
	"github.com/sangehq/imprimatur/src/internal/secrets"
)

// Apple signs macOS files with codesign (hardened runtime, a secure
// timestamp), notarises them with notarytool and staples the formats that
// take a ticket. The signing identity must already be in a keychain: the
// sign-macos workflow imports it on a runner, a person's login keychain holds
// it locally.
type Apple struct {
	H    Host
	Spec profile.MacOSSpec
}

// Capability: macOS with codesign; notarisation also needs xcrun and ditto.
func (a *Apple) Capability(h Host) Capability {
	c := Capability{Platform: profile.MacOS, Kind: "developer-id", Supported: true, Tools: []string{"codesign"}}
	if a.Spec.Notary != nil {
		c.Tools = append(c.Tools, "xcrun", "ditto")
	}
	if h.GOOS != "darwin" {
		c.Reason = "Developer ID signing needs a macOS host"
		return c
	}
	if ok, why := tool(h, c.Tools...); !ok {
		c.Reason = why
		if ok, _ := tool(h, "codesign"); ok {
			c.Verify = true
		}
		return c
	}
	c.Sign, c.Verify = true, true
	return c
}

// Certificate reads the pinned identity's certificate from the keychains.
func (a *Apple) Certificate(ctx context.Context, p profile.Profile) CertEntry {
	e := CertEntry{Profile: p.Name, Platform: profile.MacOS, Subject: a.Spec.Identity, TeamID: a.Spec.TeamID, Source: "unknown", NotAfter: a.Spec.NotAfter}
	if a.Spec.NotAfter != nil {
		e.Source = "declared"
	}
	if a.H.GOOS != "darwin" || a.Spec.Identity == "" {
		return e
	}
	e.Source = "keychain"
	r, err := a.H.Runner.Run(ctx, execx.Cmd{Tool: "security", Args: []string{"find-certificate", "-a", "-c", a.Spec.Identity, "-p"}})
	if err != nil || r.ExitCode != 0 {
		return e
	}
	// Every certificate whose name contains the identity; only an exact name
	// counts, and of several (a renewal) the one that lasts longest.
	rest := r.Stdout
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || cert.Subject.CommonName != a.Spec.Identity {
			continue
		}
		if na := cert.NotAfter.UTC(); e.NotAfter == nil || !e.Present || na.After(*e.NotAfter) {
			e.Present, e.NotAfter = true, &na
		}
	}
	return e
}

// Sign runs codesign with the pinned identity and checks the result.
func (a *Apple) Sign(ctx context.Context, art Artifact, p profile.Profile) (Signature, error) {
	if c := a.Capability(a.H); !c.Sign {
		return Signature{}, contract.New(contract.Unavailable, "Developer ID signing is not available here: %s", c.Reason)
	}
	args := []string{"--force", "--options", "runtime", "--timestamp"}
	if a.Spec.Entitlements != "" {
		ent := a.Spec.Entitlements
		if !filepath.IsAbs(ent) {
			ent = filepath.Join(a.H.Root, filepath.FromSlash(ent))
		}
		if !fileExists(ent) {
			return Signature{}, contract.New(contract.Usage, "the entitlements file %s does not exist", a.Spec.Entitlements)
		}
		args = append(args, "--entitlements", ent)
	}
	args = append(args, "--sign", a.Spec.Identity, art.Path)
	r, err := a.H.Runner.Run(ctx, execx.Cmd{Tool: "codesign", Args: args})
	if err != nil {
		return Signature{}, contract.Wrap(contract.Unavailable, err, "codesign could not run")
	}
	if r.ExitCode != 0 {
		return Signature{}, contract.New(contract.SignFailed, "codesign could not sign %s", art.Rel).WithDetails(firstLine(r.Output())).
			WithFix("check the identity is in a keychain: security find-identity -v -p codesigning")
	}
	if err := a.check(ctx, art, false); err != nil {
		return Signature{}, err
	}
	return Signature{Kind: "developer-id", Signer: a.Spec.Identity, Timestamp: "timestamp.apple.com"}, nil
}

// Verify checks codesign's strict verification, the pinned team and
// identity, and Gatekeeper when the run was notarised.
func (a *Apple) Verify(ctx context.Context, art Artifact, _ profile.Profile) error {
	if ok, why := tool(a.H, "codesign"); !ok || a.H.GOOS != "darwin" {
		if why == "" {
			why = "codesign needs a macOS host"
		}
		return contract.New(contract.Unavailable, "macOS signatures cannot be verified here: %s", why)
	}
	return a.check(ctx, art, art.Notarized)
}

func (a *Apple) check(ctx context.Context, art Artifact, gatekeeper bool) error {
	r, err := a.H.Runner.Run(ctx, execx.Cmd{Tool: "codesign", Args: []string{"--verify", "--deep", "--strict", art.Path}})
	if err != nil {
		return contract.Wrap(contract.Unavailable, err, "codesign could not run")
	}
	if r.ExitCode != 0 {
		return contract.New(contract.VerifyFailed, "%s does not verify", art.Rel).WithDetails(firstLine(r.Output()))
	}
	d, err := a.H.Runner.Run(ctx, execx.Cmd{Tool: "codesign", Args: []string{"-d", "--verbose=4", art.Path}})
	if err != nil {
		return contract.Wrap(contract.Unavailable, err, "codesign could not run")
	}
	out := d.Output()
	team := regexp.MustCompile(`(?m)^TeamIdentifier=(.*)$`).FindStringSubmatch(out)
	if team == nil || strings.TrimSpace(team[1]) != a.Spec.TeamID {
		found := "none"
		if team != nil {
			found = strings.TrimSpace(team[1])
		}
		return contract.New(contract.VerifyFailed, "%s is signed by team %s, not the pinned %s", art.Rel, found, a.Spec.TeamID)
	}
	if !regexp.MustCompile(`(?m)^Authority=` + regexp.QuoteMeta(a.Spec.Identity) + `\s*$`).MatchString(out) {
		return contract.New(contract.VerifyFailed, "%s is not signed by the pinned identity %q", art.Rel, a.Spec.Identity)
	}
	if gatekeeper {
		g, err := a.H.Runner.Run(ctx, execx.Cmd{Tool: "spctl", Args: []string{"-a", "-t", "exec", "-vv", art.Path}})
		if err != nil {
			return contract.Wrap(contract.Unavailable, err, "spctl could not run")
		}
		if g.ExitCode != 0 {
			return contract.New(contract.VerifyFailed, "Gatekeeper rejects %s", art.Rel).WithDetails(firstLine(g.Output()))
		}
	}
	return nil
}

// Notarize submits the signed files in one zip, waits for Apple's verdict,
// staples the ones whose format takes a ticket, and returns the submission id.
func (a *Apple) Notarize(ctx context.Context, files []Artifact) (string, error) {
	n := a.Spec.Notary
	if n == nil {
		return "", nil
	}
	key, err := a.H.Secrets.Resolve(ctx, n.APIKeyRef)
	if err != nil {
		return "", err
	}
	keyFile, err := secrets.AsFile(key, false)
	if err != nil {
		return "", err
	}
	defer keyFile.Close()
	keyID, err := a.literalOrRef(ctx, n.KeyID)
	if err != nil {
		return "", err
	}
	issuer, err := a.literalOrRef(ctx, n.Issuer)
	if err != nil {
		return "", err
	}
	tmp, err := os.MkdirTemp("", "impr-notary-")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	stage := filepath.Join(tmp, "stage")
	if err := os.Mkdir(stage, 0o700); err != nil {
		return "", err
	}
	for _, f := range files {
		b, err := os.ReadFile(f.Path)
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(stage, filepath.Base(f.Path)), b, 0o600); err != nil { //nolint:gosec // G703: the base name of a manifest file, inside a fresh temporary directory
			return "", err
		}
	}
	zip := filepath.Join(tmp, "notarize.zip")
	z, err := a.H.Runner.Run(ctx, execx.Cmd{Tool: "ditto", Args: []string{"-c", "-k", "--keepParent", stage, zip}})
	if err != nil || z.ExitCode != 0 {
		return "", contract.New(contract.SignFailed, "could not zip the binaries for notarisation").WithDetails(firstLine(z.Output()))
	}
	args := []string{"notarytool", "submit", zip, "--key", keyFile.Path, "--wait", "--output-format", "json"}
	if keyID != "" {
		args = append(args, "--key-id", keyID)
	}
	if issuer != "" {
		args = append(args, "--issuer", issuer)
	}
	r, err := a.H.Runner.Run(ctx, execx.Cmd{Tool: "xcrun", Args: args})
	if err != nil {
		return "", contract.Wrap(contract.Unavailable, err, "notarytool could not run")
	}
	var verdict struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	_ = json.Unmarshal(r.Stdout, &verdict)
	if r.ExitCode != 0 || verdict.Status != "Accepted" {
		return "", contract.New(contract.SignFailed, "notarisation was not accepted (status %q)", verdict.Status).
			WithDetails(firstLine(r.Output())).
			WithFix("read Apple's log: xcrun notarytool log <submission id> --key ... --key-id ... --issuer ...")
	}
	for _, f := range files {
		if ext := strings.ToLower(filepath.Ext(f.Path)); ext == ".dmg" || ext == ".pkg" {
			s, err := a.H.Runner.Run(ctx, execx.Cmd{Tool: "xcrun", Args: []string{"stapler", "staple", f.Path}})
			if err != nil || s.ExitCode != 0 {
				return "", contract.New(contract.SignFailed, "stapler could not staple the ticket to %s", f.Rel).WithDetails(firstLine(s.Output()))
			}
		}
	}
	if verdict.ID == "" {
		return "accepted", nil
	}
	return verdict.ID, nil
}

func (a *Apple) literalOrRef(ctx context.Context, v string) (string, error) {
	if profile.IsRef(v) {
		return a.H.Secrets.Resolve(ctx, v)
	}
	return v, nil
}
