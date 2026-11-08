package signing

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/sangehq/imprimatur/src/internal/artifact"
	"github.com/sangehq/imprimatur/src/internal/backend"
	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/profile"
)

// VerifyOptions is one verification.
type VerifyOptions struct {
	Root     string
	Manifest string   // build-manifest.json, optional with Signed
	Signed   string   // impr-manifest.json
	Files    []string // or loose files
	Profile  string
	Strict   bool
}

type item struct {
	rel, want, platform string
	notarized           bool
}

// Verify checks signed files against exactly one profile's pinned identity.
// The report is returned with the error, so a failed verification still
// prints what failed.
func (s *Service) Verify(ctx context.Context, o VerifyOptions) (VerifyResult, error) {
	root, err := absRoot(o.Root)
	if err != nil {
		return VerifyResult{}, err
	}
	s.Host.Root = root
	p, err := s.LoadProfile(o.Profile, contract.VerifyFailed)
	if err != nil {
		return VerifyResult{}, err
	}
	var items []item
	switch {
	case o.Signed != "":
		b, err := os.ReadFile(o.Signed)
		if err != nil {
			return VerifyResult{}, contract.Wrap(contract.Usage, err, "signed manifest not found: %s", o.Signed)
		}
		var m Manifest
		if err := json.Unmarshal(b, &m); err != nil || m.Schema != ManifestSchema {
			return VerifyResult{}, contract.New(contract.Usage, "%s is not an %s", o.Signed, ManifestFile)
		}
		if m.Profile != p.Name {
			return VerifyResult{}, contract.New(contract.VerifyFailed, "%s was signed with profile %s, not %s", o.Signed, m.Profile, p.Name)
		}
		if m.Identity.Digest() != p.Pinned().Digest() {
			return VerifyResult{}, contract.New(contract.VerifyFailed, "profile %s has been re-pinned since %s was signed", p.Name, o.Signed).
				WithDetails("signed with "+m.Identity.Digest(), "profile now "+p.Pinned().Digest())
		}
		if o.Manifest != "" {
			bm, err := artifact.ReadManifest(o.Manifest)
			if err != nil {
				return VerifyResult{}, err
			}
			if bm.Digest != m.BuildManifestDigest || bm.Commit != m.Commit || bm.Tree != m.Tree {
				return VerifyResult{}, contract.New(contract.VerifyFailed, "%s belongs to another build manifest", o.Signed)
			}
		}
		for _, a := range m.Artifacts {
			items = append(items, item{rel: a.Path, want: a.OutputSHA256, platform: a.Platform, notarized: a.Notarization != ""})
		}
		for _, out := range m.Outputs {
			if out.Kind == "sha256sums" {
				for _, pl := range []string{profile.Checksums, profile.Containers} {
					if hasOutput(m.Outputs, pl) {
						items = append(items, item{rel: out.Path, want: out.OutputSHA256, platform: pl})
					}
				}
			}
		}
	case len(o.Files) > 0:
		for _, f := range o.Files {
			items = append(items, item{rel: f})
		}
	default:
		return VerifyResult{}, contract.New(contract.Usage, "nothing to verify").
			WithFix("impr verify FILE... --profile NAME", "impr verify --signed impr-manifest.json --profile NAME")
	}

	res := VerifyResult{Contract: contract.Version, Profile: p.Name, Artifacts: []Verified{}}
	unavailable := false
	for _, it := range items {
		v := Verified{Path: it.rel, Platform: it.platform}
		if err := s.verifyOne(ctx, root, p, it, &v); err != nil {
			v.Problems = append(v.Problems, err.Error())
			if contract.CodeOf(err) == contract.Unavailable {
				unavailable = true
			}
		} else {
			v.OK = true
			v.Found = found(p, v.Platform)
		}
		res.Artifacts = append(res.Artifacts, v)
		state := "ok"
		if !v.OK {
			state = "FAIL " + strings.Join(v.Problems, "; ")
		}
		s.logf("verify    %s  %s", it.rel, state)
	}
	res.OK = true
	for _, v := range res.Artifacts {
		res.OK = res.OK && v.OK
	}
	if res.OK {
		return res, nil
	}
	if unavailable && o.Strict {
		return res, contract.New(contract.Unavailable, "a signature cannot be checked on this host")
	}
	return res, contract.New(contract.VerifyFailed, "verification failed")
}

func hasOutput(outs []SignedArtifact, platform string) bool {
	for _, o := range outs {
		if o.Platform == platform && o.Kind != "sha256sums" {
			return true
		}
	}
	return false
}

func (s *Service) verifyOne(ctx context.Context, root string, p profile.Profile, it item, v *Verified) error {
	path := it.rel
	if !filepath.IsAbs(path) {
		r, err := artifact.Resolve(root, it.rel)
		if err != nil {
			return errors.New(strings.TrimSpace(err.Error()))
		}
		path = r
	}
	sum, err := artifact.SHA256(path)
	if err != nil {
		return contract.Wrap(contract.VerifyFailed, err, "cannot read it")
	}
	v.SHA256 = sum
	if it.want != "" && !strings.EqualFold(sum, it.want) {
		return contract.New(contract.VerifyFailed, "the file is not the one that was signed")
	}
	pl := it.platform
	if pl == "" {
		k, err := artifact.KindOf(path)
		if err != nil {
			return err
		}
		pl = string(k)
		if k == artifact.KindOther {
			base := filepath.Base(path)
			switch {
			case p.Platforms.Checksums != nil && fileExists(path+checksumSuffix(p)):
				pl = profile.Checksums
			case p.Platforms.Containers != nil && fileExists(path+".sigstore.json"):
				pl = profile.Containers
			default:
				return contract.New(contract.VerifyFailed, "%s is not a Windows or macOS binary, and has no signature this profile makes", base)
			}
		}
		v.Platform = pl
	}
	be, err := s.backendFor(p, pl)
	if err != nil {
		return err
	}
	if c := be.Capability(s.Host); !c.Verify {
		return contract.New(contract.Unavailable, "%s signatures cannot be verified on this host: %s", pl, c.Reason)
	}
	return be.Verify(ctx, backend.Artifact{Path: path, Rel: it.rel, Notarized: it.notarized}, p)
}

func checksumSuffix(p profile.Profile) string {
	if p.Platforms.Checksums != nil && p.Platforms.Checksums.Kind == "minisign" {
		return ".minisig"
	}
	return ".sig"
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// found is the identity a passing verification found: exactly the pin.
func found(p profile.Profile, platform string) string {
	id := p.Pinned()
	switch platform {
	case profile.Windows:
		return id.Windows
	case profile.MacOS:
		return id.MacOS
	case profile.Checksums:
		return id.Checksums
	case profile.Containers:
		return id.Containers
	}
	return ""
}
