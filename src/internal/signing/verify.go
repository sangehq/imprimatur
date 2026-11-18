package signing

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/sangehq/imprimatur/src/internal/artifact"
	"github.com/sangehq/imprimatur/src/internal/backend"
	"github.com/sangehq/imprimatur/src/internal/capped"
	"github.com/sangehq/imprimatur/src/internal/config"
	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/profile"
	"github.com/sangehq/imprimatur/src/internal/project"
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
	sums                bool           // a SHA256SUMS file: every file it lists is re-hashed too
	signerID            string         // the windows signer the record names
	require             []string       // with --manifest: build-manifest files the checksum file must list
	build               *backend.Build // the build the signed record names (in-toto checks it)
	fromRecord          bool           // the path came from a signed record: it must resolve under --root
}

// Verify checks signed files against exactly one profile's pinned identity.
// The report is returned with the error, so a failed verification still
// prints what failed.
func (s *Service) Verify(ctx context.Context, o VerifyOptions) (VerifyResult, error) {
	o.Strict = o.Strict || s.Strict
	if s.Hooks != nil {
		ev, err := s.event("verification.run.started", o.Profile, map[string]any{"profile": o.Profile, "signed": o.Signed != "", "files": len(o.Files)})
		if err != nil {
			return VerifyResult{}, err
		}
		if err := s.Hooks.Pre(ctx, config.PhasePreVerify, ev); err != nil {
			s.Events.Emit(ctx, "hook.vetoed", o.Profile, map[string]any{"phase": config.PhasePreVerify, "reason": err.Error()})
			return VerifyResult{}, contract.Wrap(contract.VerifyFailed, err, "a pre-verify hook refused the run")
		}
		s.Events.Publish(ctx, ev)
	}
	if err := s.Events.Err(); err != nil {
		return VerifyResult{}, requiredEvents(err, "nothing was verified")
	}
	res, err := s.verify(ctx, o)
	if res.Profile != "" {
		failed := []string{}
		for _, a := range res.Artifacts {
			if !a.OK {
				failed = append(failed, a.Path)
			}
		}
		data := map[string]any{"profile": res.Profile, "artifacts": len(res.Artifacts), "failed": failed, "exitCode": int(contract.CodeOf(err))}
		if err == nil {
			s.finish(ctx, config.PhasePostVerify, "verification.run.completed", res.Profile, data)
		} else {
			s.finish(ctx, config.PhasePostVerify, "verification.run.failed", res.Profile, data)
		}
	}
	if lerr := s.Events.Err(); lerr != nil && err == nil {
		return res, requiredEvents(lerr, "the run finished but its record is incomplete")
	}
	return res, err
}

func (s *Service) verify(ctx context.Context, o VerifyOptions) (VerifyResult, error) {
	root, err := absRoot(o.Root)
	if err != nil {
		return VerifyResult{}, err
	}
	s.Host.Root = root
	p, err := s.LoadProfile(o.Profile, contract.VerifyFailed)
	if err != nil {
		return VerifyResult{}, err
	}
	if proj, ok, err := project.Load(root); err != nil {
		return VerifyResult{}, contract.Wrap(contract.Usage, err, "the repository's project file cannot be read")
	} else if ok {
		if why := proj.CheckVerify(p.Name, o.Strict); len(why) > 0 {
			return VerifyResult{}, contract.New(contract.VerifyFailed, "the repository's %s refuses this verification", project.Path).WithDetails(why...)
		}
	}
	var items []item
	switch {
	case o.Signed != "":
		b, err := capped.ReadFile(o.Signed, capped.Manifest)
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
		var require []string
		if o.Manifest != "" {
			bm, err := artifact.ReadManifest(o.Manifest)
			if err != nil {
				return VerifyResult{}, err
			}
			if bm.Digest != m.BuildManifestDigest || bm.Commit != m.Commit || bm.Tree != m.Tree {
				return VerifyResult{}, contract.New(contract.VerifyFailed, "%s belongs to another build manifest", o.Signed)
			}
			binaries := map[string]bool{}
			for _, a := range m.Artifacts {
				binaries[a.Path] = true
			}
			for _, a := range bm.Artifacts {
				if !binaries[a.Path] {
					require = append(require, a.Path)
				}
			}
			if len(require) > 0 && !hasSums(m.Outputs) {
				return VerifyResult{}, contract.New(contract.VerifyFailed, "%d file(s) of the build manifest are covered by no signature in %s", len(require), o.Signed).
					WithDetails(require...)
			}
		}
		if len(m.Artifacts) == 0 && len(m.Outputs) == 0 {
			return VerifyResult{}, contract.New(contract.VerifyFailed, "%s records no signed artifacts or outputs; there is nothing to verify", o.Signed).
				WithDetails("An empty record proves nothing, so it never passes.")
		}
		for _, a := range m.Artifacts {
			items = append(items, item{rel: a.Path, want: a.OutputSHA256, platform: a.Platform, notarized: a.Notarization != "", signerID: a.SignerID, fromRecord: true})
		}
		for _, out := range m.Outputs {
			if out.Kind == "sha256sums" {
				for _, pl := range []string{profile.Checksums, profile.Containers, profile.Attestations} {
					if hasOutput(m.Outputs, pl) {
						items = append(items, item{rel: out.Path, want: out.OutputSHA256, platform: pl, sums: true, require: require, fromRecord: true,
							build: &backend.Build{Repo: m.Repo, Commit: m.Commit, Tree: m.Tree, ManifestDigest: m.BuildManifestDigest}})
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

func hasSums(outs []SignedArtifact) bool {
	for _, o := range outs {
		if o.Kind == "sha256sums" {
			return true
		}
	}
	return false
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
	// A signed record is repository content: an absolute path in it must not
	// take verify outside --root (security review R4). Files named on the
	// command line may be anywhere.
	if it.fromRecord || !filepath.IsAbs(path) {
		r, err := artifact.Resolve(root, it.rel)
		if err != nil {
			return contract.Wrap(contract.VerifyFailed, err, "cannot verify %s", it.rel)
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
			case p.Platforms.Attestations != nil && fileExists(path+backend.AttestationExt):
				pl = profile.Attestations
			default:
				return contract.New(contract.VerifyFailed, "%s is not a Windows or macOS binary, and has no signature this profile makes", base)
			}
		}
		v.Platform = pl
	}
	if pl == profile.Windows && p.Platforms.Windows != nil && len(p.Platforms.Windows.Signers) > 0 {
		art := backend.Artifact{Path: path, Rel: it.rel, Notarized: it.notarized}
		return s.verifyWindowsSigners(ctx, p, it, art, v)
	}
	be, err := s.backendFor(p, pl)
	if err != nil {
		return err
	}
	if c := be.Capability(s.Host); !c.Verify {
		return contract.New(contract.Unavailable, "%s signatures cannot be verified on this host: %s", pl, c.Reason)
	}
	if pl == profile.Attestations && it.build == nil {
		s.logf("verify    %s: without --signed, the attested build (commit, tree, build manifest, repository) is not compared with anything", it.rel)
	}
	art := backend.Artifact{Path: path, Rel: it.rel, Notarized: it.notarized, Build: it.build}
	if err := be.Verify(ctx, art, p); err != nil {
		return err
	}
	if it.sums {
		return verifyListed(root, path, it.require)
	}
	return nil
}

// verifyListed re-hashes every file a signed SHA256SUMS lists. A valid
// signature over the checksum file proves nothing about the files on disk
// until each one is compared with its line.
func verifyListed(root, sumsPath string, require []string) error {
	b, err := os.ReadFile(sumsPath) //nolint:gosec // G304: resolved under the signing root
	if err != nil {
		return contract.Wrap(contract.VerifyFailed, err, "cannot read the checksum file")
	}
	lines, err := artifact.ParseChecksums(b)
	if err != nil {
		return contract.Wrap(contract.VerifyFailed, err, "the checksum file is malformed")
	}
	if len(lines) == 0 {
		return contract.New(contract.VerifyFailed, "the checksum file lists no files")
	}
	var bad []string
	listed := map[string]bool{}
	for _, l := range lines {
		listed[l[1]] = true
	}
	for _, r := range require {
		if !listed[r] {
			bad = append(bad, r+": in the build manifest but not in the signed checksum file")
		}
	}
	for _, l := range lines {
		path, err := artifact.Resolve(root, l[1])
		if err != nil {
			bad = append(bad, l[1]+": missing or outside the root")
			continue
		}
		sum, err := artifact.SHA256(path)
		if err != nil || sum != l[0] {
			bad = append(bad, l[1]+": does not match the signed checksum")
		}
	}
	if len(bad) > 0 {
		return contract.New(contract.VerifyFailed, "%d check(s) of the checksum file's %d entries fail: %s", len(bad), len(lines), strings.Join(bad, "; ")).WithDetails(bad...)
	}
	return nil
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
	case profile.Attestations:
		if a := p.Platforms.Attestations; a != nil && a.Signer == "cosign" {
			return id.Containers
		}
		return id.Checksums
	}
	return ""
}

// verifyWindowsSigners checks a file against a multi-certificate profile.
// A record naming its signer is checked against exactly that signer. A loose
// file passes if any signer whose selector matches it verifies it; dates are
// not applied, because a timestamped signature outlives its certificate's
// signing window.
func (s *Service) verifyWindowsSigners(ctx context.Context, p profile.Profile, it item, art backend.Artifact, v *Verified) error {
	vs := p.WindowsVariants()
	var cands []profile.Variant
	if it.signerID != "" {
		sv, ok := profile.VariantByID(vs, it.signerID)
		if !ok {
			return contract.New(contract.VerifyFailed, "the record names signer %s, which profile %s no longer lists", it.signerID, p.Name)
		}
		cands = []profile.Variant{sv}
	} else {
		arch := artifact.PEArch(art.Path)
		for _, sv := range vs {
			if sv.Select.Matches(it.rel, arch) {
				cands = append(cands, sv)
			}
		}
		if len(cands) == 0 {
			return contract.New(contract.VerifyFailed, "no signer of profile %s covers %s", p.Name, it.rel)
		}
	}
	var problems []string
	for _, sv := range cands {
		be, err := s.backendFor(sv.Profile, profile.Windows)
		if err != nil {
			return err
		}
		if c := be.Capability(s.Host); !c.Verify {
			return contract.New(contract.Unavailable, "windows signatures cannot be verified on this host: %s", c.Reason)
		}
		err = be.Verify(ctx, art, sv.Profile)
		if err == nil {
			v.SignerID = sv.ID
			return nil
		}
		problems = append(problems, sv.ID+": "+err.Error())
	}
	return contract.New(contract.VerifyFailed, "%s is not signed by any signer of profile %s: %s", it.rel, p.Name, strings.Join(problems, "; "))
}
