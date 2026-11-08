package signing

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sangehq/imprimatur/src/internal/artifact"
	"github.com/sangehq/imprimatur/src/internal/backend"
	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/profile"
)

// Service signs and verifies.
type Service struct {
	Host    backend.Host
	Store   profile.Store
	Version string
	Log     io.Writer // human lines (stderr)
	// BackendFor builds a backend; nil uses backend.For. Tests replace it.
	BackendFor func(h backend.Host, p profile.Profile, platform string) (backend.Backend, error)
}

func (s *Service) backendFor(p profile.Profile, platform string) (backend.Backend, error) {
	if s.BackendFor != nil {
		return s.BackendFor(s.Host, p, platform)
	}
	return backend.For(s.Host, p, platform)
}

func (s *Service) logf(format string, args ...any) {
	if s.Log != nil {
		_, _ = fmt.Fprintf(s.Log, format+"\n", args...)
	}
}

// SignOptions is one signing run.
type SignOptions struct {
	Root      string
	Manifest  string
	Commit    string
	Tree      string
	Profile   string
	Purpose   string
	Platforms []string
	Repo      string
	Strict    bool
}

// LoadProfile resolves a profile and refuses one that is not valid.
func (s *Service) LoadProfile(name string, code contract.Code) (profile.Profile, error) {
	p, err := s.Store.Resolve(name)
	if err != nil {
		return profile.Profile{}, err
	}
	raw, err := s.Store.Raw(p.Name)
	if err != nil {
		return profile.Profile{}, err
	}
	if _, ps, err := profile.Check(raw); err != nil {
		return profile.Profile{}, err
	} else if len(ps) > 0 {
		return profile.Profile{}, contract.New(code, "signing profile %s is not valid", p.Name).WithDetails(ps.Strings()...).
			WithFix("impr profile validate "+p.Name, "impr profile edit "+p.Name+" --set KEY=VALUE")
	}
	return p, nil
}

type work struct {
	platform string
	be       backend.Backend
	files    []backend.Artifact // windows and macos: the manifest files of that kind
}

// Sign signs the files a build manifest lists. Nothing is signed until every
// check has passed: the manifest's commit and tree, the profile's validity,
// purpose and allowed repositories, every file's digest, the host's
// capability and every certificate's presence and expiry.
func (s *Service) Sign(ctx context.Context, o SignOptions) (Result, error) {
	root, err := absRoot(o.Root)
	if err != nil {
		return Result{}, err
	}
	s.Host.Root = root
	bm, err := artifact.ReadManifest(o.Manifest)
	if err != nil {
		return Result{}, err
	}
	if o.Commit == "" || o.Tree == "" {
		return Result{}, contract.New(contract.Usage, "--commit and --tree are required with --manifest").
			WithDetails("A signing run is bound to the commit and tree the build manifest records.")
	}
	if o.Commit != bm.Commit || o.Tree != bm.Tree {
		return Result{}, contract.New(contract.SignFailed, "--commit %s --tree %s is not the build manifest's (%s, %s); nothing was signed", o.Commit, o.Tree, bm.Commit, bm.Tree)
	}
	p, err := s.LoadProfile(o.Profile, contract.SignFailed)
	if err != nil {
		return Result{}, err
	}
	purpose := profile.Purpose(o.Purpose)
	if o.Purpose == "" || !purpose.Valid() {
		return Result{}, contract.New(contract.Usage, "--purpose release, test or internal is required").
			WithDetails("imprimatur never guesses what a signature is for: a test certificate must never reach a release.")
	}
	if !p.HasPurpose(purpose) {
		return Result{}, contract.New(contract.SignFailed, "signing profile %s is for %v, not %s", p.Name, p.Purpose, purpose).
			WithDetails("A test profile never signs a release, and a release profile signs other builds only when its purposes say so.").
			WithFix("use a profile whose purpose is " + string(purpose))
	}
	if purpose == profile.PurposeRelease && p.HasPurpose(profile.PurposeTest) {
		return Result{}, contract.New(contract.SignFailed, "test profile %s can never sign a release", p.Name)
	}
	if o.Repo != "" {
		if !p.AllowsRepo(o.Repo) {
			return Result{}, contract.New(contract.SignFailed, "signing profile %s may not sign %s", p.Name, repoLabel(o.Repo)).
				WithDetails("It is not in the profile's allowedRepos.").WithFix("impr profile show " + p.Name)
		}
	} else if purpose == profile.PurposeRelease {
		return Result{}, contract.New(contract.Usage, "--repo is required to sign a release").
			WithDetails("A release profile signs only the repositories in its allowedRepos.")
	}
	platforms := o.Platforms
	if len(platforms) == 0 {
		platforms = p.Platforms.Names()
	}
	for _, pl := range platforms {
		if !slices.Contains(profile.AllPlatforms(), pl) {
			return Result{}, contract.New(contract.Usage, "%q is not a platform (%s)", pl, strings.Join(profile.AllPlatforms(), ", "))
		}
		if !p.Platforms.Has(pl) {
			return Result{}, contract.New(contract.Usage, "signing profile %s has no %s configuration", p.Name, pl).
				WithFix("impr profile edit " + p.Name + " --set platforms." + pl + ".kind=...")
		}
	}

	// Every file is checked before anything is signed.
	files := map[string][]backend.Artifact{}
	inputs := map[string]string{}
	for _, a := range bm.Artifacts {
		path, err := artifact.Resolve(root, a.Path)
		if err != nil {
			return Result{}, err
		}
		sum, err := artifact.SHA256(path)
		if err != nil {
			return Result{}, err
		}
		if sum != strings.ToLower(a.SHA256) {
			return Result{}, contract.New(contract.SignFailed, "%s differs from the build manifest; nothing was signed", a.Path).
				WithDetails("manifest "+strings.ToLower(a.SHA256), "on disk  "+sum).WithFix("rebuild, then sign the new build manifest")
		}
		inputs[a.Path] = sum
		k, err := artifact.KindOf(path)
		if err != nil {
			return Result{}, err
		}
		files[string(k)] = append(files[string(k)], backend.Artifact{Path: path, Rel: a.Path})
	}

	var plan []work
	var skipped []string
	for _, pl := range platforms {
		w := work{platform: pl}
		switch pl {
		case profile.Windows, profile.MacOS:
			w.files = files[pl]
			if len(w.files) == 0 {
				s.logf("sign      %s: no %s files in the build manifest", pl, pl)
				continue
			}
		}
		be, err := s.backendFor(p, pl)
		if err != nil {
			return Result{}, err
		}
		w.be = be
		c := be.Capability(s.Host)
		if !c.Sign {
			if o.Strict {
				return Result{}, contract.New(contract.Unavailable, "%s signing is not available on this host: %s; nothing was signed", pl, c.Reason).
					WithFix("run the sign stage on a host or runner that can sign " + pl)
			}
			skipped = append(skipped, pl+": "+c.Reason)
			continue
		}
		if err := backend.Preflight(ctx, be, p); err != nil {
			return Result{}, err
		}
		if err := s.certificateUsable(ctx, be, p, pl); err != nil {
			return Result{}, err
		}
		plan = append(plan, w)
	}

	m := Manifest{Schema: ManifestSchema, Signer: "imprimatur " + s.Version, Profile: p.Name, Purpose: purpose, Identity: p.Pinned(),
		Commit: bm.Commit, Tree: bm.Tree, Repo: o.Repo, BuildManifestDigest: bm.Digest,
		Artifacts: []SignedArtifact{}, Outputs: []SignedArtifact{}, Skipped: skipped}
	m.IdentityDigest = m.Identity.Digest()
	signed := map[string]int{} // manifest path -> index in m.Artifacts

	// Binaries first: Windows, then macOS with one notarisation for them all.
	for _, w := range plan {
		if w.platform != profile.Windows && w.platform != profile.MacOS {
			continue
		}
		for _, f := range w.files {
			sig, err := w.be.Sign(ctx, f, p)
			if err != nil {
				return Result{}, err
			}
			signed[f.Rel] = len(m.Artifacts)
			m.Artifacts = append(m.Artifacts, SignedArtifact{Path: f.Rel, InputSHA256: inputs[f.Rel], Platform: w.platform,
				Kind: sig.Kind, Signer: sig.Signer, Timestamp: sig.Timestamp})
			s.logf("sign      %s  %s, %s", f.Rel, sig.Kind, sig.Signer)
		}
		if ap, ok := w.be.(*backend.Apple); ok && ap.Spec.Notary != nil {
			ticket, err := ap.Notarize(ctx, w.files)
			if err != nil {
				return Result{}, err
			}
			for _, f := range w.files {
				m.Artifacts[signed[f.Rel]].Notarization = ticket
			}
			s.logf("notarise  %d file(s), submission %s", len(w.files), ticket)
		}
	}
	for i, a := range m.Artifacts {
		path, err := artifact.Resolve(root, a.Path)
		if err != nil {
			return Result{}, err
		}
		if m.Artifacts[i].OutputSHA256, err = artifact.SHA256(path); err != nil {
			return Result{}, err
		}
	}

	// Then the checksum file, over the bytes that will be published.
	var sumsPlan []work
	for _, w := range plan {
		if w.platform == profile.Checksums || w.platform == profile.Containers || w.platform == profile.Attestations {
			sumsPlan = append(sumsPlan, w)
		}
	}
	if len(sumsPlan) > 0 {
		var lines [][2]string
		for _, a := range bm.Artifacts {
			sum := inputs[a.Path]
			if i, ok := signed[a.Path]; ok {
				sum = m.Artifacts[i].OutputSHA256
			}
			lines = append(lines, [2]string{sum, a.Path})
		}
		sumsPath := filepath.Join(bm.Dir, SumsFile)
		if err := os.WriteFile(sumsPath, artifact.Checksums(lines), 0o644); err != nil { //nolint:gosec // G306: a published checksum file
			return Result{}, err
		}
		sumsRel := artifact.RelToRoot(root, sumsPath)
		sumsSHA, err := artifact.SHA256(sumsPath)
		if err != nil {
			return Result{}, err
		}
		m.Outputs = append(m.Outputs, SignedArtifact{Path: sumsRel, OutputSHA256: sumsSHA, Platform: profile.Checksums, Kind: "sha256sums"})
		for _, w := range sumsPlan {
			sig, err := w.be.Sign(ctx, backend.Artifact{Path: sumsPath, Rel: sumsRel}, p)
			if err != nil {
				return Result{}, err
			}
			for _, out := range sig.Outputs {
				sum, err := artifact.SHA256(out.Path)
				if err != nil {
					return Result{}, err
				}
				m.Outputs = append(m.Outputs, SignedArtifact{Path: artifact.RelToRoot(root, out.Path), OutputSHA256: sum,
					Platform: w.platform, Kind: out.Kind, Signer: sig.Signer})
			}
			s.logf("sign      %s  %s, %s", sumsRel, sig.Kind, sig.Signer)
		}
	}

	m.SignedAt = s.Host.Now().UTC()
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return Result{}, err
	}
	mpath := filepath.Join(bm.Dir, ManifestFile)
	if err := os.WriteFile(mpath, append(b, '\n'), 0o644); err != nil { //nolint:gosec // G306: the chain-of-custody record is published with the release
		return Result{}, err
	}
	msum, err := artifact.SHA256(mpath)
	if err != nil {
		return Result{}, err
	}
	res := Result{Contract: contract.Version, OK: len(skipped) == 0, Manifest: m, ManifestPath: mpath, ManifestSHA256: msum, Skipped: skipped}
	if len(skipped) > 0 {
		return res, contract.New(contract.Skipped, "%d platform(s) were skipped", len(skipped)).WithDetails(skipped...)
	}
	return res, nil
}

// certificateUsable refuses an expired certificate or one this host does not
// have, before anything is signed.
func (s *Service) certificateUsable(ctx context.Context, be backend.Backend, p profile.Profile, pl string) error {
	e := be.Certificate(ctx, p)
	if e.NotAfter != nil && !s.Host.Now().Before(*e.NotAfter) {
		return contract.New(contract.SignFailed, "the %s certificate of profile %s expired on %s; nothing was signed", pl, p.Name, e.NotAfter.Format("2006-01-02")).
			WithFix("renew it, then re-pin the profile: impr profile edit " + p.Name + " --set platforms." + pl + "...")
	}
	switch e.Source {
	case "store", "keychain", "gpg", "file":
		if !e.Present {
			return contract.New(contract.Unavailable, "the %s certificate or key of profile %s is not available on this host; nothing was signed", pl, p.Name).
				WithFix("impr cert list", "import the certificate or key, or check its reference: impr profile show "+p.Name)
		}
	}
	return nil
}

func absRoot(root string) (string, error) {
	if root == "" {
		root = "."
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(abs)
	if err != nil || !st.IsDir() {
		return "", contract.New(contract.Usage, "--root %s is not a directory", root)
	}
	return abs, nil
}

func repoLabel(u string) string {
	if id := profile.RepoIdentity(u); id != "" {
		return id
	}
	return "that push target"
}
