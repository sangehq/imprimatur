package signing

import (
	"context"

	"github.com/sangehq/imprimatur/src/internal/backend"
	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/profile"
)

// CertList is `impr cert list --json`.
type CertList struct {
	Contract     int                 `json:"contract"`
	Certificates []backend.CertEntry `json:"certificates"`
}

// Certificates lists every certificate or key the profiles use.
func (s *Service) Certificates(ctx context.Context) (CertList, error) {
	ps, err := s.Store.List()
	if err != nil {
		return CertList{}, err
	}
	out := CertList{Contract: contract.Version, Certificates: []backend.CertEntry{}}
	for _, p := range ps {
		for _, pl := range p.Platforms.Names() {
			if pl == profile.Attestations {
				continue
			}
			if pl == profile.Windows {
				// One entry per certificate: a multi-certificate spec lists each signer.
				for _, v := range p.WindowsVariants() {
					be, err := s.backendFor(v.Profile, pl)
					if err != nil {
						continue
					}
					e := be.Certificate(ctx, v.Profile)
					if v.Dated {
						e.Signer = v.ID
					}
					out.Certificates = append(out.Certificates, e)
				}
				continue
			}
			be, err := s.backendFor(p, pl)
			if err != nil {
				continue
			}
			out.Certificates = append(out.Certificates, be.Certificate(ctx, p))
		}
	}
	return out, nil
}

// ProfileCapability is what one profile can do on this host.
type ProfileCapability struct {
	Name      string                        `json:"name"`
	Valid     bool                          `json:"valid"`
	Problems  []string                      `json:"problems,omitempty"`
	Platforms map[string]backend.Capability `json:"platforms"`
	// Ready lists the platforms this host can sign for with the profile.
	Ready []string `json:"ready"`
}

// CapabilityReport is `impr profile capabilities --json`.
type CapabilityReport struct {
	Contract int                 `json:"contract"`
	Host     string              `json:"host"`
	Profiles []ProfileCapability `json:"profiles"`
}

// Capabilities reports, per profile, which platform kinds work here.
func (s *Service) Capabilities(_ context.Context, name string) (CapabilityReport, error) {
	var ps []profile.Profile
	if name != "" {
		p, err := s.Store.Resolve(name)
		if err != nil {
			return CapabilityReport{}, err
		}
		ps = []profile.Profile{p}
	} else {
		all, err := s.Store.List()
		if err != nil {
			return CapabilityReport{}, err
		}
		ps = all
	}
	rep := CapabilityReport{Contract: contract.Version, Host: HostName(s.Host.GOOS), Profiles: []ProfileCapability{}}
	for _, p := range ps {
		pc := ProfileCapability{Name: p.Name, Platforms: map[string]backend.Capability{}, Ready: []string{}}
		if raw, err := s.Store.Raw(p.Name); err == nil {
			if _, probs, err := profile.Check(raw); err == nil {
				pc.Problems = probs.Strings()
			}
		}
		pc.Valid = len(pc.Problems) == 0
		for _, pl := range p.Platforms.Names() {
			if pl == profile.Windows && len(p.Platforms.Windows.Signers) > 0 {
				c := s.windowsCapability(p)
				pc.Platforms[pl] = c
				if c.Sign {
					pc.Ready = append(pc.Ready, pl)
				}
				continue
			}
			be, err := s.backendFor(p, pl)
			if err != nil {
				pc.Platforms[pl] = backend.Capability{Platform: pl, Reason: err.Error()}
				continue
			}
			c := be.Capability(s.Host)
			pc.Platforms[pl] = c
			if c.Sign {
				pc.Ready = append(pc.Ready, pl)
			}
		}
		rep.Profiles = append(rep.Profiles, pc)
	}
	return rep, nil
}

// HostCapabilities reports which platform kinds this host can sign at all,
// across every backend imprimatur has, and per backend.
func HostCapabilities(h backend.Host) (platforms map[string]bool, backends map[string]bool) {
	platforms = map[string]bool{}
	backends = map[string]bool{}
	for _, b := range profile.WindowsBackends() {
		ok := (&backend.Authenticode{H: h, Spec: profile.WindowsSpec{Backend: b}}).Capability(h).Sign
		backends["authenticode/"+b] = ok
		platforms[profile.Windows] = platforms[profile.Windows] || ok
	}
	ok := (&backend.Apple{H: h}).Capability(h).Sign
	backends["developer-id/codesign"] = ok
	backends["developer-id/notarytool"] = (&backend.Apple{H: h, Spec: profile.MacOSSpec{Notary: &profile.NotarySpec{}}}).Capability(h).Sign
	platforms[profile.MacOS] = ok
	for kind, be := range map[string]backend.Backend{"gpg": &backend.GPG{H: h}, "minisign": &backend.Minisign{H: h}, "ssh": &backend.SSH{H: h}} {
		ok := be.Capability(h).Sign
		backends["checksums/"+kind] = ok
		platforms[profile.Checksums] = platforms[profile.Checksums] || ok
	}
	ok = (&backend.Cosign{H: h}).Capability(h).Sign
	backends["containers/cosign"] = ok
	platforms[profile.Containers] = ok
	// in-toto is signed by the checksum key or cosign, so it works where either does.
	platforms[profile.Attestations] = platforms[profile.Checksums] || platforms[profile.Containers]
	backends["attestations/in-toto"] = platforms[profile.Attestations]
	return platforms, backends
}

// HostName names the OS the way the contract reports it.
func HostName(goos string) string {
	if goos == "darwin" {
		return "macos"
	}
	return goos
}

// windowsCapability is a multi-certificate spec's capability: ready only when
// every signer can sign here, since which one a run needs depends on its files.
func (s *Service) windowsCapability(p profile.Profile) backend.Capability {
	out := backend.Capability{Platform: profile.Windows, Kind: "authenticode", Supported: true, Sign: true, Verify: true}
	for _, v := range p.WindowsVariants() {
		be, err := s.backendFor(v.Profile, profile.Windows)
		if err != nil {
			return backend.Capability{Platform: profile.Windows, Reason: err.Error()}
		}
		c := be.Capability(s.Host)
		out.Tools = append(out.Tools, c.Tools...)
		if !c.Sign || !c.Verify {
			out.Sign, out.Verify = out.Sign && c.Sign, out.Verify && c.Verify
			if out.Reason == "" {
				out.Reason = "signer " + v.ID + ": " + c.Reason
			}
		}
	}
	return out
}
