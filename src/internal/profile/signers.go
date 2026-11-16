package profile

import (
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Arches are the PE machine names a selector may name.
var Arches = []string{"386", "amd64", "arm", "arm64"}

var signerIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)

func (w WindowsSpec) validateSigners(ref func(field, v string, required bool)) Problems {
	var ps Problems
	for field, v := range map[string]string{"backend": w.Backend, "certRef": w.CertRef, "subject": w.Subject, "thumbprint": w.Thumbprint,
		"dlibPath": w.DlibPath, "metadataPath": w.MetadataPath, "passwordRef": w.PasswordRef, "timestamp": w.Timestamp} {
		if v != "" {
			ps.add("platforms.windows."+field, "with signers, %s belongs in each signer, not beside them", field)
		}
	}
	switch w.Mode {
	case "", "select":
	case "all":
		ps.add("platforms.windows.mode", "mode all (dual signing) is not supported yet; use select")
	default:
		ps.add("platforms.windows.mode", "%q is not select", w.Mode)
	}
	ids := map[string]bool{}
	for i, sg := range w.Signers {
		at := fmt.Sprintf("platforms.windows.signers[%d]", i)
		if !signerIDRe.MatchString(sg.ID) || ids[sg.ID] {
			ps.add(at+".id", "each signer has a unique id (lower-case letters, digits, . _ -)")
		}
		ids[sg.ID] = true
		if !slices.Contains(WindowsBackends(), sg.Backend) {
			ps.add(at+".backend", "%q is not %s", sg.Backend, strings.Join(WindowsBackends(), ", "))
		}
		ref(at+".certRef", sg.CertRef, sg.Backend == BackendPFX)
		ref(at+".passwordRef", sg.PasswordRef, false)
		if sg.Thumbprint == "" && sg.Subject == "" {
			ps.add(at+".pin", "pin the certificate by thumbprint or exact subject")
		}
		if (sg.Backend == BackendCertStore || sg.Backend == BackendCertum) && sg.Thumbprint == "" {
			ps.add(at+".thumbprint", "a %s certificate is pinned by its SHA-1 thumbprint; a subject alone is ambiguous", sg.Backend)
		}
		if sg.Thumbprint != "" && !thumbprintRe.MatchString(sg.Thumbprint) {
			ps.add(at+".thumbprint", "%q is not a 40-hex SHA-1 thumbprint", sg.Thumbprint)
		}
		if sg.NotBefore != nil && sg.NotAfter != nil && !sg.NotBefore.Before(*sg.NotAfter) {
			ps.add(at+".notBefore", "notBefore is not before notAfter")
		}
		if sg.Select != nil {
			for _, a := range sg.Select.Arch {
				if !slices.Contains(Arches, a) {
					ps.add(at+".select.arch", "%q is not %s", a, strings.Join(Arches, ", "))
				}
			}
			for _, g := range sg.Select.Glob {
				if _, err := path.Match(g, "x"); err != nil || g == "" {
					ps.add(at+".select.glob", "%q is not a glob", g)
				}
			}
		}
	}
	return ps
}

// Variant is one certificate of a profile's Windows spec, as a profile that
// holds only that certificate, so every backend runs unchanged on it.
type Variant struct {
	ID      string
	Profile Profile
	Select  *Selector
	// Dated is true for a listed signer: its notBefore/notAfter decide when
	// it may sign. A single-certificate spec keeps its own expiry check.
	Dated               bool
	NotBefore, NotAfter *time.Time
}

// DefaultSigner is the id of a single-certificate spec's only variant.
const DefaultSigner = "default"

// WindowsVariants expands the Windows spec into one variant per certificate.
func (p Profile) WindowsVariants() []Variant {
	w := p.Platforms.Windows
	if w == nil {
		return nil
	}
	if len(w.Signers) == 0 {
		return []Variant{{ID: DefaultSigner, Profile: p}}
	}
	out := make([]Variant, 0, len(w.Signers))
	for _, sg := range w.Signers {
		q := p
		spec := WindowsSpec{Kind: w.Kind, Backend: sg.Backend, CertRef: sg.CertRef, Subject: sg.Subject, Thumbprint: sg.Thumbprint,
			Timestamp: sg.Timestamp, DlibPath: sg.DlibPath, MetadataPath: sg.MetadataPath, PasswordRef: sg.PasswordRef, NotAfter: sg.NotAfter}
		q.Platforms.Windows = &spec
		out = append(out, Variant{ID: sg.ID, Profile: q, Select: sg.Select, Dated: true, NotBefore: sg.NotBefore, NotAfter: sg.NotAfter})
	}
	return out
}

// Matches reports whether a selector picks a file, by its manifest path and
// PE architecture ("" when unknown, which no arch list matches).
func (s *Selector) Matches(rel, arch string) bool {
	if s == nil {
		return true
	}
	if len(s.Arch) > 0 && !slices.Contains(s.Arch, arch) {
		return false
	}
	if len(s.Glob) > 0 {
		base := path.Base(filepath.ToSlash(rel))
		ok := false
		for _, g := range s.Glob {
			if m, _ := path.Match(g, base); m {
				ok = true
			}
			if m, _ := path.Match(g, filepath.ToSlash(rel)); m {
				ok = true
			}
		}
		return ok
	}
	return true
}

// Choose picks exactly one variant to sign a file at a time. A listed signer
// is eligible when its selector matches and now is inside its dates. With
// none eligible, or more than one, it fails: there is never a first match.
// The one exception is a rotation: when every eligible signer declares
// notBefore, the newest wins.
func Choose(vs []Variant, rel, arch string, now time.Time) (Variant, error) {
	var cands []Variant
	for _, v := range vs {
		if !v.Select.Matches(rel, arch) {
			continue
		}
		if v.Dated && ((v.NotBefore != nil && now.Before(*v.NotBefore)) || (v.NotAfter != nil && !now.Before(*v.NotAfter))) {
			continue
		}
		cands = append(cands, v)
	}
	switch len(cands) {
	case 0:
		return Variant{}, fmt.Errorf("no signer of the profile may sign %s (arch %q) now", rel, arch)
	case 1:
		return cands[0], nil
	}
	newest, ids := cands[0], []string{}
	for _, c := range cands {
		ids = append(ids, c.ID)
		if c.NotBefore == nil {
			return Variant{}, fmt.Errorf("%s matches several signers (%s); narrow their selectors, or give each a notBefore for a rotation", rel, strings.Join(ids, ", "))
		}
		if c.NotBefore.After(*newest.NotBefore) {
			newest = c
		}
	}
	for _, c := range cands {
		if c.ID != newest.ID && c.NotBefore.Equal(*newest.NotBefore) {
			return Variant{}, fmt.Errorf("%s matches signers %s and %s with the same notBefore", rel, newest.ID, c.ID)
		}
	}
	return newest, nil
}

// VariantByID finds a variant, for verifying a record that names its signer.
func VariantByID(vs []Variant, id string) (Variant, bool) {
	for _, v := range vs {
		if v.ID == id {
			return v, true
		}
	}
	return Variant{}, false
}
