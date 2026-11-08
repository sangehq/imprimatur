package profile

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/sangehq/imprimatur/src/internal/contract"
)

// LegacySettingsFile is the PowerShell line's settings file name.
const LegacySettingsFile = "imprimatur.settings.json"

// LegacyKeys are the settings the PowerShell line saved.
var LegacyKeys = []string{"WINDOWS_SIGNER", "WINDOWS_SIGN_THUMBPRINT", "WINDOWS_SIGN_SUBJECT", "CERTUM_SUBJECT",
	"ARTIFACT_DLIB", "ARTIFACT_METADATA", "GPG_FINGERPRINT"}

// LegacyMacOSVars are the environment variables the PowerShell line read for
// macOS signing. They were never saved (they hold secrets), so migration
// records references to them, never their values.
var LegacyMacOSVars = []string{"MACOS_SIGN_P12", "MACOS_SIGN_PASSWORD", "MACOS_NOTARY_ISSUER_ID", "MACOS_NOTARY_KEY_ID", "MACOS_NOTARY_KEY"}

// LegacyEnv is what discovery and migration read from the host.
type LegacyEnv struct {
	GOOS      string
	Home      string
	User      string
	ConfigDir string // imprimatur's own config directory
	Getenv    func(string) string
	Now       func() time.Time
}

// FindLegacy locates the PowerShell line's config: IMPR_LEGACY_CONFIG (a
// directory or the settings file; "off" disables discovery), the toolkit an
// installed ~/.local/bin/impr or imprimatur link points into, or a settings
// file copied into imprimatur's own config directory. "" when there is none.
func FindLegacy(e LegacyEnv) string {
	if v := e.Getenv("IMPR_LEGACY_CONFIG"); v != "" {
		if v == "off" {
			return ""
		}
		return v
	}
	if e.Home != "" {
		for _, name := range []string{"impr", "imprimatur"} {
			link := filepath.Join(e.Home, ".local", "bin", name)
			target, err := filepath.EvalSymlinks(link)
			if err != nil {
				continue
			}
			root := filepath.Dir(filepath.Dir(target)) // <toolkit>/bin/impr
			if _, err := os.Stat(filepath.Join(root, "src", "impr.ps1")); err == nil {
				return filepath.Join(root, "config")
			}
		}
	}
	if e.ConfigDir != "" {
		if _, err := os.Stat(filepath.Join(e.ConfigDir, LegacySettingsFile)); err == nil {
			return filepath.Join(e.ConfigDir, LegacySettingsFile)
		}
	}
	return ""
}

// LegacyReport is what an import did.
type LegacyReport struct {
	Contract int                 `json:"contract"`
	Source   string              `json:"source"`
	Imported []string            `json:"imported"`
	Skipped  []string            `json:"skipped,omitempty"`
	Default  string              `json:"default,omitempty"`
	Problems map[string][]string `json:"problems,omitempty"`
	Notes    []string            `json:"notes,omitempty"`
}

var ownerSafe = regexp.MustCompile(`[^a-z0-9._-]`)

// ImportLegacy brings the PowerShell line's configuration into the store:
// its signing profiles and default when it has them, otherwise its single
// settings file as one profile named "default", which becomes the default.
// The macOS variables become a separate profile, "default-macos", holding
// references to them. Existing profiles are never replaced. The source is
// only read.
func ImportLegacy(s Store, source string, e LegacyEnv) (LegacyReport, error) {
	rep := LegacyReport{Contract: contract.Version, Source: source, Imported: []string{}, Problems: map[string][]string{}}
	dir, settingsPath := source, ""
	if st, err := os.Stat(source); err != nil {
		return rep, contract.Wrap(contract.Usage, err, "the legacy configuration %s cannot be read", source).
			WithFix("impr profile import-legacy --from <toolkit>/config")
	} else if !st.IsDir() {
		dir, settingsPath = filepath.Dir(source), source
	} else {
		settingsPath = filepath.Join(dir, LegacySettingsFile)
	}
	idx, _, err := s.LoadIndex()
	if err != nil {
		return rep, err
	}
	legacyDefault := ""
	// 1. Profiles the PowerShell 1.8.x line already had.
	if entries, err := os.ReadDir(filepath.Join(dir, "profiles")); err == nil {
		var names []string
		for _, en := range entries {
			if n, ok := strings.CutSuffix(en.Name(), ".json"); ok && ValidName(n) {
				names = append(names, n)
			}
		}
		sort.Strings(names)
		for _, n := range names {
			b, err := os.ReadFile(filepath.Join(dir, "profiles", n+".json")) //nolint:gosec // G304: a profile file in the legacy config the user named
			if err != nil {
				return rep, err
			}
			p, ps, err := Check(b)
			if err != nil {
				rep.Skipped = append(rep.Skipped, n+": "+err.Error())
				continue
			}
			if p.Name != n {
				rep.Skipped = append(rep.Skipped, n+": the file names profile "+p.Name)
				continue
			}
			if err := s.importOne(p, ps, &rep); err != nil {
				return rep, err
			}
		}
		var li Index
		if b, err := os.ReadFile(filepath.Join(dir, "profiles.json")); err == nil { //nolint:gosec // G304: the legacy index the user named
			if json.Unmarshal(b, &li) == nil {
				legacyDefault = li.Default
			}
		}
	}
	// 2. The settings file, when there were no profiles to bring.
	if len(rep.Imported) == 0 && len(rep.Skipped) == 0 {
		settings, err := readLegacySettings(settingsPath, &rep)
		if err != nil {
			return rep, err
		}
		if p := settingsProfile(settings, e); p != nil {
			if err := s.importOne(*p, p.Validate(), &rep); err != nil {
				return rep, err
			}
			legacyDefault = p.Name
		}
	}
	// 3. The macOS variables, as references only.
	if p := macOSProfile(e); p != nil {
		if err := s.importOne(*p, p.Validate(), &rep); err != nil {
			return rep, err
		}
		rep.Notes = append(rep.Notes, "the MACOS_* variables became profile default-macos (references only); set platforms.macos.teamId and identity, then use --profile default-macos")
	}
	if idx.Default == "" && legacyDefault != "" {
		if _, ok, _ := s.Get(legacyDefault); ok {
			idx.Default = legacyDefault
			rep.Default = legacyDefault
		}
	}
	idx.MigratedFrom = source
	idx.MigratedAt = e.Now().UTC().Format(time.RFC3339)
	if err := s.SaveIndex(idx); err != nil {
		return rep, err
	}
	if len(rep.Problems) == 0 {
		rep.Problems = nil
	}
	return rep, nil
}

func (s Store) importOne(p Profile, ps Problems, rep *LegacyReport) error {
	if _, ok, err := s.Get(p.Name); err != nil {
		return err
	} else if ok {
		rep.Skipped = append(rep.Skipped, p.Name+": a profile with that name already exists; kept it")
		return nil
	}
	if err := s.WriteUnchecked(p); err != nil {
		return err
	}
	rep.Imported = append(rep.Imported, p.Name)
	if len(ps) > 0 {
		rep.Problems[p.Name] = ps.Strings()
	}
	return nil
}

func readLegacySettings(path string, rep *LegacyReport) (map[string]string, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: the legacy settings file the user named or that was found
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, contract.Wrap(contract.Usage, err, "%s is not valid JSON", path).WithFix("fix its syntax, then run impr profile import-legacy")
	}
	out := map[string]string{}
	for k, v := range raw {
		known := false
		for _, l := range LegacyKeys {
			known = known || l == k
		}
		if !known {
			rep.Notes = append(rep.Notes, "ignored unknown setting "+k)
			continue
		}
		if s, ok := v.(string); ok {
			out[k] = strings.TrimSpace(s)
		}
	}
	sort.Strings(rep.Notes)
	return out, nil
}

func ownerOf(e LegacyEnv) string {
	o := ownerSafe.ReplaceAllString(strings.ToLower(e.User), "-")
	if o == "" {
		o = "me"
	}
	return o
}

// settingsProfile maps the 1.8 settings to one profile, as the PowerShell
// line's own migration does: the test certificate becomes an explicit
// personal test profile that can never sign a release; Certum and Artifact
// Signing become internal profiles to finish (pin, allowedRepos, then
// release); a GPG key becomes the checksum key.
func settingsProfile(st map[string]string, e LegacyEnv) *Profile {
	signer := strings.ToLower(st["WINDOWS_SIGNER"])
	if signer == "" && e.GOOS == "windows" && len(st) > 0 {
		signer = "selfsigned"
	}
	owner := ownerOf(e)
	var p *Profile
	switch signer {
	case "selfsigned":
		subject := st["WINDOWS_SIGN_SUBJECT"]
		if subject == "" {
			subject = "CN=" + e.User + " Code Signing (Test)"
		}
		w := &WindowsSpec{Kind: "authenticode", Backend: BackendCertStore, Subject: subject, Thumbprint: st["WINDOWS_SIGN_THUMBPRINT"]}
		p = &Profile{Name: "default", Scope: ScopePersonal, Owner: owner, Purpose: []Purpose{PurposeTest}, Platforms: Platforms{Windows: w},
			Notes: "Migrated from imprimatur.settings.json: the self-signed test certificate. It can never sign a release."}
	case "certum":
		w := &WindowsSpec{Kind: "authenticode", Backend: BackendCertum, Subject: st["CERTUM_SUBJECT"]}
		if w.Subject != "" && !strings.Contains(w.Subject, "=") {
			w.Subject = "CN=" + w.Subject
		}
		p = &Profile{Name: "default", Scope: ScopePersonal, Owner: owner, Purpose: []Purpose{PurposeInternal}, Platforms: Platforms{Windows: w},
			Notes: "Migrated from imprimatur.settings.json. Pin the thumbprint and add allowedRepos, then add release to purpose."}
	case "artifact":
		w := &WindowsSpec{Kind: "authenticode", Backend: BackendAzure, DlibPath: st["ARTIFACT_DLIB"], MetadataPath: st["ARTIFACT_METADATA"]}
		p = &Profile{Name: "default", Scope: ScopePersonal, Owner: owner, Purpose: []Purpose{PurposeInternal}, Platforms: Platforms{Windows: w},
			Notes: "Migrated from imprimatur.settings.json. Pin the certificate subject and add allowedRepos, then add release to purpose."}
	}
	if fpr := st["GPG_FINGERPRINT"]; fpr != "" {
		if p == nil {
			p = &Profile{Name: "default", Scope: ScopePersonal, Owner: owner, Purpose: []Purpose{PurposeInternal},
				Notes: "Migrated from imprimatur.settings.json."}
		}
		p.Platforms.Checksums = &ChecksumSpec{Kind: "gpg", KeyRef: "gpg-agent://" + fpr, Fingerprint: fpr}
	}
	return p
}

// macOSProfile records the MACOS_* variables that are set, as env://
// references.
func macOSProfile(e LegacyEnv) *Profile {
	set := map[string]bool{}
	for _, v := range LegacyMacOSVars {
		set[v] = e.Getenv(v) != ""
	}
	if !set["MACOS_SIGN_P12"] && !set["MACOS_NOTARY_KEY"] {
		return nil
	}
	m := &MacOSSpec{Kind: "developer-id"}
	if set["MACOS_SIGN_P12"] {
		m.CertRef = "env://MACOS_SIGN_P12"
	}
	if set["MACOS_NOTARY_KEY"] {
		m.Notary = &NotarySpec{APIKeyRef: "env://MACOS_NOTARY_KEY"} //nolint:gosec // G101: the name of a variable, not a credential
		if set["MACOS_NOTARY_KEY_ID"] {
			m.Notary.KeyID = "env://MACOS_NOTARY_KEY_ID"
		}
		if set["MACOS_NOTARY_ISSUER_ID"] {
			m.Notary.Issuer = "env://MACOS_NOTARY_ISSUER_ID"
		}
	}
	return &Profile{Name: "default-macos", Scope: ScopePersonal, Owner: ownerOf(e), Purpose: []Purpose{PurposeInternal},
		Platforms: Platforms{MacOS: m},
		Notes:     "Migrated from the MACOS_* environment variables (references only). Set teamId and identity."}
}
