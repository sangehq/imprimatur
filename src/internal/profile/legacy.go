package profile

import (
	"encoding/json"
	"errors"
	"io"
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
	"CERTUM_THUMBPRINT", "ARTIFACT_DLIB", "ARTIFACT_METADATA", "GPG_FINGERPRINT"}

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
	if err := movePre14(source, &rep); err != nil {
		return rep, err
	}
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
		if p := settingsProfile(settings, dir, e); p != nil {
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

// FirstRunDefault makes, on a first run on Windows with no PowerShell
// settings at all, the profile the PowerShell line's migration made there
// (Invoke-ProfileMigration, O-120): the self-signed test certificate as the
// personal test profile "default", which can never sign a release, and the
// default. It reports what it did; elsewhere it does nothing.
func FirstRunDefault(s Store, e LegacyEnv) (LegacyReport, error) {
	rep := LegacyReport{Contract: contract.Version, Source: "first run on Windows", Imported: []string{}, Problems: map[string][]string{}}
	if e.GOOS != "windows" {
		return rep, nil
	}
	idx, _, err := s.LoadIndex()
	if err != nil {
		return rep, err
	}
	p := settingsProfile(map[string]string{"WINDOWS_SIGNER": "SelfSigned"}, "", e)
	p.Notes = "Made on impr's first run on Windows, as the PowerShell line did: the self-signed test certificate. It can never sign a release."
	if err := s.importOne(*p, p.Validate(), &rep); err != nil {
		return rep, err
	}
	if idx.Default == "" && len(rep.Imported) == 1 {
		idx.Default, rep.Default = p.Name, p.Name
	}
	idx.MigratedFrom = rep.Source
	idx.MigratedAt = e.Now().UTC().Format(time.RFC3339)
	if err := s.SaveIndex(idx); err != nil {
		return rep, err
	}
	if len(rep.Problems) == 0 {
		rep.Problems = nil
	}
	return rep, nil
}

// pre14Files are the files impr 1.3 and earlier kept in the toolkit's root,
// which 1.4 moved into config/ (Move-LegacyConfig).
var pre14Files = []string{LegacySettingsFile, ".imprimatur-state.json", "metadata.json"}

// movePre14 moves a pre-1.4 toolkit's files from its root into config/, as
// the PowerShell line did on every run (O-09), so an import from such a
// toolkit finds them. Unlike the rest of import-legacy, which only reads the
// toolkit, this changes the toolkit's own tree: it renames files within it
// (root to config/), copying nothing out and deleting nothing. It acts only
// on configDir named config inside a PowerShell toolkit (one with
// src/impr.ps1). A file already in config/ wins and the old one is left in
// place, reported; the move never replaces one, even one that appears after
// the check (moveNoReplace).
// linkFile is os.Link; a test replaces it to take the copy path.
var linkFile = os.Link

// beforePre14Move is a test seam that runs just before each move, so a test
// can make the target appear between the check and the move.
var beforePre14Move = func(string) {}

func movePre14(configDir string, rep *LegacyReport) error {
	root := filepath.Dir(configDir)
	if filepath.Base(configDir) != "config" {
		return nil
	}
	if _, err := os.Stat(filepath.Join(root, "src", "impr.ps1")); err != nil {
		return nil
	}
	for _, name := range pre14Files {
		from, to := filepath.Join(root, name), filepath.Join(configDir, name)
		if st, err := os.Lstat(from); err != nil || !st.Mode().IsRegular() {
			continue
		}
		if _, err := os.Lstat(to); err == nil {
			rep.Notes = append(rep.Notes, "both "+from+" and "+to+" exist; used "+to+" (delete the old one)")
			continue
		}
		if err := os.MkdirAll(configDir, 0o700); err != nil {
			return err
		}
		beforePre14Move(to)
		if err := moveNoReplace(from, to); err != nil {
			if errors.Is(err, fs.ErrExist) {
				rep.Notes = append(rep.Notes, "both "+from+" and "+to+" exist; used "+to+" (delete the old one)")
				continue
			}
			return contract.Wrap(contract.Unavailable, err, "move %s into %s", from, configDir)
		}
		rep.Notes = append(rep.Notes, "moved "+name+" from the toolkit root (impr 1.3 and earlier) to "+to)
	}
	return nil
}

// moveNoReplace moves from to to, failing with fs.ErrExist rather than
// replacing a file at to: a hard link (which the system refuses atomically
// when to exists) then the old name removed; where links are not supported,
// an exclusive create and a copy.
func moveNoReplace(from, to string) error {
	lerr := linkFile(from, to)
	if lerr == nil {
		return os.Remove(from)
	}
	if errors.Is(lerr, fs.ErrExist) {
		return lerr
	}
	src, err := os.Open(from) //nolint:gosec // G304: a pre-1.4 file in the toolkit the user named
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()
	dst, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: config/ in the same toolkit
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		_ = os.Remove(to)
		return err
	}
	if err := dst.Close(); err != nil {
		_ = os.Remove(to)
		return err
	}
	_ = src.Close()
	return os.Remove(from)
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
func settingsProfile(st map[string]string, dir string, e LegacyEnv) *Profile {
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
		// The PowerShell line read the thumbprint from CERTUM_THUMBPRINT at run
		// time; a settings file may carry it too (O-193).
		thumb := st["CERTUM_THUMBPRINT"]
		if thumb == "" && e.Getenv != nil {
			thumb = e.Getenv("CERTUM_THUMBPRINT")
		}
		thumb = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(thumb), " ", ""))
		w := &WindowsSpec{Kind: "authenticode", Backend: BackendCertum, Subject: st["CERTUM_SUBJECT"], Thumbprint: thumb}
		if w.Subject != "" && !strings.Contains(w.Subject, "=") {
			w.Subject = "CN=" + w.Subject
		}
		p = &Profile{Name: "default", Scope: ScopePersonal, Owner: owner, Purpose: []Purpose{PurposeInternal}, Platforms: Platforms{Windows: w},
			Notes: "Migrated from imprimatur.settings.json. Pin the thumbprint and add allowedRepos, then add release to purpose."}
	case "artifact":
		w := &WindowsSpec{Kind: "authenticode", Backend: BackendAzure, DlibPath: st["ARTIFACT_DLIB"], MetadataPath: st["ARTIFACT_METADATA"]}
		if w.MetadataPath == "" {
			// The PowerShell line's default: metadata.json in its config folder.
			if def := filepath.Join(dir, "metadata.json"); fileExists(def) {
				w.MetadataPath = def
			}
		}
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
	notes := "Migrated from the MACOS_* environment variables (references only). Set teamId and identity."
	if set["MACOS_SIGN_P12"] {
		// impr imports it into a temporary keychain for each run.
		m.CertRef = "env://MACOS_SIGN_P12"
		if set["MACOS_SIGN_PASSWORD"] {
			m.PasswordRef = "env://MACOS_SIGN_PASSWORD"
		}
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
		Notes:     notes}
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}
