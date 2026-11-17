package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sangehq/imprimatur/src/internal/contract"
)

// Store keeps profiles as <dir>/profiles/<name>.json and the default in
// <dir>/profiles.json.
type Store struct {
	Dir string // the imprimatur config directory
}

// Index is profiles.json.
type Index struct {
	Default      string `json:"default,omitempty"`
	MigratedFrom string `json:"migratedFrom,omitempty"`
	MigratedAt   string `json:"migratedAt,omitempty"`
}

func (s Store) profilesDir() string { return filepath.Join(s.Dir, "profiles") }

// IndexPath is profiles.json.
func (s Store) IndexPath() string { return filepath.Join(s.Dir, "profiles.json") }

// Path is a profile's file. The name is checked first, so it cannot leave
// the directory.
func (s Store) Path(name string) (string, error) {
	if !ValidName(name) {
		return "", contract.New(contract.Usage, "%q is not a profile name", name).
			WithDetails("Profile names are lower-case letters, digits, dot, underscore and dash, up to 64.").
			WithFix("impr profile list")
	}
	return filepath.Join(s.profilesDir(), name+".json"), nil
}

// Get reads one profile. ok is false when there is none.
func (s Store) Get(name string) (p Profile, ok bool, err error) {
	path, err := s.Path(name)
	if err != nil {
		return Profile{}, false, err
	}
	b, err := os.ReadFile(path) //nolint:gosec // G304: a checked profile name under the config directory
	if errors.Is(err, fs.ErrNotExist) {
		return Profile{}, false, nil
	}
	if err != nil {
		return Profile{}, false, err
	}
	p, _, err = Decode(b)
	if err != nil {
		return Profile{}, false, contract.Wrap(contract.Usage, err, "signing profile %s is not valid JSON", name).
			WithFix("impr profile edit "+name, "or fix "+path+" by hand")
	}
	return p, true, nil
}

// Raw returns a profile file's bytes, for validation with Check.
func (s Store) Raw(name string) ([]byte, error) {
	path, err := s.Path(name)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(path) //nolint:gosec // G304: a checked profile name under the config directory
}

// List reads every profile, sorted by name.
func (s Store) List() ([]Profile, error) {
	entries, err := os.ReadDir(s.profilesDir())
	if errors.Is(err, fs.ErrNotExist) {
		return []Profile{}, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if n, ok := strings.CutSuffix(e.Name(), ".json"); ok && !e.IsDir() && ValidName(n) {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	out := make([]Profile, 0, len(names))
	for _, n := range names {
		p, ok, err := s.Get(n)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, p)
		}
	}
	return out, nil
}

// Save validates and writes a profile. An existing profile is replaced only
// with replace; a managed one never.
func (s Store) Save(p Profile, replace bool) error {
	p.Schema = Schema
	path, err := s.Path(p.Name)
	if err != nil {
		return err
	}
	if old, ok, err := s.Get(p.Name); err != nil {
		return err
	} else if ok {
		if old.Managed {
			return ErrManaged(p.Name, "replaced")
		}
		if !replace {
			return contract.New(contract.Usage, "signing profile %s already exists", p.Name).
				WithFix("impr profile edit "+p.Name+" --set KEY=VALUE", "or replace it: --force")
		}
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	if _, ps, err := Check(b); err != nil {
		return err
	} else if len(ps) > 0 {
		return contract.New(contract.Usage, "signing profile %s is not valid; nothing was saved", p.Name).
			WithDetails(ps.Strings()...).WithFix("impr help profile")
	}
	return writeFile(path, append(b, '\n'))
}

// WriteUnchecked writes a profile without validation: only migration does
// this, so an incomplete imported profile is kept for the user to finish.
func (s Store) WriteUnchecked(p Profile) error {
	p.Schema = Schema
	path, err := s.Path(p.Name)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(path, append(b, '\n'))
}

// Remove deletes a profile; a managed one never.
func (s Store) Remove(name string) error {
	p, ok, err := s.Get(name)
	if err != nil {
		return err
	}
	if !ok {
		return ErrMissing(name)
	}
	if p.Managed {
		return ErrManaged(name, "removed")
	}
	path, _ := s.Path(name)
	return os.Remove(path)
}

// ErrManaged refuses a change to an organisation's profile.
func ErrManaged(name, action string) error {
	return contract.New(contract.Usage, "signing profile %s is managed by your organisation; it cannot be %s here", name, action).
		WithDetails("Company and team profiles are distributed by a signing administrator and are read-only to users.").
		WithFix("Ask your signing administrator to change it.")
}

// ErrMissing is the error for a profile that does not exist.
func ErrMissing(name string) error {
	return contract.New(contract.Usage, "there is no signing profile %q", name).
		WithFix("impr profile list", "impr profile add "+name+" --scope personal --owner <you> --purpose test ...")
}

// LoadIndex reads profiles.json; exists is false when it was never written.
func (s Store) LoadIndex() (idx Index, exists bool, err error) {
	b, err := os.ReadFile(s.IndexPath())
	if errors.Is(err, fs.ErrNotExist) {
		return Index{}, false, nil
	}
	if err != nil {
		return Index{}, false, err
	}
	if err := json.Unmarshal(b, &idx); err != nil {
		return Index{}, true, contract.Wrap(contract.Usage, err, "%s is not valid JSON", s.IndexPath()).
			WithFix("impr profile default <name> rewrites it")
	}
	return idx, true, nil
}

// SaveIndex writes profiles.json.
func (s Store) SaveIndex(idx Index) error {
	b, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(s.IndexPath(), append(b, '\n'))
}

// Resolve returns the named profile, or the default the user chose. Nothing
// else: never the first profile, never a test certificate because nothing
// was configured.
func (s Store) Resolve(name string) (Profile, error) {
	chosen := name
	if chosen == "" {
		idx, _, err := s.LoadIndex()
		if err != nil {
			return Profile{}, err
		}
		chosen = idx.Default
	}
	if chosen == "" {
		return Profile{}, contract.New(contract.Usage, "no signing profile was given and there is no default").
			WithDetails("impr signs only with a profile you chose: it never falls back to a test certificate or to the first certificate whose name matches.").
			WithFix("pass --profile <name>", "or choose a default: impr profile default <name>", "impr profile list")
	}
	p, ok, err := s.Get(chosen)
	if err != nil {
		return Profile{}, err
	}
	if !ok {
		return Profile{}, ErrMissing(chosen)
	}
	return p, nil
}

// writeFile writes atomically, owner-only.
func writeFile(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(b)
	serr := tmp.Sync()
	cerr := tmp.Close()
	if err := errors.Join(werr, serr, cerr, os.Chmod(name, 0o600)); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
