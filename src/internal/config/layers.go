package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
)

// ProfilesDir is where configuration profiles live, under the user config dir.
const ProfilesDir = "config.d"

var profileNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// ProfileNameOK reports whether name is a configuration profile name.
func ProfileNameOK(name string) bool { return profileNameRe.MatchString(name) }

// Sources locate the layers. Profile, when set, overrides activeProfile
// (it is IMPR_CONFIG_PROFILE).
type Sources struct {
	SystemDir string // "" when there is no system layer
	UserDir   string
	Profile   string
}

// Layer is one file that contributed to the effective configuration.
type Layer struct {
	Name    string `json:"name"` // system | user | profile:<name>
	Path    string `json:"path"`
	Present bool   `json:"present"`
}

// Effective is the merged configuration and where it came from.
type Effective struct {
	Config  Config   `json:"config"`
	Layers  []Layer  `json:"layers"`
	Profile string   `json:"activeProfile,omitempty"`
	Locked  []string `json:"locked,omitempty"`
}

// maxLayer bounds a config file.
const maxLayer = 1 << 20

// readLayer reads one layer as a JSON object. A missing file is nil. A file
// writable by group or others is refused (Unix): it decides what runs.
func readLayer(path string) (map[string]any, bool, error) {
	st, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !st.Mode().IsRegular() || st.Size() > maxLayer {
		return nil, false, fmt.Errorf("%s is not a regular file under 1 MiB", path)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o022 != 0 {
		return nil, false, fmt.Errorf("%s is writable by group or others (%v); chmod 600 it", path, st.Mode().Perm())
	}
	b, err := os.ReadFile(path) //nolint:gosec // G304: a config layer impr owns
	if err != nil {
		return nil, false, err
	}
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil || m == nil {
		return nil, false, fmt.Errorf("%s is not a JSON object: %v", path, err)
	}
	return m, true, nil
}

// merge applies src over dst as a JSON merge patch (RFC 7386): objects merge
// key by key, null removes a key, anything else (arrays included) replaces.
func merge(dst, src map[string]any) map[string]any {
	if dst == nil {
		dst = map[string]any{}
	}
	for k, v := range src {
		if v == nil {
			delete(dst, k)
			continue
		}
		sv, sok := v.(map[string]any)
		dv, dok := dst[k].(map[string]any)
		if sok && dok {
			dst[k] = merge(dv, sv)
		} else if sok {
			dst[k] = merge(nil, sv)
		} else {
			dst[k] = v
		}
	}
	return dst
}

// Has reports whether a dotted key is set in a layer.
func Has(m map[string]any, key string) bool {
	_, ok := Get(m, key)
	return ok
}

// Get reads a dotted key.
func Get(m map[string]any, key string) (any, bool) {
	var cur any = m
	for _, part := range strings.Split(key, ".") {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = obj[part]; !ok {
			return nil, false
		}
	}
	return cur, true
}

// LoadEffective merges the layers: system < user < active profile. A key the
// system layer locks may not be set below it, only the system layer may lock,
// a named profile that does not exist is an error (never "no profile"), and
// the merged result is decoded strictly and validated.
func LoadEffective(s Sources) (Effective, error) {
	eff := Effective{}
	var sys map[string]any
	if s.SystemDir != "" {
		p := filepath.Join(s.SystemDir, File)
		m, ok, err := readLayer(p)
		if err != nil {
			return eff, err
		}
		sys = m
		eff.Layers = append(eff.Layers, Layer{Name: "system", Path: p, Present: ok})
	}
	userPath := filepath.Join(s.UserDir, File)
	user, uok, err := readLayer(userPath)
	if err != nil {
		return eff, err
	}
	eff.Layers = append(eff.Layers, Layer{Name: "user", Path: userPath, Present: uok})
	if Has(user, "locked") {
		return eff, fmt.Errorf("%s: only the system config may lock keys", userPath)
	}
	if v, ok := Get(sys, "locked"); ok {
		arr, _ := v.([]any)
		for _, x := range arr {
			if k, ok := x.(string); ok {
				eff.Locked = append(eff.Locked, k)
			}
		}
	}
	if _, set := Get(user, "activeProfile"); set && slices.Contains(eff.Locked, "activeProfile") {
		return eff, fmt.Errorf("%s sets activeProfile, which the system config locks", userPath)
	}
	if s.Profile != "" && slices.Contains(eff.Locked, "activeProfile") {
		return eff, fmt.Errorf("IMPR_CONFIG_PROFILE is set, but the system config locks activeProfile")
	}
	name := s.Profile
	if name == "" {
		if v, ok := Get(user, "activeProfile"); ok {
			name, _ = v.(string)
		} else if v, ok := Get(sys, "activeProfile"); ok {
			name, _ = v.(string)
		}
	}
	var prof map[string]any
	if name != "" {
		if !ProfileNameOK(name) {
			return eff, fmt.Errorf("configuration profile %q is not a valid name", name)
		}
		p := filepath.Join(s.UserDir, ProfilesDir, name+".json")
		m, ok, err := readLayer(p)
		if err != nil {
			return eff, err
		}
		if !ok {
			return eff, fmt.Errorf("configuration profile %s is selected but %s does not exist", name, p)
		}
		for _, k := range []string{"locked", "activeProfile", "schema"} {
			if Has(m, k) {
				return eff, fmt.Errorf("%s: a configuration profile may not set %s", p, k)
			}
		}
		prof = m
		eff.Profile = name
		eff.Layers = append(eff.Layers, Layer{Name: "profile:" + name, Path: p, Present: true})
	}
	for _, lower := range []struct {
		name string
		m    map[string]any
	}{{"user config", user}, {"configuration profile " + name, prof}} {
		for _, k := range eff.Locked {
			if lowerSets(lower.m, k) {
				return eff, fmt.Errorf("the %s sets %s, which the system config locks", lower.name, k)
			}
		}
	}
	merged := merge(merge(merge(nil, sys), user), prof)
	merged["schema"] = Schema
	if name != "" {
		merged["activeProfile"] = name
	}
	b, err := json.Marshal(merged)
	if err != nil {
		return eff, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&eff.Config); err != nil {
		return eff, fmt.Errorf("the merged configuration: %w", err)
	}
	if ps := eff.Config.Validate(); len(ps) > 0 {
		return eff, fmt.Errorf("the merged configuration: %v", ps)
	}
	sort.Strings(eff.Locked)
	return eff, nil
}

// lowerSets reports whether a lower layer sets a locked key or anything
// under it, or replaces an object that contains it.
func lowerSets(m map[string]any, locked string) bool {
	if m == nil {
		return false
	}
	if Has(m, locked) {
		return true
	}
	parts := strings.Split(locked, ".")
	for i := 1; i < len(parts); i++ { // a parent set to a non-object, or null, replaces the locked key
		if v, ok := Get(m, strings.Join(parts[:i], ".")); ok {
			if _, isObj := v.(map[string]any); !isObj {
				return true
			}
		}
	}
	return false
}

// Set writes a dotted key into a layer map, creating objects on the way.
func Set(m map[string]any, key string, v any) error {
	parts := strings.Split(key, ".")
	cur := m
	for _, part := range parts[:len(parts)-1] {
		next, ok := cur[part].(map[string]any)
		if !ok {
			if _, exists := cur[part]; exists {
				return fmt.Errorf("%s is not an object", part)
			}
			next = map[string]any{}
			cur[part] = next
		}
		cur = next
	}
	cur[parts[len(parts)-1]] = v
	return nil
}

// Unset removes a dotted key from a layer map, reporting whether it was set.
func Unset(m map[string]any, key string) bool {
	parts := strings.Split(key, ".")
	cur := m
	for _, part := range parts[:len(parts)-1] {
		next, ok := cur[part].(map[string]any)
		if !ok {
			return false
		}
		cur = next
	}
	_, ok := cur[parts[len(parts)-1]]
	delete(cur, parts[len(parts)-1])
	return ok
}

// ReadLayer reads one layer file for editing (nil, false when absent).
func ReadLayer(path string) (map[string]any, bool, error) { return readLayer(path) }

// WriteLayer writes a layer file atomically, owner-only.
func WriteLayer(path string, m map[string]any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".layer.tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if _, err := f.Write(append(b, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
