package cli

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/paths"
	"github.com/sangehq/imprimatur/src/internal/secrets"
)

func shortSum(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// permissionProblems reports what others on this machine could change or
// read: impr's folders writable by group or others (anyone who can write
// them can swap a profile, a hook pin or the event log), and key files
// (file:// references in profiles, the server's TLS key) readable by them.
// Windows has no such mode bits, so it reports nothing there.
func (a *App) permissionProblems(d paths.Dirs) []string {
	if a.GOOS == "windows" {
		return nil
	}
	var out []string
	for _, dir := range []string{d.Config, d.State, filepath.Join(d.Config, "profiles"), filepath.Join(d.Config, "bundles"),
		filepath.Join(d.State, "events"), filepath.Join(d.State, "audit"), filepath.Join(d.State, "server")} {
		st, err := os.Stat(dir)
		if err != nil {
			continue
		}
		if st.Mode().Perm()&0o022 != 0 {
			out = append(out, fmt.Sprintf("%s is writable by group or others (%v); chmod go-w it", dir, st.Mode().Perm()))
		}
	}
	// The secrets folder and .env are owner-only (ID-32, ID-33), and the .env
	// holds references only.
	sec := filepath.Join(d.Config, paths.SecretsDir)
	if st, err := os.Stat(sec); err == nil && st.Mode().Perm()&0o077 != 0 {
		out = append(out, fmt.Sprintf("%s is open to group or others (%v); chmod 700 it", sec, st.Mode().Perm()))
	}
	_ = filepath.WalkDir(sec, func(p string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return nil
		}
		if st, err := os.Lstat(p); err == nil && st.Mode().Perm()&0o077 != 0 {
			out = append(out, fmt.Sprintf("secret file %s is readable by group or others (%v); chmod 600 it", p, st.Mode().Perm()))
		}
		return nil
	})
	if _, err := secrets.ReadEnvFile(filepath.Join(d.Config, paths.EnvFile)); err != nil {
		out = append(out, strings.TrimPrefix(contract.Text(err), "impr: "))
	}
	for _, f := range append([]string{filepath.Join(d.Config, "config.json")}, jsonFiles(filepath.Join(d.Config, paths.ProfileDir))...) {
		if st, err := os.Lstat(f); err == nil && st.Mode().Perm()&0o022 != 0 {
			out = append(out, fmt.Sprintf("%s is writable by group or others (%v); chmod 600 it", f, st.Mode().Perm()))
		}
	}
	keys := map[string]bool{}
	if eff, err := a.effective(d); err == nil && eff.Config.Server.TLS != nil && eff.Config.Server.TLS.KeyFile != "" {
		keys[eff.Config.Server.TLS.KeyFile] = true
	}
	_ = filepath.WalkDir(filepath.Join(d.Config, "profiles"), func(p string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() || !strings.HasSuffix(p, ".json") {
			return nil
		}
		b, err := os.ReadFile(p) //nolint:gosec // G304: impr's own profile files
		if err == nil {
			collectFileRefs(b, keys)
		}
		return nil
	})
	names := make([]string, 0, len(keys))
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		st, err := os.Stat(k)
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		if st.Mode().Perm()&0o077 != 0 {
			out = append(out, fmt.Sprintf("key file %s is readable by group or others (%v); chmod 600 it", k, st.Mode().Perm()))
		}
	}
	return out
}

// collectFileRefs finds every file:// reference in a profile document.
func collectFileRefs(b []byte, into map[string]bool) {
	var v any
	if json.Unmarshal(b, &v) != nil {
		return
	}
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case map[string]any:
			for _, y := range t {
				walk(y)
			}
		case []any:
			for _, y := range t {
				walk(y)
			}
		case string:
			if p, ok := strings.CutPrefix(t, "file://"); ok && filepath.IsAbs(p) {
				into[p] = true
			}
		}
	}
	walk(v)
}

// jsonFiles lists the .json files in dir.
func jsonFiles(dir string) []string {
	m, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	return m
}
