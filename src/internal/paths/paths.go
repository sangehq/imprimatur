// Package paths locates imprimatur's user files. The same layout on every
// OS, Windows included (design ID-03): configuration in
// $XDG_CONFIG_HOME/imprimatur, else ~/.config/imprimatur; state in
// $XDG_STATE_HOME/imprimatur, else ~/.local/state/imprimatur. Earlier Windows
// builds used %AppData%\imprimatur and %LocalAppData%\imprimatur; those are
// reported as Legacy so the first run can copy them across once.
package paths

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// App is the directory name under the config and state roots.
const App = "imprimatur"

// MigratedMarker is written into the new config dir after a legacy copy.
const MigratedMarker = ".migrated-from"

// Env is the environment lookups need; tests pass their own.
type Env struct {
	GOOS   string
	Getenv func(string) string
	Home   string
}

// Dirs are imprimatur's directories.
type Dirs struct {
	Config string `json:"config"`
	State  string `json:"state"`
	// LegacyConfig and LegacyState are the pre-0.2 Windows locations, set
	// only on Windows when they differ from Config and State.
	LegacyConfig string `json:"legacyConfig,omitempty"`
	LegacyState  string `json:"legacyState,omitempty"`
}

// isAbs accepts a Windows drive or UNC path on any host, so tests describing
// Windows run anywhere.
func isAbs(goos, p string) bool {
	if goos == "windows" {
		return (len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/')) || strings.HasPrefix(p, `\\`)
	}
	return strings.HasPrefix(p, "/")
}

// Resolve returns the config and state directories. IMPR_CONFIG_DIR and
// IMPR_STATE_DIR override both (tests and CI). A relative XDG value is
// ignored, as the XDG spec requires.
func Resolve(e Env) (Dirs, error) {
	var d Dirs
	d.Config = e.Getenv("IMPR_CONFIG_DIR")
	d.State = e.Getenv("IMPR_STATE_DIR")
	if d.Config == "" {
		if v := e.Getenv("XDG_CONFIG_HOME"); isAbs(e.GOOS, v) {
			d.Config = filepath.Join(v, App)
		} else if e.Home != "" {
			d.Config = filepath.Join(e.Home, ".config", App)
		}
	}
	if d.State == "" {
		if v := e.Getenv("XDG_STATE_HOME"); isAbs(e.GOOS, v) {
			d.State = filepath.Join(v, App)
		} else if e.Home != "" {
			d.State = filepath.Join(e.Home, ".local", "state", App)
		}
	}
	if e.GOOS == "windows" {
		if v := e.Getenv("AppData"); v != "" && filepath.Join(v, App) != d.Config {
			d.LegacyConfig = filepath.Join(v, App)
		}
		if v := e.Getenv("LocalAppData"); v != "" && filepath.Join(v, App) != d.State {
			d.LegacyState = filepath.Join(v, App)
		}
	}
	if d.Config == "" || d.State == "" {
		return d, errors.New("cannot locate the imprimatur config or state directory: no home directory (set IMPR_CONFIG_DIR and IMPR_STATE_DIR)")
	}
	return d, nil
}

// MigrateLegacy copies a legacy Windows config and state tree into the new
// locations, once: only when the legacy dir exists and the new one does not.
// The legacy tree is left untouched (preserve by default); a marker in the
// new config dir records where it came from. It returns what it copied.
func MigrateLegacy(d Dirs, now time.Time) ([]string, error) {
	var copied []string
	for _, pair := range [][2]string{{d.LegacyConfig, d.Config}, {d.LegacyState, d.State}} {
		from, to := pair[0], pair[1]
		if from == "" || !isDir(from) || exists(to) {
			continue
		}
		if err := copyTree(from, to); err != nil {
			return copied, fmt.Errorf("copy %s to %s: %w", from, to, err)
		}
		copied = append(copied, from)
	}
	if len(copied) > 0 {
		if err := os.MkdirAll(d.Config, 0o700); err != nil {
			return copied, err
		}
		msg := fmt.Sprintf("%s\n%s\n", strings.Join(copied, "\n"), now.UTC().Format(time.RFC3339))
		if err := os.WriteFile(filepath.Join(d.Config, MigratedMarker), []byte(msg), 0o600); err != nil {
			return copied, err
		}
	}
	return copied, nil
}

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// copyTree copies regular files and directories, private (0700/0600), and
// refuses symlinks rather than following them out of the tree.
func copyTree(from, to string) error {
	return filepath.WalkDir(from, func(p string, de fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(from, p)
		if err != nil {
			return err
		}
		dst := filepath.Join(to, rel)
		switch {
		case de.IsDir():
			return os.MkdirAll(dst, 0o700)
		case de.Type().IsRegular():
			b, err := os.ReadFile(p) //nolint:gosec // G304: walking the user's own legacy config dir
			if err != nil {
				return err
			}
			return os.WriteFile(dst, b, 0o600) //nolint:gosec // G703: dst is rel-joined under the new config dir from WalkDir of the legacy one
		default:
			return fmt.Errorf("%s is not a regular file or directory; not copied", p)
		}
	})
}

// SystemConfig is the machine-wide, read-only config dir an administrator
// manages: /etc/imprimatur, /Library/Application Support/imprimatur on macOS,
// %ProgramData%\imprimatur on Windows. IMPR_SYSTEM_CONFIG_DIR overrides it
// (tests and CI); "off" disables the system layer.
func SystemConfig(e Env) string {
	if v := e.Getenv("IMPR_SYSTEM_CONFIG_DIR"); v != "" {
		if v == "off" {
			return ""
		}
		return v
	}
	switch e.GOOS {
	case "windows":
		if v := e.Getenv("ProgramData"); v != "" {
			return filepath.Join(v, App)
		}
		return ""
	case "darwin":
		return filepath.Join("/Library", "Application Support", App)
	}
	return filepath.Join("/etc", App)
}
