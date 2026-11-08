// Package paths locates imprimatur's user files. XDG everywhere, macOS
// included: configuration in $XDG_CONFIG_HOME/imprimatur (else
// ~/.config/imprimatur) and state in $XDG_STATE_HOME/imprimatur (else
// ~/.local/state/imprimatur). On Windows %AppData%\imprimatur and
// %LocalAppData%\imprimatur.
package paths

import (
	"errors"
	"path/filepath"
)

// App is the directory name under the config and state roots.
const App = "imprimatur"

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
}

// Resolve returns the config and state directories. IMPR_CONFIG_DIR and
// IMPR_STATE_DIR override both (tests and CI).
func Resolve(e Env) (Dirs, error) {
	var d Dirs
	if v := e.Getenv("IMPR_CONFIG_DIR"); v != "" {
		d.Config = v
	}
	if v := e.Getenv("IMPR_STATE_DIR"); v != "" {
		d.State = v
	}
	if e.GOOS == "windows" {
		if d.Config == "" {
			if v := e.Getenv("AppData"); v != "" {
				d.Config = filepath.Join(v, App)
			}
		}
		if d.State == "" {
			if v := e.Getenv("LocalAppData"); v != "" {
				d.State = filepath.Join(v, App)
			}
		}
	} else {
		if d.Config == "" {
			if v := e.Getenv("XDG_CONFIG_HOME"); filepath.IsAbs(v) {
				d.Config = filepath.Join(v, App)
			} else if e.Home != "" {
				d.Config = filepath.Join(e.Home, ".config", App)
			}
		}
		if d.State == "" {
			if v := e.Getenv("XDG_STATE_HOME"); filepath.IsAbs(v) {
				d.State = filepath.Join(v, App)
			} else if e.Home != "" {
				d.State = filepath.Join(e.Home, ".local", "state", App)
			}
		}
	}
	if d.Config == "" || d.State == "" {
		return d, errors.New("cannot locate the imprimatur config or state directory: no home directory")
	}
	return d, nil
}
