package execx

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// openerWait bounds how long OpenPage waits for the desktop's opener to hand
// the page to the browser; an opener that keeps running (xdg-open, at times)
// is left to finish on its own.
const openerWait = 5 * time.Second

// BrowserArgv is the desktop opener's command line for a local page: open on
// macOS, the URL protocol handler on Windows, xdg-open elsewhere. The page is
// the only argument a caller supplies.
func BrowserArgv(goos, page string) []string {
	switch goos {
	case "darwin":
		return []string{"open", page}
	case "windows":
		return []string{"rundll32", "url.dll,FileProtocolHandler", page}
	}
	return []string{"xdg-open", page}
}

// OpenPage opens a local HTML page in the desktop's browser: impr serve's
// owner-only launch page, which redirects to the sign-in link, so the link is
// never on a command line another local user can read (authama audit S-01).
// It is not a signing tool and not on Allowed; it takes one argument, an
// absolute path to an existing regular .html file, and nothing else.
func OpenPage(goos, page string) error {
	if !filepath.IsAbs(page) || filepath.Ext(page) != ".html" {
		return fmt.Errorf("%q is not an absolute path to an .html page", page)
	}
	st, err := os.Lstat(page)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return errors.New(page + " is not a regular file")
	}
	argv := BrowserArgv(goos, page)
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return fmt.Errorf("%s: %w", argv[0], ErrNotFound)
	}
	cmd := exec.Command(path, argv[1:]...) //nolint:gosec // G204: the desktop opener by its resolved path, one checked file argument, no shell
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(openerWait):
		return nil
	}
}
