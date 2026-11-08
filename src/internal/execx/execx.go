// Package execx is the only place imprimatur runs another program. Every
// external tool a backend needs is on one allow-list, resolved to an absolute
// path, and started directly with its arguments: never through a shell. A tool
// that is not on the list cannot be run, whatever a caller asks for.
package execx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
)

// Allowed is every tool imprimatur may run, and why.
var Allowed = map[string]string{
	"signtool":     "Authenticode signing and verification on Windows (Windows SDK)",
	"osslsigncode": "Authenticode signing with a .pfx and verification on any host",
	"certutil":     "whether a pinned certificate is in the Windows certificate store",
	"codesign":     "Apple code signing and its verification",
	"xcrun":        "notarytool and stapler (only those two)",
	"ditto":        "the zip notarytool submits",
	"spctl":        "Gatekeeper assessment of a notarised binary",
	"security":     "macOS keychain: certificate expiry and secret:// lookups",
	"secret-tool":  "Linux secret service: secret:// lookups",
	"gpg":          "GPG checksum signatures",
	"minisign":     "minisign checksum signatures",
	"ssh-keygen":   "SSH checksum signatures (ssh-keygen -Y)",
	"cosign":       "Sigstore cosign blob signatures, key and keyless",
}

// xcrunTools are the only subcommands xcrun may start.
var xcrunTools = []string{"notarytool", "stapler"}

// Names lists the allowed tools, sorted.
func Names() []string {
	out := make([]string, 0, len(Allowed))
	for k := range Allowed {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Cmd is one invocation.
type Cmd struct {
	Tool  string   // a name from Allowed
	Args  []string // passed as-is, never through a shell
	Dir   string
	Env   []string // added to the environment
	Stdin []byte
}

// Result is what the tool did.
type Result struct {
	Path     string // the absolute path that ran
	ExitCode int
	Stdout   []byte
	Stderr   []byte
}

// Output is stdout and stderr together, for messages.
func (r Result) Output() string {
	return strings.TrimSpace(string(r.Stdout) + "\n" + string(r.Stderr))
}

// Runner runs allowed tools. Run returns an error only when the tool could not
// be run at all; a non-zero exit is Result.ExitCode.
type Runner interface {
	LookPath(tool string) (string, error)
	Run(ctx context.Context, c Cmd) (Result, error)
}

// ErrNotAllowed is returned for a tool that is not on the allow-list.
var ErrNotAllowed = errors.New("not on imprimatur's tool allow-list")

// ErrNotFound is returned for an allowed tool that is not installed.
var ErrNotFound = errors.New("not installed or not on PATH")

// Check refuses a tool that is not allowed, and an xcrun call that starts
// anything but notarytool or stapler.
func Check(c Cmd) error {
	if _, ok := Allowed[c.Tool]; !ok {
		return fmt.Errorf("%q: %w", c.Tool, ErrNotAllowed)
	}
	if c.Tool == "xcrun" && (len(c.Args) == 0 || !slices.Contains(xcrunTools, c.Args[0])) {
		return fmt.Errorf("xcrun %s: %w (only %s)", strings.Join(c.Args, " "), ErrNotAllowed, strings.Join(xcrunTools, ", "))
	}
	return nil
}

// maxOutput bounds what is kept from one call.
const maxOutput = 4 << 20

// OS runs real programs.
type OS struct {
	// Timeout bounds one call; zero means 30 minutes (notarisation waits).
	Timeout time.Duration
}

// LookPath resolves an allowed tool to an absolute path.
func (OS) LookPath(tool string) (string, error) {
	if _, ok := Allowed[tool]; !ok {
		return "", fmt.Errorf("%q: %w", tool, ErrNotAllowed)
	}
	p, err := exec.LookPath(tool)
	if err != nil {
		return "", fmt.Errorf("%s: %w", tool, ErrNotFound)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return abs, nil
}

// Run starts the tool by its absolute path, with no shell, bounded output
// and a timeout.
func (o OS) Run(ctx context.Context, c Cmd) (Result, error) {
	if err := Check(c); err != nil {
		return Result{}, err
	}
	path, err := o.LookPath(c.Tool)
	if err != nil {
		return Result{}, err
	}
	d := o.Timeout
	if d == 0 {
		d = 30 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, c.Args...) //nolint:gosec // G204: an allow-listed tool by absolute path, no shell
	cmd.Dir = c.Dir
	cmd.Env = append(os.Environ(), c.Env...)
	cmd.WaitDelay = time.Second
	if c.Stdin != nil {
		cmd.Stdin = bytes.NewReader(c.Stdin)
	}
	var stdout, stderr limited
	stdout.max, stderr.max = maxOutput, maxOutput
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	res := Result{Path: path, Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if ctx.Err() == context.DeadlineExceeded {
		return res, fmt.Errorf("%s timed out after %s", c.Tool, d)
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			res.ExitCode = ee.ExitCode()
			return res, nil
		}
		return res, fmt.Errorf("run %s: %w", c.Tool, err)
	}
	return res, nil
}

type limited struct {
	bytes.Buffer
	max int
}

func (b *limited) Write(p []byte) (int, error) {
	if room := b.max - b.Len(); len(p) > room {
		if room > 0 {
			b.Buffer.Write(p[:room])
		}
		return len(p), nil
	}
	return b.Buffer.Write(p)
}

// Available reports whether every tool resolves here.
func Available(r Runner, tools ...string) bool {
	for _, t := range tools {
		if _, err := r.LookPath(t); err != nil {
			return false
		}
	}
	return true
}
