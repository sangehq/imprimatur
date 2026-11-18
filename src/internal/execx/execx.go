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
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"
)

// Allowed is every tool imprimatur may run, and why.
var Allowed = map[string]string{
	"signtool":     "Authenticode signing and verification on Windows (Windows SDK)",
	"lipo":         "impr build --archives: join the macOS amd64 and arm64 builds into a universal binary (lipo -create only)",
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
	"go":           "impr build: go build only, never -toolexec, -exec, -overlay or -modfile",
	"git":          "impr build: the commit, tree, remote and whether the tree is clean (exact forms only)",
	"az":           "whether the Azure CLI is signed in before Artifact Signing (az account show only)",
	"powershell":   "impr rules test: Test-AppLockerPolicy through impr's own embedded script only (Windows)",
	"openssl":      "re-wrap a macOS .p12 under a one-time password, so the real one never reaches a command line (two pkcs12 forms only)",
}

// gitForms are the only git command lines impr runs. status turns fsmonitor
// off, so a repository's config cannot make git start a program.
var gitForms = [][]string{
	{"rev-parse", "HEAD"},
	{"rev-parse", "HEAD^{tree}"},
	{"remote", "get-url", "origin"},
	{"remote", "-v"},                                           // a release's --repo must be one of the checkout's remotes
	{"describe", "--tags", "--abbrev=0", "--match", "v[0-9]*"}, // a build's snapshot version
	{"-c", "core.fsmonitor=false", "status", "--porcelain", "--untracked-files=no"},
	{"-c", "core.fsmonitor=false", "status", "--porcelain", "--untracked-files=all"}, // untracked source counts (security review R7)
}

// commitTreeRe is a full commit id with ^{tree}: the one variable git form,
// reading a release commit's tree (security review R7).
var commitTreeRe = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?\^\{tree\}$`)

func commitTreeForm(args []string) bool {
	return len(args) == 4 && args[0] == "rev-parse" && args[1] == "--verify" && args[2] == "--quiet" && commitTreeRe.MatchString(args[3])
}

// goRefused are go build flags that run or substitute programs or files.
var goRefused = []string{"-toolexec", "-exec", "-overlay", "-modfile", "-pkgdir"}

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
	if c.Tool == "git" && !slices.ContainsFunc(gitForms, func(f []string) bool { return slices.Equal(f, c.Args) }) && !commitTreeForm(c.Args) {
		return fmt.Errorf("git %s: %w (only %d exact forms)", strings.Join(c.Args, " "), ErrNotAllowed, len(gitForms))
	}
	if c.Tool == "lipo" && (len(c.Args) != 5 || c.Args[0] != "-create" || c.Args[1] != "-output") {
		return fmt.Errorf("lipo %s: %w (only lipo -create -output OUT A B)", strings.Join(c.Args, " "), ErrNotAllowed)
	}
	if c.Tool == "az" && !slices.Equal(c.Args, []string{"account", "show", "--output", "none"}) {
		return fmt.Errorf("az %s: %w (only az account show)", strings.Join(c.Args, " "), ErrNotAllowed)
	}
	if c.Tool == "go" {
		if len(c.Args) == 0 || c.Args[0] != "build" {
			return fmt.Errorf("go %s: %w (only go build)", strings.Join(c.Args, " "), ErrNotAllowed)
		}
		for _, a := range c.Args {
			for _, r := range goRefused {
				if a == r || strings.HasPrefix(a, r+"=") {
					return fmt.Errorf("go build %s: %w", r, ErrNotAllowed)
				}
			}
		}
	}
	if c.Tool == "openssl" {
		if err := checkOpenSSL(c.Args); err != nil {
			return err
		}
	}
	if c.Tool == "powershell" {
		if err := checkPowerShell(c.Args); err != nil {
			return err
		}
	}
	if c.Tool == "xcrun" && (len(c.Args) == 0 || !slices.Contains(xcrunTools, c.Args[0])) {
		return fmt.Errorf("xcrun %s: %w (only %s)", strings.Join(c.Args, " "), ErrNotAllowed, strings.Join(xcrunTools, ", "))
	}
	return nil
}

// baseEnv is what every child sees from impr's own environment: enough to
// find programs, temp space, the user's home, locale, TLS roots and proxies,
// and on Windows the system folders. Nothing else is inherited, so a secret
// held in an env:// variable reaches a tool only when a backend passes it on
// purpose (Cmd.Env).
var baseEnv = []string{
	"PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "TMP", "TEMP", "TZ", "LANG", "LC_*",
	"SSL_CERT_FILE", "SSL_CERT_DIR", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy",
	"SystemRoot", "SYSTEMROOT", "windir", "WINDIR", "SystemDrive", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "ProgramData",
	"ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "CommonProgramFiles", "PATHEXT", "COMPUTERNAME", "USERNAME", "USERDOMAIN",
}

// toolEnv is what one tool needs beyond baseEnv, and why.
var toolEnv = map[string][]string{
	"gpg":         {"GNUPGHOME", "GPG_TTY"},                                                                                                                 // keyring location, pinentry
	"ssh-keygen":  {"SSH_AUTH_SOCK"},                                                                                                                        // agent-held keys
	"secret-tool": {"DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR"},                                                                                          // the Secret Service bus
	"cosign":      {"SIGSTORE_*", "TUF_ROOT", "COSIGN_EXPERIMENTAL"},                                                                                        // keyless endpoints and trust root
	"xcrun":       {"DEVELOPER_DIR", "SDKROOT"},                                                                                                             // which Xcode
	"codesign":    {"DEVELOPER_DIR"},                                                                                                                        //
	"signtool":    {},                                                                                                                                       //
	"security":    {},                                                                                                                                       //
	"go":          {"GOPATH", "GOCACHE", "GOMODCACHE", "GOROOT", "GOPROXY", "GOPRIVATE", "GONOPROXY", "GONOSUMDB", "GONOSUMCHECK", "GOSUMDB", "GOINSECURE"}, // module and build caches, proxies
	"git":         {},
	"az":          {"AZURE_CONFIG_DIR"},
	"powershell":  {"PSModulePath"},
	"openssl":     {},
	"lipo":        {"DEVELOPER_DIR"},
}

// ChildEnv filters environ down to baseEnv and the tool's own names, then
// appends extra (which a backend sets on purpose and always wins).
func ChildEnv(environ []string, tool string, extra []string) []string {
	allow := append(append([]string{}, baseEnv...), toolEnv[tool]...)
	out := make([]string, 0, len(allow)+len(extra))
	for _, kv := range environ {
		k, _, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			continue
		}
		for _, a := range allow {
			if a == k || (strings.HasSuffix(a, "*") && strings.HasPrefix(k, strings.TrimSuffix(a, "*"))) {
				out = append(out, kv)
				break
			}
		}
	}
	return append(out, extra...)
}

// maxOutput bounds what is kept from one call.
const maxOutput = 4 << 20

// OS runs real programs.
type OS struct {
	// Timeout bounds one call; zero means 30 minutes (notarisation waits).
	Timeout time.Duration
	// Pins names exactly which file a tool is, by absolute path and sha256
	// (config.json tools). A pinned tool is never looked up on PATH, and a
	// file whose digest no longer matches is refused before it runs.
	Pins map[string]Pin
}

// Pin is one pinned tool.
type Pin struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// LookPath resolves an allowed tool to an absolute path.
func (o OS) LookPath(tool string) (string, error) {
	if _, ok := Allowed[tool]; !ok {
		return "", fmt.Errorf("%q: %w", tool, ErrNotAllowed)
	}
	if p, ok := o.Pins[tool]; ok {
		if _, err := CheckPinned(p.Path, p.SHA256); err != nil {
			return "", fmt.Errorf("pinned %s: %w", tool, err)
		}
		return p.Path, nil
	}
	p, err := exec.LookPath(tool)
	if err != nil && tool == "signtool" && runtime.GOOS == "windows" {
		// The Windows SDK does not put signtool on PATH (O-130).
		if k := signtoolInKits(kitsBin(), runtime.GOARCH); k != "" {
			return k, nil
		}
	}
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
	cmd.Env = ChildEnv(os.Environ(), c.Tool, c.Env)
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
	if stdout.truncated || stderr.truncated {
		// A cut-off answer (notarytool's JSON, a gpg status stream) must not
		// be read as a whole one (audit N-B24).
		return res, fmt.Errorf("%s printed more than %d bytes; its output was cut off, so it is not trusted", c.Tool, maxOutput)
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
	max       int
	truncated bool
}

func (b *limited) Write(p []byte) (int, error) {
	if room := b.max - b.Len(); len(p) > room {
		if room > 0 {
			b.Buffer.Write(p[:room])
		}
		b.truncated = true
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
