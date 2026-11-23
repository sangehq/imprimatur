package secrets

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"

	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/execx"
)

// EnvFileName is the file under impr's config folder that maps variable names
// to credential references (owner decision ID-32): `NAME=secret://NAME`. It
// never holds a value.
const EnvFileName = ".env"

// SecretsDir is the owner-only folder under impr's config folder that holds a
// secret's file where the host has no secret store (ID-33).
const SecretsDir = "secrets"

// storedPrefix marks a value impr put into an OS store: base64, so a PEM key's
// line breaks and any quote survive the store's own syntax.
const storedPrefix = "impr-b64:"

var nameRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,62}$`)

// ValidName reports whether name can name a stored secret and a .env line.
func ValidName(name string) bool { return nameRe.MatchString(name) }

// refSchemes are the references a .env line may hold. env:// is refused there:
// a .env line is the end of an env:// lookup, never another one.
var refSchemes = []string{"secret", "keychain", "cert-store", "gpg-agent", "file"}

func encodeStored(v string) string {
	return storedPrefix + base64.StdEncoding.EncodeToString([]byte(v))
}

func decodeStored(v string) (string, error) {
	enc, ok := strings.CutPrefix(v, storedPrefix)
	if !ok {
		return v, nil // a value stored by hand
	}
	b, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", errors.New("a value impr stored no longer decodes")
	}
	return string(b), nil
}

// ReadEnvFile reads a .env of NAME=reference lines. It refuses a file others
// can read or write, a value that is not a reference, an env:// reference, a
// bad name and a name given twice. A missing file is an empty map.
func ReadEnvFile(path string) (map[string]string, error) {
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, contract.New(contract.Usage, "%s is not a regular file (links are not followed)", path)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0 {
		return nil, contract.New(contract.Usage, "%s is readable or writable by others (%v)", path, st.Mode().Perm()).WithFix("chmod 600 " + path)
	}
	if st.Size() > 64<<10 {
		return nil, contract.New(contract.Usage, "%s is larger than 64 KiB", path)
	}
	b, err := os.ReadFile(path) //nolint:gosec // G304: impr's own config file
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, ref, ok := strings.Cut(line, "=")
		name, ref = strings.TrimSpace(name), strings.TrimSpace(ref)
		switch {
		case !ok:
			return nil, contract.New(contract.Usage, "%s line %d is not NAME=reference", path, n)
		case !ValidName(name):
			return nil, contract.New(contract.Usage, "%s line %d: %q is not a name (A-Z, 0-9, _)", path, n, name)
		case !envRef(ref):
			return nil, contract.New(contract.Usage, "%s line %d: %s must be a reference (%s://...), never a value", path, n, name, strings.Join(refSchemes, "://, ")).
				WithDetails("Put the value in the OS secret store: impr secret set " + name)
		case out[name] != "":
			return nil, contract.New(contract.Usage, "%s line %d: %s is given twice", path, n, name)
		}
		out[name] = ref
	}
	return out, sc.Err()
}

func envRef(ref string) bool {
	scheme, name, ok := Scheme(ref)
	return ok && slices.Contains(refSchemes, scheme) && !strings.ContainsAny(name, " \t\"'")
}

// SetEnv adds or replaces one NAME=reference line in the .env at path,
// writing it owner-only through a temporary file of its own.
func SetEnv(path, name, ref string) error {
	if !ValidName(name) {
		return contract.New(contract.Usage, "%q is not a name (A-Z, 0-9, _)", name)
	}
	if !envRef(ref) {
		return contract.New(contract.Usage, "%s: %q is not a reference; .env never holds a value", name, ref)
	}
	m, err := ReadEnvFile(path)
	if err != nil {
		return err
	}
	m[name] = ref
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	slices.Sort(names)
	var b strings.Builder
	b.WriteString("# imprimatur: NAME=reference, read for env://NAME when the variable is not set.\n")
	b.WriteString("# References only (secret://, keychain://, file://, ...); never a secret value.\n")
	for _, k := range names {
		fmt.Fprintf(&b, "%s=%s\n", k, m[k])
	}
	return writeOwnerOnly(path, []byte(b.String()))
}

// writeOwnerOnly writes data to path, 0600 in a 0700 folder, through a
// temporary file renamed into place.
func writeOwnerOnly(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".impr-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.Write(data)
	cerr := f.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(tmp)
		return errors.Join(werr, cerr)
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// Put stores a secret value under name and returns the reference that reads
// it back (ID-33): the OS store first (the macOS keychain, the Linux secret
// service, the Windows Credential Manager) as secret://NAME, else a 0600 file
// in the 0700 secrets folder under configDir as file://PATH. The value never
// reaches a command line: the store's tool reads it on stdin.
func (r Resolver) Put(ctx context.Context, name, value, configDir string) (string, error) {
	if !ValidName(name) {
		return "", contract.New(contract.Usage, "%q is not a name (A-Z, 0-9, _; up to 63)", name)
	}
	if value == "" {
		return "", contract.New(contract.Usage, "%s: the value is empty", name)
	}
	stored := encodeStored(value)
	switch r.GOOS {
	case "darwin":
		// security -i reads commands on stdin, so the value is never on a
		// command line; base64 keeps it one quoted-free token.
		cmd := fmt.Sprintf("add-generic-password -U -s %s -a %s -w %s\n", Service, name, stored)
		res, err := r.Runner.Run(ctx, execx.Cmd{Tool: "security", Args: []string{"-i"}, Stdin: []byte(cmd)})
		if err == nil && res.ExitCode == 0 {
			return "secret://" + name, nil
		}
	case "linux", "freebsd":
		res, err := r.Runner.Run(ctx, execx.Cmd{Tool: "secret-tool", Args: []string{"store", "--label=" + Service + "/" + name, "service", Service, "account", name},
			Stdin: []byte(stored)})
		if err == nil && res.ExitCode == 0 {
			return "secret://" + name, nil
		}
	case "windows":
		if credWrite(Service+"/"+name, stored) == nil {
			return "secret://" + name, nil
		}
	}
	if configDir == "" {
		return "", contract.New(contract.Unavailable, "%s: this host has no secret store impr can write, and no config folder for a file", name)
	}
	path := filepath.Join(configDir, SecretsDir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil { //nolint:gosec // G302: a folder, owner-only
		return "", err
	}
	if err := writeOwnerOnly(path, []byte(value)); err != nil {
		return "", err
	}
	return "file://" + path, nil
}
