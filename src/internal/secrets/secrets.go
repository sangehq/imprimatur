// Package secrets resolves the credential references a profile holds. A value
// is held in memory for one signing run, written to an owner-only temporary
// file only when a tool needs a file, and removed straight after. Nothing here
// prints or stores a value.
package secrets

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/execx"
)

// Service is the OS secret-store service name secret:// references live under.
const Service = "imprimatur"

// Resolver resolves references.
type Resolver struct {
	Runner execx.Runner
	Getenv func(string) string
	GOOS   string
}

// Scheme returns a reference's scheme and name ("env", "NAME").
func Scheme(ref string) (scheme, name string, ok bool) {
	scheme, name, ok = strings.Cut(ref, "://")
	return scheme, name, ok && name != ""
}

// Resolve returns the value a reference names. env:// reads the variable,
// secret:// asks the OS secret store (the macOS keychain or the Linux secret
// service), and keychain://, cert-store:// and gpg-agent:// name a store the
// platform tool reads itself, so they resolve to the name.
func (r Resolver) Resolve(ctx context.Context, ref string) (string, error) {
	scheme, name, ok := Scheme(ref)
	if !ok {
		return "", contract.New(contract.Usage, "%q is not a credential reference", ref).
			WithFix("use secret://, env://, keychain://, cert-store:// or gpg-agent://")
	}
	switch scheme {
	case "env":
		v := r.Getenv(name)
		if v == "" {
			return "", contract.New(contract.Unavailable, "the variable %s named by %s is not set", name, ref).
				WithFix("set it in this terminal or as a CI secret")
		}
		return v, nil
	case "keychain", "cert-store", "gpg-agent":
		return name, nil
	case "secret":
		return r.store(ctx, name)
	}
	return "", contract.New(contract.Usage, "%q is not a credential reference", ref)
}

func (r Resolver) store(ctx context.Context, name string) (string, error) {
	var c execx.Cmd
	switch r.GOOS {
	case "darwin":
		c = execx.Cmd{Tool: "security", Args: []string{"find-generic-password", "-s", Service, "-a", name, "-w"}}
	case "linux", "freebsd":
		c = execx.Cmd{Tool: "secret-tool", Args: []string{"lookup", "service", Service, "account", name}}
	default:
		return "", contract.New(contract.Unavailable, "secret://%s: this host has no secret store imprimatur can read", name).
			WithFix("use an env:// reference set from a CI secret, or cert-store:// for a certificate")
	}
	res, err := r.Runner.Run(ctx, c)
	if err != nil {
		return "", contract.Wrap(contract.Unavailable, err, "secret://%s: the secret store is unavailable", name)
	}
	v := strings.TrimRight(string(res.Stdout), "\r\n")
	if res.ExitCode != 0 || v == "" {
		return "", contract.New(contract.Unavailable, "secret://%s is not in the %s secret store", name, Service).
			WithFix("store it under service " + Service + ", account " + name)
	}
	return v, nil
}

// File is a credential as a file a tool can read.
type File struct {
	Path    string
	cleanup func()
}

// Close removes a temporary file; a file that was already on disk stays.
func (f File) Close() {
	if f.cleanup != nil {
		f.cleanup()
	}
}

// AsFile turns a resolved value into a file. A value naming an existing file
// is used in place; key material (PEM, an OpenSSH or minisign key) is written
// to an owner-only temporary file; with decodeBase64, base64 content (a .p12
// or .pfx in a CI secret) is decoded first.
func AsFile(value string, decodeBase64 bool) (File, error) {
	if !strings.ContainsAny(value, "\n") {
		if st, err := os.Stat(value); err == nil && !st.IsDir() {
			return File{Path: value}, nil
		}
	}
	data := []byte(value)
	if decodeBase64 && !strings.Contains(value, "-----BEGIN") {
		d, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(value), ""))
		if err != nil {
			return File{}, contract.New(contract.Unavailable, "the credential is neither a file nor base64 content")
		}
		data = d
	} else if !strings.Contains(value, "-----BEGIN") && !strings.Contains(value, "untrusted comment:") {
		return File{}, contract.New(contract.Unavailable, "the credential names a file that does not exist").
			WithFix("point the reference at the key file, or put the key itself in the variable")
	}
	dir, err := os.MkdirTemp("", "impr-cred-")
	if err != nil {
		return File{}, err
	}
	path := filepath.Join(dir, "credential")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return File{}, err
	}
	return File{Path: path, cleanup: func() { _ = os.RemoveAll(dir) }}, nil
}

// TempText writes non-file text (a password) to an owner-only temporary file
// for tools that read it from a file rather than a command line.
func TempText(text string) (File, error) {
	if text == "" {
		return File{}, errors.New("empty value")
	}
	dir, err := os.MkdirTemp("", "impr-cred-")
	if err != nil {
		return File{}, err
	}
	path := filepath.Join(dir, "value")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return File{}, err
	}
	return File{Path: path, cleanup: func() { _ = os.RemoveAll(dir) }}, nil
}
