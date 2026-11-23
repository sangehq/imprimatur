package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/paths"
	"github.com/sangehq/imprimatur/src/internal/secrets"
)

var secretFlags = flagSpec{"json": boolFlag, "file": stringFlag}

// maxSecret caps a stored value: a key, a token or a password, never a file
// of any size.
const maxSecret = 64 << 10

// SecretEntry is one line of impr secret list: a name and its reference,
// never the value.
type SecretEntry struct {
	Name string `json:"name"`
	Ref  string `json:"ref"`
}

// cmdSecret stores signing secrets (owner decisions ID-31 to ID-33): impr
// secret set NAME puts a value, read from stdin or --file, into the OS secret
// store and records NAME=reference in .env, so a profile names it as
// env://NAME. impr secret list shows names and references only.
func cmdSecret(ctx context.Context, a *App, args []string) (int, error) {
	p, err := parse(args, secretFlags)
	if err != nil {
		return 0, err
	}
	if len(p.pos) == 0 {
		return 0, contract.New(contract.Usage, "impr secret set NAME [--file FILE] | list").WithFix("printf '%s' \"$VALUE\" | impr secret set IMPR_NOTARY_KEY")
	}
	d, err := a.dirs()
	if err != nil {
		return 0, contract.Wrap(contract.Unavailable, err, "locate the imprimatur config")
	}
	if err := paths.EnsureLayout(d); err != nil {
		return 0, contract.Wrap(contract.Unavailable, err, "create %s owner-only", d.Config)
	}
	env := filepath.Join(d.Config, paths.EnvFile)
	switch p.pos[0] {
	case "list":
		m, err := secrets.ReadEnvFile(env)
		if err != nil {
			return 0, err
		}
		list := []SecretEntry{}
		for k, v := range m {
			list = append(list, SecretEntry{Name: k, Ref: v})
		}
		sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
		if p.on("json") {
			a.json(map[string]any{"contract": contract.Version, "secrets": list})
			return 0, nil
		}
		for _, e := range list {
			a.say("secret    %s = %s", e.Name, e.Ref)
		}
		return 0, nil
	case "set":
		if len(p.pos) != 2 {
			return 0, contract.New(contract.Usage, "impr secret set NAME [--file FILE]")
		}
		value, err := a.secretValue(p)
		if err != nil {
			return 0, err
		}
		ref, err := a.PutSecret(ctx, p.pos[1], value)
		if err != nil {
			return 0, err
		}
		if p.on("json") {
			a.json(map[string]any{"contract": contract.Version, "name": p.pos[1], "ref": ref})
		} else {
			a.say("secret    stored %s as %s; a profile names it env://%s", p.pos[1], ref, p.pos[1])
		}
		return 0, nil
	}
	return 0, contract.New(contract.Usage, "impr secret set NAME [--file FILE] | list")
}

// secretValue reads the value from --file, or from stdin when it is not a
// terminal: a value typed at a prompt would be shown on the screen.
func (a *App) secretValue(p parsed) (string, error) {
	var r io.Reader
	switch {
	case p.str("file") != "":
		f, err := os.Open(p.str("file"))
		if err != nil {
			return "", contract.Wrap(contract.Usage, err, "read %s", p.str("file"))
		}
		defer func() { _ = f.Close() }()
		r = f
	case a.Stdin != nil && (a.Interactive == nil || !a.Interactive()):
		r = a.Stdin
	default:
		return "", contract.New(contract.Usage, "pipe the value to impr secret set, or name a file with --file; impr never reads a secret typed at a prompt").
			WithFix("impr secret set NAME --file ~/Downloads/AuthKey_ABC123.p8")
	}
	b, err := io.ReadAll(io.LimitReader(r, maxSecret+1))
	if err != nil {
		return "", err
	}
	if len(b) > maxSecret {
		return "", contract.New(contract.Usage, "the value is larger than %d bytes", maxSecret)
	}
	v := string(b)
	if strings.TrimSpace(v) == "" {
		return "", contract.New(contract.Usage, "the value is empty")
	}
	return v, nil
}

// PutSecret stores value under name and records NAME=reference in .env. The
// web page (impr serve) and impr secret set both use it.
func (a *App) PutSecret(ctx context.Context, name, value string) (string, error) {
	if !secrets.ValidName(name) {
		return "", contract.New(contract.Usage, "%q is not a name (A-Z, 0-9, _; up to 63, starting with a letter)", name)
	}
	d, err := a.dirs()
	if err != nil {
		return "", err
	}
	if err := paths.EnsureLayout(d); err != nil {
		return "", err
	}
	ref, err := a.host().Secrets.Put(ctx, name, value, d.Config)
	if err != nil {
		return "", err
	}
	if err := secrets.SetEnv(filepath.Join(d.Config, paths.EnvFile), name, ref); err != nil {
		return "", err
	}
	return ref, nil
}
