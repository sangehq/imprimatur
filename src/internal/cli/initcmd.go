package cli

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sangehq/imprimatur/src/internal/contract"
)

var initFlags = flagSpec{"json": boolFlag, "main": stringFlag, "module": stringFlag, "repo-root": stringFlag, "force": boolFlag}

// initTargets are the targets the PowerShell line's GoReleaser template
// built (templates/goreleaser.yaml: windows amd64/386/arm64, linux
// amd64/arm64/386/armv7, darwin amd64/arm64), as build/targets.txt lines.
var initTargets = []string{"windows amd64", "windows 386", "windows arm64", "linux amd64", "linux arm64", "linux 386", "linux arm 7",
	"darwin amd64", "darwin arm64"}

// initIgnores keep impr build's output out of git: the per-OS folders and
// archives, the build manifest, and a Windows resource file a build that was
// cut short leaves in the main package.
var initIgnores = []string{"build/*/", "build/build-manifest.json", "zz_impr_winres_windows_*.syso"}

// cmdInit sets a project up for impr build, as the PowerShell line's
// impr init did for GoReleaser (O-36..O-39): build/targets.txt with the old
// template's targets in place of .goreleaser.yaml (impr build replaced
// GoReleaser, ID-09, so that file would never be read), the build output in
// .gitignore when the project uses git, and the program chosen with --main
// when the module has several. An existing targets.txt is kept unless
// --force. sange does this itself when it drives impr.
func cmdInit(_ context.Context, a *App, args []string) (int, error) {
	p, err := parse(args, initFlags)
	if err != nil {
		return 0, err
	}
	if err := needNoArgs(p, "impr init"); err != nil {
		return 0, err
	}
	o, err := a.buildOptions(p)
	if err != nil {
		if strings.Contains(err.Error(), "found 0 commands") {
			return 0, contract.New(contract.Usage, "this module has no program to build (no cmd/NAME/main.go)").
				WithFix("add one, such as cmd/<name>/main.go with package main, then run impr init again")
		}
		return 0, err
	}
	if p.str("main") != "" {
		if _, err := os.Stat(filepath.Join(o.ModuleDir, filepath.FromSlash(o.Main), "main.go")); err != nil {
			return 0, contract.New(contract.Usage, "%s is not a program in this module (no main.go there)", o.Main).
				WithFix("impr init --main ./cmd/<name>")
		}
	}
	targets := filepath.Join(o.RepoRoot, "build", "targets.txt")
	if _, err := os.Lstat(targets); err == nil && !p.on("force") {
		return 0, contract.New(contract.Usage, "this project is already set up (%s exists); impr init does not overwrite it, so your edits are safe", targets).
			WithFix("impr build", "impr init --force   (start the targets over; your edits to it are lost)")
	}
	if err := os.MkdirAll(filepath.Dir(targets), 0o755); err != nil { //nolint:gosec // G301: a source-tree folder
		return 0, err
	}
	body := "# Release targets: \"GOOS GOARCH [GOARM]\". Written by impr init; impr build reads it.\n" + strings.Join(initTargets, "\n") + "\n"
	if err := os.WriteFile(targets, []byte(body), 0o644); err != nil { //nolint:gosec // G306: a tracked source file
		return 0, err
	}
	a.say("init      wrote %s (%d targets)", targets, len(initTargets))
	if err := a.initIgnore(o.RepoRoot); err != nil {
		return 0, err
	}
	a.say("init      build with: impr build --main %s", o.Main)
	if p.on("json") {
		a.json(map[string]any{"contract": contract.Version, "targets": targets, "main": o.Main})
	}
	return 0, nil
}

// initIgnore adds the build output to .gitignore when the project has one or
// is a git work tree, under a comment, each line once.
func (a *App) initIgnore(root string) error {
	path := filepath.Join(root, ".gitignore")
	cur, err := os.ReadFile(path) //nolint:gosec // G304: the project's own .gitignore
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if os.IsNotExist(err) {
		if _, gerr := os.Stat(filepath.Join(root, ".git")); gerr != nil {
			return nil
		}
	}
	have := strings.Split(strings.ReplaceAll(string(cur), "\r\n", "\n"), "\n")
	var add []string
	for _, l := range initIgnores {
		if !slices.Contains(have, l) {
			add = append(add, l)
		}
	}
	if len(add) == 0 {
		return nil
	}
	text := string(cur)
	if text != "" && !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	if text != "" {
		text += "\n"
	}
	text += "# impr build output\n" + strings.Join(add, "\n") + "\n"
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil { //nolint:gosec // G306: a tracked source file
		return err
	}
	a.say("init      added %s to %s", strings.Join(add, ", "), path)
	return nil
}
