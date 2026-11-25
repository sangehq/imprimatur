// Command gonotices writes, or checks, third-party-notices-go.md: the licence
// notices of every Go module compiled into impr.
//
//	make notices        # rewrite the file
//	make notices-check  # fail when it is out of date (scripts/test-all.sh runs this)
//
// The Makefile pipes `go list -deps -f <gonotices.ListFormat> ./cmd/impr` in
// on stdin and passes -goroot "$(go env GOROOT)".
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sangehq/imprimatur/src/internal/gonotices"
)

// minModules is the floor a check asserts, so a go list that finds nothing
// cannot pass as an empty, matching file (12 modules on 2026-11-25).
const minModules = 10

func main() {
	var (
		check  bool
		root   string
		goroot string
	)
	flag.BoolVar(&check, "check", false, "only compare the file with what it would be")
	flag.StringVar(&root, "root", "..", "repository root (the Makefile runs this from src/)")
	flag.StringVar(&goroot, "goroot", "", "GOROOT, for the standard library's licence")
	flag.Parse()
	if err := run(check, root, goroot); err != nil {
		fmt.Fprintln(os.Stderr, "gonotices:", err)
		os.Exit(1)
	}
}

func run(check bool, root, goroot string) error {
	mods, err := gonotices.Parse(os.Stdin, goroot)
	if err != nil {
		return err
	}
	if len(mods)-1 < minModules {
		return fmt.Errorf("go list found %d modules, want at least %d", len(mods)-1, minModules)
	}
	ns, err := gonotices.Read(mods)
	if err != nil {
		return err
	}
	want := gonotices.Render(ns)
	path := filepath.Join(root, gonotices.File)
	if !check {
		if err := os.WriteFile(path, want, 0o644); err != nil { //nolint:gosec // G306: a tracked file shipped with releases
			return err
		}
		fmt.Printf("wrote %s: %d modules and the standard library\n", path, len(mods)-1)
		return nil
	}
	have, err := os.ReadFile(path) //nolint:gosec // G304: the repository's own notices file
	if err != nil {
		return fmt.Errorf("%w: %v; run make notices", gonotices.ErrStale, err)
	}
	if !bytes.Equal(have, want) {
		var heads []string
		for _, m := range mods {
			heads = append(heads, strings.TrimSpace(m.Path+" "+m.Version))
		}
		return fmt.Errorf("%w (the modules compiled in are: %s); run make notices and commit it", gonotices.ErrStale, strings.Join(heads, ", "))
	}
	fmt.Printf("%s: %d modules and the standard library, up to date\n", gonotices.File, len(mods)-1)
	return nil
}
