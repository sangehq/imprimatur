package build

import (
	gobuildpkg "go/build"
	"os"
	"path/filepath"
	"strings"

	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/winres"
)

// sysoName is the file impr writes into the main package for one build.
func sysoName(goarch string) string { return "zz_impr_winres_windows_" + goarch + ".syso" }

// writeSyso writes the Windows resources for a Windows target into the main
// package, for this one go build, and returns the function that removes it.
// It writes nothing for other targets, with o.WinRes nil, for an
// architecture with no PE resource relocation, or when the package already
// carries its own .syso for the target (a go-winres file the project keeps).
func (b Builder) writeSyso(o Options, t Target) (func(), error) {
	none := func() {}
	if t.GOOS != "windows" || o.WinRes == nil {
		return none, nil
	}
	pkg := filepath.Join(o.ModuleDir, filepath.FromSlash(strings.TrimPrefix(o.Main, "./")))
	if !winres.Supported(t.GOARCH) {
		b.logf("build     %s/%s: no version information (no PE resource support for %s)", t.GOOS, t.GOARCH, t.GOARCH)
		return none, nil
	}
	own, _ := filepath.Glob(filepath.Join(pkg, "*.syso"))
	for _, f := range own {
		base := filepath.Base(f)
		if base == sysoName(t.GOARCH) {
			return none, contract.New(contract.Usage, "%s already exists; remove it (impr writes it for each build and removes it after)", f)
		}
		// Go's own file-name rules decide which .syso files this target links.
		ctx := gobuildpkg.Default
		ctx.GOOS, ctx.GOARCH = t.GOOS, t.GOARCH
		if ok, _ := ctx.MatchFile(pkg, base); ok {
			b.logf("build     %s/%s: the package has its own %s; impr adds no version information", t.GOOS, t.GOARCH, base)
			return none, nil
		}
	}
	info := winres.Info{ProductName: orStr(o.WinRes.Product, o.Binary), CompanyName: o.WinRes.Company,
		FileDescription: o.WinRes.Description, LegalCopyright: o.WinRes.Copyright,
		OriginalFilename: o.Binary + ".exe", InternalName: o.Binary,
		ProductVersion: orStr(o.Version, "0.0.0"), FileVersion: winres.FileVersion(o.Version)}
	var ico []byte
	if j := filepath.Join(pkg, filepath.FromSlash(winres.JSONFile)); fileExists(j) {
		var notes []string
		var err error
		if info, ico, notes, err = winres.FromJSON(j, info); err != nil {
			return none, contract.Wrap(contract.Usage, err, "read %s", winres.JSONFile)
		}
		for _, n := range notes {
			b.logf("build     %s: %s", winres.JSONFile, n)
		}
	}
	if o.WinRes.Icon != "" {
		var err error
		if ico, err = os.ReadFile(o.WinRes.Icon); err != nil {
			return none, contract.Wrap(contract.Usage, err, "read --icon")
		}
	}
	syso, err := winres.Syso(t.GOARCH, info, winres.CLIManifest, ico)
	if err != nil {
		return none, contract.Wrap(contract.Usage, err, "the Windows resources")
	}
	path := filepath.Join(pkg, sysoName(t.GOARCH))
	if err := os.WriteFile(path, syso, 0o600); err != nil { //nolint:gosec // G703: a fixed name in the main package, which --main confines to the module
		return none, err
	}
	return func() { _ = os.Remove(path) }, nil
}

func orStr(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}
