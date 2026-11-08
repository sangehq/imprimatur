# Installation

impr is built from source; releases are on hold, so there is no download,
package-manager or `go install` path.

## Requirements

- Go 1.27 or newer (the module declares `go 1.27.0`).
- `make` and `git`.
- The tools of the backends you use, on `PATH` (see [backends](tools/backends.md)):
  `signtool` (Windows SDK) or `osslsigncode`, `codesign` and `xcrun` (macOS),
  `gpg`, `minisign`, `ssh-keygen`, `cosign`. None is needed to build.

## Build

```bash
git clone https://github.com/sangehq/imprimatur.git
cd imprimatur
make build
```

`make build` writes the host binary to `build/{host-os}/impr` (`build/macos/impr`
on a Mac, `impr.exe` on Windows). Put it on your `PATH`, for example:

```bash
ln -s "$PWD/build/macos/impr" ~/.local/bin/impr
```

To pin a version, check out its tag before building (`git checkout vX.Y.Z`).
`make cross` builds every target in `build/targets.txt` into `build/{os}/`
with `build/checksums.txt`.

> If `~/.local/bin/impr` is a link to the PowerShell imprimatur, impr reads
> that toolkit's `config/` the first time it runs to import your settings
> ([migration](recipes/migrate-from-powershell.md)). Replace the link
> afterwards; the PowerShell toolkit is only read, never changed.

## Where impr keeps its files

| What | Unix (macOS included) | Windows |
| --- | --- | --- |
| Configuration | `$XDG_CONFIG_HOME/imprimatur`, else `~/.config/imprimatur` | `%AppData%\imprimatur` |
| State | `$XDG_STATE_HOME/imprimatur`, else `~/.local/state/imprimatur` | `%LocalAppData%\imprimatur` |

`IMPR_CONFIG_DIR` and `IMPR_STATE_DIR` override both. Profiles are
`<config>/profiles/<name>.json` and the default is in `<config>/profiles.json`;
files are written owner-only (0600). The state directory is reserved: this
version writes nothing there (`impr doctor` reports where it is).

---

[← Docs index](../README.md#documentation)
