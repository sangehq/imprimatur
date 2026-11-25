# Installation

impr ships as binaries on the GitHub release only, never through a package manager or `go install`
(see [release](release.md)). Download one, or build from source.

## Download

Take `impr_{os}_{arch}` (`.exe` on Windows; `macos`, never `darwin`) and `checksums.txt` from the
[latest release](https://github.com/sangehq/imprimatur/releases/latest), then check it:

```bash
sha256sum -c --ignore-missing checksums.txt   # shasum -a 256 -c --ignore-missing on macOS
gh attestation verify impr_linux_amd64 --repo sangehq/imprimatur --signer-workflow simtabi/.github/.github/workflows/go-release.yml
```

Put it on your `PATH` as `impr` (`chmod +x` it first on macOS, Linux and FreeBSD).

## Requirements

- Go 1.27.4 or newer (the module declares `go 1.27.4`; earlier 1.27 releases carry GO-2026-6859 in `net/http`, which `impr serve` uses).
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

The same layout on every OS, Windows included (`~` is `%USERPROFILE%` there):

| What | Location |
| --- | --- |
| Configuration | `$XDG_CONFIG_HOME/imprimatur`, else `~/.config/imprimatur` |
| State | `$XDG_STATE_HOME/imprimatur`, else `~/.local/state/imprimatur` |

This deliberately differs from the estate's usual `%AppData%` rule for
Windows: the owner chose one predictable layout for every OS (2026-11-15).
Earlier Windows builds used `%AppData%\imprimatur` and
`%LocalAppData%\imprimatur`. The first run that finds one of those, and no new
folder yet, copies it across and writes `<config>/.migrated-from`; the old
folder is left in place.

`IMPR_CONFIG_DIR` and `IMPR_STATE_DIR` override both. Profiles are
`<config>/profiles/<name>.json` and the default is in `<config>/profiles.json`;
files are written owner-only (0600). The state directory is reserved: this
version writes nothing there (`impr doctor` reports where it is).

---

[← Docs index](../README.md#documentation)
