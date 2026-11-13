# sangehq/imprimatur

> Sign and verify release artifacts with named, scoped signing profiles, and render Windows allow rules for them.

Go 1.27 or newer, built from source; runs on macOS, Linux and Windows. No registry version, Tests or Static analysis badge yet: no version has been released yet and the repository ([sangehq/imprimatur](https://github.com/sangehq/imprimatur)) is private, so there is nothing those badges could truthfully show. The licence is MIT.

## Install

No version has been released yet. Binaries will ship on the GitHub release
only, never through a package manager or `go install`. Build from source:

```bash
git clone https://github.com/sangehq/imprimatur.git
cd imprimatur
make build            # writes build/{macos,linux,windows}/impr
```

Put `build/<your OS>/impr` on your `PATH`. To pin a version, check out its tag
before building. See [installation](docs/installation.md).

## Quick start guide and usage

### Getting started

impr needs a signing profile before it signs anything. If you used the
PowerShell imprimatur, your settings are imported into a profile named
`default` the first time impr runs (or run `impr profile import-legacy`).
Otherwise add one:

```bash
impr profile add me-test --scope personal --owner me --purpose test \
  --set platforms.checksums.kind=ssh \
  --set platforms.checksums.keyRef=env://IMPR_SSH_KEY \
  --set platforms.checksums.fingerprint=SHA256:<your key's fingerprint>
impr profile capabilities me-test     # what this host can sign with it
```

Profiles live in `~/.config/imprimatur/profiles/` (`%AppData%\imprimatur` on
Windows) and hold credential references only, never a key or password.

### Usage

Sign exactly the files a build manifest lists, then verify them against the
profile's pinned identity:

```bash
export IMPR_SSH_KEY=~/.ssh/release_ed25519
impr sign --manifest build/build-manifest.json --commit "$(git rev-parse HEAD)" \
  --tree "$(git rev-parse HEAD^{tree})" --profile me-test --purpose test --json --strict
impr verify --signed build/impr-manifest.json --profile me-test --json --strict
```

The full walkthrough is [getting started](docs/getting-started.md); everything
else is in the [documentation](#documentation) below.

## <a name="documentation"></a>Documentation

### Guides

- [Installation](docs/installation.md) — building from source, and where impr keeps its files
- [Getting started](docs/getting-started.md) — a first profile, a first signed build manifest
- [Configuration](docs/configuration.md) — profiles, credential references, paths and environment variables
- [Architecture](docs/architecture.md) — the backend port, the exec allow-list, and why
- [Release](docs/release.md) — how binaries are released on the GitHub release, and the commands that start one

### Reference

- [`impr companion info`](docs/tools/companion.md) — the contract v1 other tools call
- [`impr profile`](docs/tools/profile.md) — list, show, add, edit, rm, import, export, validate, default, capabilities, import-legacy
- [`impr sign`](docs/tools/sign.md) — signing a build manifest, `impr-manifest.json`
- [`impr verify`](docs/tools/verify.md) — checking signatures against a pinned identity
- [`impr cert list`](docs/tools/cert.md) — the certificates and keys profiles use, with expiry
- [`impr rules`](docs/tools/rules.md) — AppLocker and WDAC supplemental policies from a request
- [`impr doctor`](docs/tools/doctor.md) — a health report of profiles and host capability
- [Backends](docs/tools/backends.md) — every signing backend, the tools it runs and what it pins

### Recipes

- [Migrate from the PowerShell imprimatur](docs/recipes/migrate-from-powershell.md) — what is imported, and what is not ported yet
- [Sign checksums with an SSH key](docs/recipes/ssh-checksums.md) — the backend that runs on every host
- [Sign and notarise for macOS](docs/recipes/macos-notarization.md) — Developer ID, notarytool and stapler
- [Use impr from sange's pipeline](docs/recipes/sange-pipeline.md) — the calls sange makes and what it checks

## Contributing and security

Report a vulnerability through GitHub private vulnerability reporting, or to
`security@simtabi.com`.

## License

MIT. Copyright (c) 2026 Simtabi LLC. See [LICENSE](LICENSE).
