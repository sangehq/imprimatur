# sangehq/imprimatur

[![Release](https://img.shields.io/github/v/release/sangehq/imprimatur)](https://github.com/sangehq/imprimatur/releases)
[![CI](https://github.com/sangehq/imprimatur/actions/workflows/ci.yml/badge.svg)](https://github.com/sangehq/imprimatur/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

> Sign and verify release artifacts with named, scoped signing profiles, and render Windows allow rules for them.

Go 1.27.4 or newer to build; runs on macOS, Linux, Windows and FreeBSD. There is no registry badge: binaries ship on the GitHub release only. The one CI workflow runs the tests and the static analysis (gofmt, vet, golangci-lint, govulncheck), so a single CI badge stands for both.

## Install

Download the binary for your platform from the [latest GitHub release](https://github.com/sangehq/imprimatur/releases/latest)
(`impr_{os}_{arch}`, `.exe` on Windows) and check it against the release's `checksums.txt`:

```bash
sha256sum -c --ignore-missing checksums.txt   # shasum -a 256 -c on macOS
```

Or build from source:

```bash
git clone https://github.com/sangehq/imprimatur.git
cd imprimatur
make build            # writes build/{host-os}/impr
```

Put the binary on your `PATH`. impr is never published through a package manager or `go install`.
See [installation](docs/installation.md).

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

Profiles live in `~/.config/imprimatur/profiles/` on every OS, Windows
included, and hold credential references only, never a key or password.

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
- [Troubleshooting](docs/troubleshooting.md) — what each refusal means, and what to do about it

### Reference

- [`impr companion info`](docs/tools/companion.md) — the contract v1 other tools call
- [`impr profile`](docs/tools/profile.md) — list, show, add, edit, rm, import, export, validate, default, capabilities, import-legacy
- [`impr build`](docs/tools/build.md) — cross-compile a Go module into `build/{os}/` with a commit-bound build manifest
- [`impr release`](docs/tools/release.md) — build, sign and verify in one step; never tags, pushes or publishes
- [`impr sign`](docs/tools/sign.md) — signing a build manifest, `impr-manifest.json`
- [`impr approve`](docs/tools/approve.md) — a second person's SSH-signed approval for a release, for profiles with `requiresApproval`
- [`impr verify`](docs/tools/verify.md) — checking signatures against a pinned identity
- [`impr cert list`](docs/tools/cert.md) — the certificates and keys profiles use, with expiry
- [`impr rules`](docs/tools/rules.md) — AppLocker and WDAC supplemental policies from a request or from signed files
- [`impr doctor`](docs/tools/doctor.md) — a health report of profiles and host capability
- [`impr menu`](docs/tools/menu.md) — the interactive menu, for a person at a terminal
- [`impr completion`](docs/tools/completion.md) — tab completion for bash, zsh, fish and PowerShell
- [`impr install`](docs/tools/install.md) — install, uninstall and `impr path`
- [`make/impr.mk`](docs/tools/make.md) — impr's commands as Make targets for a project's Makefile
- [`.imprimatur/project.json`](docs/tools/project.md) — a repository's own tighten-only signing rules
- [`impr config`](docs/tools/config.md) — layered configuration (system, user, configuration profiles) and locked keys
- [`impr hooks`](docs/tools/hooks.md) — pinned programs that gate signing and verification or react to events
- [`impr serve`](docs/tools/serve.md) — the REST API and signed inbound webhooks, over a private socket
- [Web UI](docs/tools/web-ui.md) — the browser UI `impr serve` starts on 127.0.0.1:7823, signed in with a one-time link
- [`impr webhooks`](docs/tools/webhooks.md) — signed Standard Webhooks deliveries of impr's events to other apps
- [`impr audit`](docs/tools/audit.md) — the hash-chained record of every command that signs or changes configuration
- [`impr notify`](docs/tools/notify.md) — desktop notifications for failures, vetoes and certificate expiry
- [`impr secret`](docs/tools/secret.md) — store signing secrets in the OS secret store; references in `.env`
- [`impr events`](docs/tools/events.md) — the CloudEvents log of signing and verification runs, and its hash chain
- [Backends](docs/tools/backends.md) — every signing backend, the tools it runs and what it pins

### Recipes

- [Migrate from the PowerShell imprimatur](docs/recipes/migrate-from-powershell.md) — what is imported, and what is not ported yet
- [Sign checksums with an SSH key](docs/recipes/ssh-checksums.md) — the backend that runs on every host
- [Sign and notarise for macOS](docs/recipes/macos-notarization.md) — Developer ID, notarytool and stapler
- [Use impr from sange's pipeline](docs/recipes/sange-pipeline.md) — the calls sange makes and what it checks
- [Sign checksums with a GPG key](docs/recipes/gpg-checksums.md) — a key in gpg-agent, or one held in a secret for CI
- [Sign checksums with minisign](docs/recipes/minisign-checksums.md) — a minisign key pinned by its key id
- [Sign with Azure Artifact Signing](docs/recipes/artifact-signing.md) — the dlib, its metadata, and signing in
- [Sign with a Certum certificate](docs/recipes/certum-signing.md) — a store certificate pinned by thumbprint, and renewal
- [Trust a test certificate](docs/recipes/trust-test-certificate.md) — `impr cert create`, then trust it on a test machine
- [Deploy allow rules](docs/recipes/deploy-allow-rules.md) — AppLocker and WDAC supplemental policies from signed files
- [Sign from a project's Makefile](docs/recipes/project-makefile.md) — `make/impr.mk` and a project file
- [Set up a new machine](docs/recipes/new-machine.md) — install, bring profiles over, check the host
- [Require a second person to approve](docs/recipes/two-person-release.md) — signed approvals for a release profile

## Contributing and security

Report a vulnerability through GitHub private vulnerability reporting, or to
`security@simtabi.com`.

## License

MIT. Copyright (c) 2026 Simtabi LLC. See [LICENSE](LICENSE).
