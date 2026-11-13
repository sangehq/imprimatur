# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- The read commands (`companion info`, `profile list`, `profile show`, `cert list`)
  accept `--strict`, and `companion info` advertises the `strictReads`
  capability, so sange can pass `--strict` to every call.
- Repository files the organisation standard requires: `CONTRIBUTING.md`,
  `SECURITY.md` (reports by email to security@simtabi.com), `CODE_OF_CONDUCT.md`
  (Contributor Covenant 2.1), `.editorconfig`, a weekly grouped Dependabot
  configuration for Go modules and GitHub Actions, issue templates and a pull
  request template, with a guard test that fails when any of them is missing
  or loses its required text.
- The Go rewrite of imprimatur (SIG-07, decision SD-066), module
  `github.com/sangehq/imprimatur/src`, one binary `impr`. The PowerShell 1.8.x
  line stays in use until this one reaches parity; see
  [migrate from the PowerShell imprimatur](docs/recipes/migrate-from-powershell.md)
  for what is not ported yet.
- Signing profiles (`imprimatur.signing-profile/v1`): scope, owner, purposes,
  `allowedRepos`, `requiresApproval`, per-platform specs holding credential
  references only, and the pinned identity verification must find. A profile is
  never both `test` and `release`; key material in a profile file is refused.
- `impr profile list|show|add|edit|rm|import|export|validate|default|capabilities|import-legacy`.
- The PowerShell line's settings (`imprimatur.settings.json`) and profiles are
  imported automatically the first time impr runs, or with
  `impr profile import-legacy`; the `MACOS_*` variables become a separate
  `default-macos` profile of `env://` references.
- Backends behind one port (`Sign`, `Verify`, `Capability`, `Certificate`):
  Authenticode (Azure Artifact Signing, Certum, Windows certificate store through
  signtool; `.pfx` through osslsigncode), Apple Developer ID (codesign,
  notarytool, stapler), GPG, minisign and SSH checksum signatures, and cosign
  bundles, key or keyless.
- Contract v1 for sange: `--json` on stdout, human text on stderr, exit codes
  0 to 5, `--strict`; `impr companion info`, `impr sign --manifest`,
  `impr verify`, `impr cert list`, `impr doctor`, and `impr rules --request`
  (AppLocker publisher rules and a WDAC supplemental policy, deterministic, no
  file-hash rules).
- `impr-manifest.json` per signing run: the profile, its pinned identity and
  digest, the build-manifest digest, and every file's digest before and after
  signing.
- Every external tool runs through one allow-listed adapter by absolute path,
  never through a shell.
- Configuration and state under XDG on every Unix, macOS included
  (`~/.config/imprimatur`, `~/.local/state/imprimatur`), `%AppData%` and
  `%LocalAppData%` on Windows.

### Changed

- Releases build on a pushed `vX.Y.Z` tag, or on request with
  `gh workflow run release.yml --repo sangehq/imprimatur -f tag=vX.Y.Z`, through
  `simtabi/.github`'s shared `go-release.yml` and a new `src/.goreleaser.yaml`.
  The binaries still ship on the GitHub release only, under the same names
  (`impr_{os}_{arch}[.exe]` for every line of `build/targets.txt`, plus
  `checksums.txt`), and `checksums.txt` now lists bare file names. The
  dispatch-only workflow and its `confirm=release-go` input are gone; the guard
  tests now pin the new triggers, the pinned shared call, a GoReleaser config
  that publishes nowhere else, and its targets against `build/targets.txt`.
