# Contributing to imprimatur

Thanks for helping. This page covers how the code is laid out, how to build and test it, and what a pull
request needs before it can merge.

## Layout

The Go module lives in `src/` (`github.com/sangehq/imprimatur/src`). Everything the toolchain reads is
under `src/`; the repository's own files stay at the top.

```text
src/cmd/impr/          thin entrypoint
src/internal/cli/      the command tree (standard library flag parsing)
src/internal/profile/  signing profiles: model, validation, pinned identity, store, legacy import
src/internal/backend/  one backend per signing kind, behind one port
src/internal/signing/  sign, verify, certificates, capability reports
src/internal/execx/    the only package that runs external programs
src/internal/guardtest repository guards
build/                 targets.txt is tracked; everything else there is generated
```

The module has no third-party dependencies. Adding one needs a reason in the pull request.

## Build and test

```bash
make build      # build/{host-os}/impr
make test       # go test -race ./...
make check      # gofmt check, vet, lint, tests (every local gate)
make lint       # golangci-lint (config in src/.golangci.yml)
make cross      # every target in build/targets.txt, plus build/checksums.txt
```

`make check` is the gate a pull request has to pass locally before it is pushed.

Tests that need a real signing tool run only where it is installed and skip with a reason otherwise.
`ssh-keygen` runs everywhere; `gpg`, `minisign`, `codesign` and the Windows tools run where present. The
cosign real-tool test always skips, because a key-mode run would upload to the public transparency log.

## Guard tests

`src/internal/guardtest` checks the repository itself rather than a feature:

- only `internal/execx` runs programs, and only from its allow-list;
- `build/` holds only `targets.txt`, `checksums.txt`, `archives/` and one folder per OS;
- every docs page has a title, the right footer depth, and the README has its required sections;
- CI has no push trigger and exactly one weekly schedule;
- the release workflow runs only on a version tag or a dispatch naming one, calls the shared, commit-pinned
  `go-release.yml`, and its GoReleaser config publishes nowhere but the GitHub release and builds exactly
  `build/targets.txt`;
- `actions/*` float on a major tag, and every other action is pinned to a commit SHA with a version
  comment;
- the community files the organisation standard requires are present.

A new guard is proven red once, by introducing the defect it catches, before it is relied on.

## Rules for changes

- **Credentials and keys are generated at run time** in tests, never written into a test, fixture or doc.
- **Signing never falls back.** No "first matching certificate", no silent test certificate: a missing or
  ambiguous profile is an error with a fix line.
- **External programs run only through `execx`**, by absolute path, never through a shell.
- **Docs change with the code.** A user-visible change updates the matching page under `docs/` and adds an
  `[Unreleased]` entry to `CHANGELOG.md`.
- **A pushed version tag publishes.** Push one only for code that is ready to ship; see
  [docs/release.md](docs/release.md).

## Pull requests

Branch from `main`, keep one concern per pull request, and fill in the template. Changes reach `main` only
through a pull request with green checks.

## Conduct and security

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities privately as
described in [SECURITY.md](SECURITY.md), never in a public issue.
