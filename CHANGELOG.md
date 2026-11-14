# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Layered configuration with configuration profiles.** The effective
  configuration merges three layers, each over the one before, as a JSON
  merge patch:
  1. the machine's system config (`/etc/imprimatur`,
     `/Library/Application Support/imprimatur`, `%ProgramData%\imprimatur`;
     `IMPR_SYSTEM_CONFIG_DIR` overrides it);
  2. the user's `config.json`;
  3. the active configuration profile, `config.d/<name>.json`, chosen by
     `IMPR_CONFIG_PROFILE` or `activeProfile`.

  How it behaves:
  - **Locks.** The system config can lock keys; a lower layer that sets one,
    or replaces its parent, is refused. Only the system config may lock.
  - **Profiles.** A selected profile that does not exist is an error, never
    "no profile".
  - **Checks.** Every layer must be owner-only and is decoded strictly.
  - **Commands.** `impr config path|show|validate|get|set|unset` and
    `impr config profile list|create|use|rm`. A change that would not load,
    or that touches a locked key, is rolled back and the file left as it was.
  - **Events and capability.** Changes are recorded as `config.changed`, and
    `companion info` reports `configProfiles`.

- **Multi-certificate Windows signing.** `platforms.windows.signers` lists several
  certificates. Each signer has its own backend, pin, references and dates, and
  a selector (`arch`: 386, amd64, arm, arm64; `glob` on the file name or path).
  - **One signer per file.** Each Windows file is signed by exactly the one
    signer that may sign it now. A file no signer covers, or one that several
    signers match, fails the run before anything is signed. There is never a
    first match.
  - **Rotation.** When every matching signer declares `notBefore`, the newest
    one wins, and an expired signer is never chosen.
  - **Record and verify.** The record names each file's `signerId`, and verify
    checks that file against exactly that signer.
  - **Reporting.** `cert list` reports each signer, and `profile capabilities`
    reports the platform ready only when every signer can sign on the host.
  - **Compatibility.** A single-certificate profile is unchanged, and so is its
    pinned identity digest, which sange computes too.
  - **Not yet.** Dual signing (`mode: all`) is refused until the backends can
    append signatures.
  - **Capability.** `companion info` reports `multiSigner`.

- `impr serve`: a REST API over the same commands, answering with exactly the
  `--json` document each command prints.
  - **Endpoints.** `GET /v1/health|companion|doctor|profiles|profiles/{name}|certs|events`,
    `POST /v1/verify`, `POST /v1/sign`.
  - **Transport.** It listens on a Unix socket (`<state>/server/impr.sock`,
    0600 in a 0700 dir) or a loopback port; other addresses are refused.
  - **Auth.** Every endpoint but `/v1/health` needs a scoped bearer token
    (`read`, `verify`, `sign`, `events`). `impr server token add|list|revoke`
    shows a token once and stores only its sha256. Every refusal returns the
    same 401 body.
  - **Request limits.** A rate limit per token, a 1 MiB body cap, and strict
    JSON.
  - **Where artifacts come from.** verify and sign read artifacts only under
    `server.roots`.
  - **Signing.** `/v1/sign` is off unless `server.allowSign` is set. It then
    needs the `sign` scope and the same commit- and tree-bound manifest as the
    CLI, and runs one signing at a time.
  - **Inbound webhooks.** Other apps can call `POST /v1/hooks/{name}` with a
    Standard Webhooks signature. A replay ledger persists across restarts, and
    each endpoint has an allow-list of actions (`verify`, `doctor`,
    `cert.list`, `profile.list`); signing is never one of them.
  - **Lifecycle and capability.** `server.started` and `server.stopped` are
    recorded, Ctrl-C or SIGTERM shuts it down gracefully, and `companion info`
    reports `server`.

- Outbound webhooks: `config.json` `webhooks.outbound` sends impr's events to
  other apps as Standard Webhooks 1.0 deliveries. Each delivery carries
  `webhook-id`, `webhook-timestamp` and a `v1` HMAC-SHA256 signature, checked
  against the reference test vector; the body is the structured CloudEvent.
  - **Secrets.** Every secret is a `whsec_` value impr generates
    (`impr webhooks secret`) and holds by reference. During a rotation a
    previous secret signs alongside the new one.
  - **Targets.** Only https is used; private, loopback and link-local targets
    (cloud metadata included) are refused unless `allowPrivate` is set. The
    check is made on the address actually dialled. No redirects are followed,
    and the timeout is 15 s.
  - **Outbox.** Every delivery goes through a durable outbox in the state dir:
    a retry schedule, `410` sends straight to the dead letter, and
    `impr webhooks list|secret|retry|deliveries` manage it.
  - **What is sent.** Local-class events never leave the machine.
  - **Capability.** `companion info` reports `webhooks`.

- Hooks: `<config>/config.json` (`imprimatur.config/v1`) can name `pre-sign`,
  `pre-verify` and `event` hooks. Each is an absolute path pinned by sha256, and
  runs with no shell, the CloudEvent on stdin, a minimal environment and a
  timeout. A `pre-*` hook with `veto` stops the run before anything is signed
  or verified (exit 3 or 4) and records `hook.vetoed`. A pre-hook that fails its
  pin also stops the run. Hooks come only from the user's own config, never from
  a repository; a group- or world-writable `config.json` or hook is refused.
  `impr hooks list|pin|test`; `companion info` reports the `hooks` capability.

- Events: impr records a CloudEvents 1.0 event for every signing and
  verification run (`sh.sange.imprimatur.signing.run.started`, `.artifact.signed`,
  `.run.completed|skipped|failed`, `verification.run.completed|failed`) in a
  hash-chained log at `<state>/events/YYYY-MM.jsonl`, with a random install id as
  the source. `impr events tail|verify|types` reads it; `companion info` reports
  the `events` capability. Events never go to stdout, so `--json` output is
  unchanged.

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

- Configuration and state now live in `~/.config/imprimatur` and
  `~/.local/state/imprimatur` on every OS, Windows included (`XDG_CONFIG_HOME`
  and `XDG_STATE_HOME` are honoured everywhere). On Windows the first run copies
  an existing `%AppData%\imprimatur` and `%LocalAppData%\imprimatur` across once,
  writes `<config>/.migrated-from`, and leaves the old folders in place.

- The action-pin guard expects a shared workflow (`owner/.github/.github/workflows/*.yml`) pinned to a commit with a `# vX.Y.Z` comment naming its release tag, in place of the `# owner/.github#N` pull-request comment, now that simtabi/.github tags its releases.
- `release.yml` calls simtabi/.github's shared `go-release.yml` at its `v0.1.0` release (`b3388da`), pinned as `@<commit>  # v0.1.0` so Dependabot can advance the commit and the tag comment together. v0.1.0 replaces the withdrawn `v1.0.0` and `v1.0.1`: it adds optional inputs only (`node-version` among them), fetches every owned org's Go modules from git rather than proxy.golang.org, and changes nothing a caller passes.
- `make check-build` is new, and `make build` and `make cross` run it after they write: it fails when `build/` holds anything but `targets.txt`, `checksums.txt` and the OS folders, and when it inspected fewer files than the build wrote (`BUILD_LAYOUT_MIN`: 2 after `make build`, one per target plus two after `make cross`).
- Releases build on a pushed `vX.Y.Z` tag, or on request with
  `gh workflow run release.yml --repo sangehq/imprimatur -f tag=vX.Y.Z`, through
  `simtabi/.github`'s shared `go-release.yml` and a new `src/.goreleaser.yaml`.
  The binaries still ship on the GitHub release only, under the same names
  (`impr_{os}_{arch}[.exe]` for every line of `build/targets.txt`, plus
  `checksums.txt`), and `checksums.txt` now lists bare file names. The
  dispatch-only workflow and its `confirm=release-go` input are gone; the guard
  tests now pin the new triggers, the pinned shared call, a GoReleaser config
  that publishes nowhere else, and its targets against `build/targets.txt`.

### Fixed

- `impr verify --signed` re-hashes every file the signed `SHA256SUMS` lists.
  Before, it checked only the checksum file's signature, so a tampered archive
  passed. With `--manifest`, every build-manifest file must be signed or listed.
- `impr verify --signed` refuses a record that lists no artifacts or outputs,
  where it exited 0.
- A file missing at verify time exits 4 (verification failed), not 5.
- `impr sign` fails when no requested platform had files to sign, where it
  exited 0 having signed nothing.
- `SHA256SUMS` and `impr-manifest.json` are written by atomic rename, so a
  symlink planted at either path is replaced rather than written through.
- External tools no longer inherit impr's whole environment. Each sees a base
  set (PATH, HOME, temp, locale, TLS roots, proxies, Windows system folders) plus
  the few variables it needs (for example `GNUPGHOME` for gpg, `SSH_AUTH_SOCK`
  for ssh-keygen), so a secret held in an `env://` variable reaches only the
  backend that asked for it. cosign's `env://` key is passed to it explicitly.
- gpg verification fails on a revoked or expired key, an expired, bad or
  unverifiable signature, or a non-zero exit, even when a `VALIDSIG` line is
  present, and a full 40- or 64-hex pin must equal the signing fingerprint (a
  shorter long-key-id pin still matches as a suffix, as before).
- Reading an Authenticode signature refuses a certificate table larger than
  the file or 16 MiB, where a crafted PE could make impr allocate up to 4 GiB.
