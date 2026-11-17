# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `impr build VERSION` and `impr release VERSION` stamp VERSION; the positional
  version was silently ignored. `--version` alone now stamps `main.version`
  (the PowerShell build's variable) instead of nothing, and a version that does
  not reach the binary fails the build and names the variable.
- A build given no version takes the latest `v*` tag plus `-snapshot`, or
  `v0.0.0-snapshot` with a warning, as the PowerShell release did.
- `impr build` refuses `--profile`, `--purpose`, `--platforms` and `--repo`
  instead of ignoring them; they belong to `impr release`.
- `impr release --json` prints one document holding the build, sign and verify
  results, and `step` on a failure; it printed two documents.
- `impr path`, `install`, `uninstall` and `version` refuse a stray word
  instead of ignoring it, as the PowerShell tool did.
- `impr profile edit` and `export` with no NAME say on stderr that they use
  the default profile, and name it; they acted on it silently.
- `impr rules FILE...` writes the AppLocker publisher name in AppLocker's own
  form, the subject's O, L, S and C upper-cased without the CN
  (`O=ACME LTD, L=LONDON, C=GB`), as the PowerShell toolkit did. It wrote the
  whole subject, CN included and not upper-cased, so publisher rules could
  fail to match on Windows.
- WDAC rules from `impr rules FILE...` pin the highest certificate below the
  root, as WDAC's Publisher level does and the PowerShell toolkit did; they
  pinned the CA right above the leaf, which Artifact Signing rotates. A leaf
  issued straight by a root pins itself.
- On Windows, `signtool` is found under `Windows Kits\10\bin` (newest SDK,
  this architecture first, then x64) when it is not on `PATH`, as the
  PowerShell toolkit did; a normal SDK install reported Windows signing as
  unavailable.
- `impr profile import-legacy` keeps the Certum thumbprint from
  `CERTUM_THUMBPRINT` (environment or settings file), so an imported Certum
  profile validates without edits.
- An Artifact Signing profile without `dlibPath` or `metadataPath` fails
  `impr profile validate` (and `add`), naming the field; it validated and
  failed only when signing. `impr profile import-legacy` uses the PowerShell
  default `config/metadata.json` when `ARTIFACT_METADATA` was not set.
- `impr rules --enforce` notes that it does not reach the WDAC supplemental
  policy, which follows its base policy's mode; the docs said both were
  enforced.
- `impr rules FILE...` checks each file against its own Authenticode
  signature before making rules, and refuses a file changed after signing
  (exit 4); it took the signer from the file without checking the hash. It
  also warns for a signature with no timestamp.
- `impr rules FILE...` reads an Artifact Signing certificate profile's own EKU
  from the files and pins it, refuses the generic Artifact Signing EKU
  `1.3.6.1.4.1.311.97.1.0` (it matches every customer under the CA) and an
  EKU the certificate lacks. A `--request` with the generic EKU still renders,
  with a note.

### Changed

- `impr rules --scope` takes the PowerShell toolkit's four scopes with their
  meanings: `product` (the default) now allows any file of the product,
  `file` allows the product's listed binaries at any version, and `version`
  adds `--file-version`. In 0.1.0 `product` wrote what `file` writes now and
  `file` was refused, so rules made with `--scope product` in 0.1.0 match
  `--scope file` now. A `--request` gains an optional `scope`; without it a
  request renders as before.
- `impr doctor` exits 5 (unavailable) when it finds problems; it exited 1,
  the usage code, so a caller could not tell a host that is not ready from a
  mistyped command.

## [0.1.0] - 2026-11-17

### Added

- `events.source`: `sange.sh` (the default, unchanged output) or `simtabi.com`.
  It chooses the domain of every event's `source`
  (`https://sange.sh/imprimatur/install/<id>` or
  `https://simtabi.com/sange/imprimatur/install/<id>`) and of the in-toto
  provenance build type (`https://sange.sh/imprimatur/buildtypes/manifest/v1`
  or `https://simtabi.com/sange/imprimatur/buildtypes/manifest/v1`). Any other
  value is refused when the configuration loads. Verification accepts both
  build types under either setting, so earlier attestations still verify.
- The in-toto provenance builder id follows `events.source` too:
  `https://sange.sh/imprimatur` under `sange.sh` (the default, unchanged) and
  `https://simtabi.com/sange/imprimatur` under `simtabi.com`. `impr verify` now
  checks it, accepting either form under either setting and refusing any
  other; every attestation impr wrote before carries the default, so it
  still verifies.
- `impr doctor` reports a launch agent installed under a label impr used before
  2026-11-17, and `impr uninstall` names every impr launch agent left behind,
  under either label. Neither removes one.

- On macOS, `impr serve` checks each Unix-socket connection's peer uid
  (`LOCAL_PEERCRED`), as it already does on Linux.
- On Windows, `impr serve` listens on a named pipe by default. Only the
  current user can open it, remote clients are refused, and a pipe already
  held under the name stops it from starting. `"listen": "unix"` still
  selects the Unix socket.
- `golang.org/x/sys` is a dependency, for the two items above.
- A `github` inbound kind for `impr serve`. It checks `X-Hub-Signature-256`,
  refuses a repeated `X-GitHub-Delivery` for 7 days, answers `ping`, and records
  each delivery as `webhook.inbound.received`. With `run` set, a delivery also runs
  one allowed action. `githubEvents` limits which events are accepted.
- On Linux, `impr serve` checks each Unix-socket connection's peer uid and
  closes connections from any other user.
- Standard Webhooks `v1a` (ed25519), opt-in. `impr webhooks secret --ed25519`
  makes a `whsk_` signing key and its `whpk_` public key. An outbound
  `secretRef` holding a `whsk_` key signs `v1a`. An inbound endpoint takes
  `publicKey` in place of, or beside, `secretRef`.
- `events.required`. When it is on, `impr sign` and `impr verify` fail closed
  (exit 5) if the event log cannot be written. Without it, they warn and carry on, as before.
- `impr events tail --follow` prints each new event until Ctrl-C.
- `post-sign` and `post-verify` hooks. Each runs once the run has finished,
  with its last event on stdin. It cannot veto or change the exit code; a
  failure is a warning plus a `hook.failed` event.
- `webhook.delivery.dead`, `webhook.secret.rotated` and `server.auth.refused`
  events. All three are local-class, and `server.auth.refused` is raised at
  most once a minute per caller.

- `impr webhooks add|rm|rotate|test`. Changes go through the same validation,
  locks and rollback as `impr config set`. `rotate` overlaps two keys, then
  `--finish` drops the old one. Deliveries now honour a receiver's
  `Retry-After`.
- REST endpoints.
  - **Read scope.** `GET /v1/profiles/{name}/capabilities` and
    `POST /v1/rules`, with the request as the body.
  - **Admin scope.** `GET`, `POST` and `DELETE /v1/webhooks…` and
    `POST /v1/webhooks/{name}/test`. Changing configuration also needs
    `server.allowAdmin`, which is off by default.

- `impr events replay --to WEBHOOK` resends logged events to one outbound
  webhook. It sends only what the subscription receives, skips what it already
  acknowledged (unless `--force`), and stops at `--limit`. `--since`, `--type`
  and `--dry-run` narrow it.
- `profile.created`, `profile.changed` and `profile.removed` are now emitted
  (they were catalogued, but never raised). Each carries the profile's name,
  scope, owner, purposes and identity digest.

- `impr doctor` reports impr's folders that group or others can write, and key
  files (`file://` references, the server's TLS key) they can read. It also
  lists every allow-listed tool with its path, SHA-256 and pin.

- `policy.strict` runs every sign and verify as if `--strict` were given, so a
  `ci` or `prod` configuration profile fails closed.

- Redaction. Secret-shaped text (impr's webhook secrets and API tokens, PEM
  private keys, key=value credentials, bearer tokens, credentials in URLs,
  forge, chat and cloud tokens) is masked in every error, log line, event and
  audit record.
- Ctrl-C and SIGTERM stop the running tool and let impr remove its temporary
  keychain, credential files and decrypted keys before exiting 130. A second
  Ctrl-C ends impr at once.

- `impr build` embeds Windows version information, an application manifest and
  an optional `.ico` icon in every Windows binary, written natively with no
  go-winres. It reads `winres/winres.json` when present.
  - **Flags.** `--product`, `--company`, `--description`, `--copyright`,
    `--icon` and `--no-winres`.
  - **Rules.** `impr rules FILE...` now reads the product name from the files
    themselves when `--product` is not given.

- Audit anchoring. With `audit.anchor.enabled`, impr emits an `audit.head` event
  holding the audit trail's and event log's chain heads. It is sent after each
  audited command, and on a schedule under `impr serve`.
  - **Delivery.** Any outbound webhook subscribed to `audit.head`, sange's
    server included, carries it off the machine.
  - **Checking.** `impr audit anchor` emits one on demand, and
    `impr audit verify --against FILE` checks a kept anchor. It catches a
    consistent rewrite of the whole trail, which the chain alone cannot.

- Two more ways to run the expiry check. `impr cert install-check --print`
  prints a daily systemd timer, launchd job or Windows task, and installs
  nothing. `notify.checkOnCommand` makes other commands run the check at most
  once a day; it is off by default.

- `impr rules test --policy FILE FILE...` asks Windows (`Test-AppLockerPolicy`)
  whether a policy would allow each file, and exits 4 on a denial. PowerShell
  is allow-listed for that one embedded script only, checked byte for byte,
  with paths passed as parameters.

- `impr rules --include-default-rules` (and `includeDefaultRules` in a request)
  adds AppLocker's standard default rules to each collection, with a note that
  the Windows folder rule also allows user-writable folders under it.

- Recipes for GPG and minisign checksums, Azure Artifact Signing, Certum,
  trusting a test certificate, deploying allow rules, a project Makefile, a new
  machine and a two-person release, and a troubleshooting page.

- `impr serve install-unit --print` prints a systemd user service, a launchd
  agent or a Windows logon task for `impr serve`, and how to install it. It
  installs nothing itself, and it refuses a config the server would not start
  with. The systemd unit is sandboxed and can write only impr's state directory
  and the signing roots.

- Fuzz tests for every parser that reads untrusted input: checksum files, build
  manifests, profiles, PE signatures and PKCS#7, SSH signature armor, rules
  requests (whose XML output must stay well-formed), webhook deliveries and
  config files. `make fuzz` runs them, and CI runs them weekly. `make vuln` runs
  govulncheck, which CI runs on every pull request.

- Desktop notifications through go-notifykit, impr's first dependency outside
  the standard library. Failed runs, hook vetoes and certificates near expiry
  appear under impr's own name and icon. Nothing is shown in tests or CI.
  - **Commands.** `impr notify send|ping|doctor`, and `impr serve` answers
    `ping`.
  - **Certificate expiry.** `impr cert list`, and `impr serve` every six hours,
    raise `cert.expiring` once per threshold (`notify.certExpiryDays`, default
    30, 14 and 7) and `cert.expired` once.

- Approvals. `impr approve` signs an `imprimatur.approval/v1` document with the
  approver's SSH key. It binds one profile, purpose, commit, tree and build
  manifest digest, and it expires. `impr sign --approval FILE` (and `approvals`
  in `POST /v1/sign`) passes approvals in, and `impr-manifest.json` records
  them.
  - **Opt-in.** impr enforces a profile's `requiresApproval` only when
    `approvals.enforce` is on, because sange enforces it (APR-11) before calling
    impr. A repository's `.imprimatur/project.json` can set `requireApproval`.
  - **Modes.** A profile's `approval` is `signed` (the default; `approvals.required`
    distinct approvers from `approvals.approvers`) or `confirm` (typed at a
    terminal; refused in CI, pipes and the REST API).

- in-toto attestations. With `--platforms attestations`, `impr sign` writes
  `SHA256SUMS.intoto.jsonl`: a DSSE envelope holding an in-toto Statement v1
  over every checksum entry, with SLSA provenance v1 naming the commit, tree
  and repository.
  - **Signer.** The profile's pinned checksum key or cosign signs it; an ssh key
    signs in the `in-toto` namespace.
  - **Verifying.** `impr verify --signed` checks the signer, the subjects and
    the commit, and capabilities report `attestations` wherever its signer
    works.

- `impr serve` streams events. `GET /v1/events/stream` sends the event log as
  Server-Sent Events, with type filters and `Last-Event-ID` resume.
  - **Limits.** At most 8 streams, a keepalive every 15 seconds, and a reconnect
    every hour so the token is re-checked.
- `GET /v1/openapi.json` describes the API as OpenAPI 3.1. Tests hold it to the
  routes the server registers and the request structs' fields.

- Signed profile bundles. `impr profile bundle install|list|verify` installs an
  organisation's managed profiles from an `imprimatur.profile-bundle/v1` file
  signed with `ssh-keygen -Y sign -n imprimatur-bundle`.
  - **Trust.** Only a key in `bundles.trustedKeys` for the bundle's owner is
    accepted; administrators lock `bundles` in the system config.
  - **Checked on every use.** A managed profile is re-verified against its
    stored, signed bundle each time it signs or verifies, so a hand edit stops
    with exit 4.

- `impr rules FILE...` builds allow rules from signed `.exe` and `.dll` files
  on any host. The publisher, leaf and issuing CA (pinned by its TBS hash)
  come from the files' own Authenticode signatures.
  - **Scopes.** `--scope publisher|product|version`, with `--product`,
    `--file-version`, `--base-policy`, `--eku`, `--applocker`, `--wdac`,
    `--enforce` and `--sid`.
  - **Signer check.** Files signed by another publisher or CA are refused.

- `impr cert create` makes a self-signed code-signing certificate and a
  `test` profile that signs with it through osslsigncode on any host.
  - **Files.** The key goes in an owner-only PEM bundle, referenced as
    `file://`, and the public `.cer` sits next to it for trusting on test
    machines.
  - **Supporting changes.** The `pfx` backend accepts such a PEM bundle, and
    `file://` is a reference scheme for owner-only key files.
- `cert list` reads a Windows store certificate's real expiry from the
  certificate `certutil` exports.
- Artifact Signing checks `az account show` before signing when the Azure CLI
  is the credential. `az` is allowed in that one form only.

- **gpg keys held in a secret.** A gpg checksum key can be held in a
  `secret://` or `env://` reference (armored, with an optional `passwordRef`)
  instead of gpg-agent.
  - **Throwaway home.** It is imported into a 0700 gpg home that exists for
    one run.
  - **Verification.** `publicKey` names the armored public key to verify
    against.
- **macOS `.p12` from a reference.** `platforms.macos.certRef` and
  `passwordRef` sign from a `.p12` placed in a temporary keychain for one run
  and deleted afterwards, also on failure. The PowerShell import maps
  `MACOS_SIGN_P12` and `MACOS_SIGN_PASSWORD` to them.

- `impr sign FILE...` signs loose files under the signing root. impr writes
  `impr-loose-manifest.json` bound to HEAD's commit and tree, then signs it
  with every usual check.
  - **Releases.** A release needs a clean git work tree.
  - **Outside git.** Only test and internal purposes sign, and their record
    names commit `000…0`.

- A repository's `.imprimatur/project.json` (`imprimatur.project/v1`) can
  tighten signing in that repository: one profile, the allowed purposes and
  platforms, always `--strict`, always `--repo`.
  - **Where it applies.** It is read from the signing root on every `sign`
    and `verify` (and so `release` and the REST API).
  - **Refused before signing.** A run it refuses stops before anything is
    signed.
  - **Tighten only.** It cannot loosen anything or add anything that runs,
    and an unknown field, a second object or a symlink is an error.

- `impr serve` can serve other machines when `server.allowRemote` and
  `server.tls` (certificate, key, client CA) are set.
  - **mTLS.** It requires TLS 1.3 and a client certificate from that CA on
    every connection, as well as a token.
  - **Key file.** It refuses a key file others can read.
  - **The prompt.** At a terminal it asks before listening on such an address;
    `--yes` skips the prompt.
  - **Default.** Loopback and the Unix socket stay the default.

- **Tool pins.** `config.json` `tools.<name>` pins an external tool to an
  absolute path and sha256. A pinned tool is never looked up on PATH, and is
  refused before it runs if its digest changed. `impr tools list|pin` shows
  and prints pins.
- **`policy.gpgFullFingerprint`**, on by default, refuses gpg pins shorter
  than a full fingerprint at sign and verify time. Set it to `false` to allow
  the 16-hex ids older profiles carry. Breaking: such a profile must be
  re-pinned.
- **Audit trail.** Every command that signs, verifies, builds, releases,
  installs, or changes profiles, configuration, tokens or completion appends
  one record to `<state>/audit/` (hash-chained, 0600). A record holds the
  user, command, arguments with secret-shaped values redacted, exit code and
  duration. `impr audit tail|verify` reads it.
- **Head files.** The event log and the audit trail keep a `head` file with
  the newest line's hash, so an edit to the newest record is detected too.

- `impr build` cross-compiles a Go module into the estate layout
  (`build/{os}/{binary}_{os}_{arch}[.exe]`, `macos` for darwin) from
  `build/targets.txt` or `--targets`, and writes `build/build-manifest.json`
  (`sange.build-manifest/v1`) bound to the git commit and tree.
  - **Fixed `go build`.** It runs `go build` itself: CGO off, the user's go env
    file off, no workspace, local toolchain, `-trimpath`.
  - **No repository code runs.** It never runs a repository's GoReleaser
    config or hooks.
  - **Refusals.** It refuses a version that is not semantic (it goes into
    `-ldflags`), a main package outside the module, and uncommitted changes
    unless `--allow-dirty`.
  - **`--clean`.** It removes only this binary's earlier files under `build/`.
- `impr release` runs build, then `sign` and `verify --signed --manifest`
  with a profile and purpose. It never builds from uncommitted changes, and
  never tags, pushes or publishes.
- The allow-list gains `go` (only `go build`; `-toolexec`, `-exec`,
  `-overlay`, `-modfile` and `-pkgdir` are refused) and `git` (four exact
  read-only forms; `status` runs with fsmonitor off).
- Aliases `b` (build) and `r` (release).

- The interactive menu: `impr menu`, and `impr` with no arguments at a terminal.
  Its entries run the same commands as the CLI. Signing shows the build
  manifest's commit, tree and file count, and signs only after a typed `yes`.
  Without a terminal (a pipe, CI, sange) `impr` alone still prints the usage and
  exits 1.

- `impr completion bash|zsh|fish|powershell`, and `impr completion install|uninstall`
  for bash, zsh and fish into the folders those shells load (no shell profile
  is edited). Completion is generated from the usage text; a test fails if a
  command has none.
- `impr install` copies the running binary to `~/.local/bin` (every OS), never
  replaces a program that is not impr, and never edits PATH (it prints what to
  add). `impr uninstall` removes only impr; `impr path` shows every location.
- `make/impr.mk`: the commands as `impr-*` Make targets for a project's
  Makefile (`impr-sign`, `impr-verify`, `impr-doctor`, `impr-cert`, `impr-rules`,
  `impr-events`, and the aliases `impr-s`, `impr-v`, `impr-d`).
- The PowerShell toolkit's aliases `s` (sign), `v` (verify), `d` (doctor), `h`
  (help).

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
- Event types moved from `sh.sange.imprimatur.*` to
  `com.simtabi.sange.imprimatur.*`, the namespace of Simtabi LLC, which owns
  sange and its family (owner decision, 2026-11-17). The part after the prefix
  is unchanged. New events, webhook deliveries, the event stream, hooks'
  `IMPR_EVENT_TYPE` and `impr events types` carry the new name; a receiver that
  compares the full type must accept it (sange's server already does for
  `audit.head`). Events already logged keep their old type and still verify.
- The launchd labels moved too: `com.simtabi.sange.imprimatur.serve` (was
  `sh.sange.imprimatur.serve`) and `com.simtabi.sange.imprimatur.cert-check`
  (was `sh.sange.imprimatur.cert-check`). impr still installs nothing: with the
  old plist in `~/Library/LaunchAgents`, `impr serve install-unit --print` and
  `impr cert install-check --print` print `launchctl bootout` and `rm -f` for
  it before the new `bootstrap`, and each step is safe to repeat.
- The notifier id is `com.simtabi.sange.imprimatur` (was
  `sh.sange.imprimatur`), and the macOS helper app's bundle id
  `com.simtabi.sange.imprimatur.notifier`. The helper app keeps its path and is
  rewritten on the next notification; macOS asks for notification permission
  once more.

### Deprecated

- The `sh.sange.imprimatur.` type prefix in filters: hook `on`, webhook
  `types`, `impr events tail|replay --type` and the event stream's `type` still
  select the same events with it, and events logged under it still match. May
  be removed no earlier than v0.2.0; write short names (`signing.*`) or the new
  prefix.
- Recognising launch agents under `sh.sange.imprimatur.serve` and
  `sh.sange.imprimatur.cert-check`. May be removed no earlier than v0.2.0.

### Security

- On macOS, signing with a `.p12` no longer puts its password on a command
  line. impr re-wraps the `.p12` with `openssl pkcs12` under a one-time
  password, passing the real password to openssl in its environment. `openssl`
  is allow-listed in those two forms only.

- The module now needs Go 1.27.4. Go 1.27.0 to 1.27.3 carry GO-2026-6859, an
  HTTP/1 server crash in `net/http`'s MaxBytesReader, which `impr serve`
  uses on every request. CI and release builds read the version from
  `src/go.mod`, so they now build with the fixed toolchain. Found by
  govulncheck in CI.

### Fixed

- A build manifest listing a path outside the signing root (`/`, a drive
  letter, `..`) is refused when read, so `impr approve` cannot approve one.
  Signing already refused it. Found by `FuzzReadManifest` in CI's fuzz job.

- `impr audit verify --json` and `impr events verify --json` printed two
  documents when the chain was broken. Each now prints its result once and
  exits 4.

- `impr profile bundle verify --json` printed two documents when a profile
  failed. It now prints its result once and exits 4.

- A failure to render the AppLocker policy is now an error. Before, the error
  was dropped and the policy came out empty.

- A malformed SSH signature whose markers overlap
  (`-----BEGIN SSH SIGNATURE-----END SSH SIGNATURE-----`) no longer panics
  `impr verify`. Found by `FuzzSSHSigKey`.
- A checksum file line whose path holds a control character, such as a lone
  carriage return, is refused. Before, it was accepted as a path that could not
  be written back. Found by `FuzzParseChecksums`. So is a path that starts
  with `*` after the binary-mode marker, or has spaces at either end: each read
  back as a different path. The fuzzer found this one in CI's weekly job.

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
- Validation now agrees with signing:
  - A cert-store or Certum certificate must be pinned by thumbprint. Signing
    already refused a subject-only pin, but validation passed it.
  - An `allowedRepos` pattern must name its host and owner literally.
    `github.com` (every repository on the host), `*/**` and
    `github.com/*/tool` are refused.
  - A macOS `certRef` is no longer silently ignored: it now signs from a
    temporary keychain (see Added).
- An `.msi` (which impr cannot check yet) or a `.pkg` (which needs
  productsign) in a build manifest stops the run before anything is signed,
  instead of being signed in place and failing afterwards.
- Gatekeeper is asked `-t open` for a `.dmg` and `-t install` for a `.pkg`,
  where `-t exec` rejected correctly notarised images.
- Notarisation stages each file in its own folder, so two files with the same
  name in different directories are both submitted.
- A relative cosign `publicKey` resolves against the signing root, as
  `entitlements` does, not the working directory.
- `cert list` and the pre-sign check no longer write a PFX, minisign or SSH
  private key to a temporary file just to report it present. An SSH key's
  fingerprint is read from the unencrypted OpenSSH header.
- A test certificate's signature may fail verification only on the exact
  untrusted-root messages of signtool and OpenSSL. A digest mismatch, expiry,
  revocation or invalid signature always fails.
- A tool whose output passes the 4 MiB cap is an error, not a silently
  truncated answer.
- `--json` and `--help` are read only as options: not as another option's
  value, and not after `--`. `--help` works on every command, and
  `impr help <command>` prints that command's usage.
- `--set managed=…` is refused: managed profiles come from an organisation.
- A failed automatic import of the PowerShell settings is recorded once, not
  retried and re-warned on every command.
- Docs:
  - `docs/release.md` says provenance is attested, now that the repository is
    public.
  - The doctor and companion examples list every capability.
  - The usage text lists `attestations`.

### Changed (CI)

- CI runs the test suite on macOS and Windows weekly and on request. These
  legs never run on pull requests.
