# Migrate from the PowerShell imprimatur

Your PowerShell settings become a signing profile automatically; this page
says what is imported, and which PowerShell features the Go `impr` does not
have yet.

## What is imported

The first time impr runs and finds no `profiles.json` of its own, it looks for
the PowerShell toolkit's `config/`: `IMPR_LEGACY_CONFIG`, then the toolkit an
installed `~/.local/bin/impr` or `~/.local/bin/imprimatur` link points into,
then an `imprimatur.settings.json` copied into impr's own config directory. To
run it yourself, or from another place:

```bash
impr profile import-legacy                     # discovery as above
impr profile import-legacy --from ~/tools/imprimatur/config --json
```

| PowerShell configuration | Becomes |
| --- | --- |
| `config/profiles/*.json` and `config/profiles.json` (the 1.8.x profiles) | the same profiles, and the same default |
| `WINDOWS_SIGNER=SelfSigned` (+ thumbprint, subject) | profile `default`: personal, `test`, cert-store. It can never sign a release |
| nothing at all, on Windows (a first run with no toolkit) | the same profile `default`, with the subject `CN=<you> Code Signing (Test)`, as the PowerShell line's migration made; elsewhere nothing is made |
| `WINDOWS_SIGNER=Certum` + `CERTUM_SUBJECT` (+ `CERTUM_THUMBPRINT`) | profile `default`: personal, `internal`, certum, pinned by the thumbprint from `CERTUM_THUMBPRINT` (the environment at import time, or the settings file). Without one, pin it; then add `allowedRepos` and `release` |
| `WINDOWS_SIGNER=Artifact` + `ARTIFACT_DLIB`, `ARTIFACT_METADATA` | profile `default`: personal, `internal`, azure-artifact-signing. With no `ARTIFACT_METADATA`, the old default `<toolkit>/config/metadata.json` is used when it exists. Pin the subject, add `allowedRepos`, then `release` |
| `GPG_FINGERPRINT` | `platforms.checksums` of `default`: gpg, `gpg-agent://<fingerprint>` |
| `MACOS_SIGN_P12`, `MACOS_NOTARY_KEY`, `MACOS_NOTARY_KEY_ID`, `MACOS_NOTARY_ISSUER_ID` set in the environment | profile `default-macos`: `env://` references only, never the values. Set `teamId` and `identity` |

The source is only read. A profile that already exists is kept, never
replaced. Imported profiles may have things to finish; `impr profile validate`
lists them, and impr will not sign with an invalid profile.

## Renamed options

Each old spelling still works as an alias of the Go name (design ID-13):

| PowerShell | Go impr |
| --- | --- |
| `impr profile add NAME --file FILE` | `--from-file FILE` (`--file` still works) |
| `impr profile export NAME --out FILE` | `--out-file FILE` (`--out` still works) |
| `impr install --yes` | accepted; impr install never asks |
| `impr install --no-completion` | leaves out the completion question and hint |
| `impr build VERSION` stamping `main.version` | the same; `--version-var` names another variable |
| `impr build` signing with `--profile`, `--signer`, `--thumbprint` … | moved to `impr release --profile NAME --purpose P` |
| `impr rules --scope file` (product + binary) | the same meaning (ID-11); `--scope product` is product only |
| `impr rules` allow rules for Everyone | `BUILTIN\Users` by default (ID-25); `--sid S-1-1-0` keeps Everyone |
| GoReleaser archives (`.tar.gz`, `.zip`) and the `macos-universal` binary | `impr build --archives` / `impr release --archives` (ID-12); archive names carry no version |

## Dropped by decision

- `impr release --create-cert`: run `impr cert create` once, then release with that test profile.
  `impr build --out DIR`: build output is `build/`, one folder per OS (ID-23).
- For parity, not ported: SBOMs, deb/rpm packages and reproducible builds (they stay on the roadmap),
  Rust builds, and allow rules for scripts (ID-24). The PowerShell line's own changelog (1.0–1.8) is not
  carried into this repository; its history is kept in the owner's archive of the old checkout.

- `impr rules` writes to `--out-dir` only when you name it (no default `policies/`), and makes one set of
  rules per publisher per run (ID-20). Its default input, OriginalFilename grouping, minimum version and
  product-named rules are ported.

- From `make/impr.mk`: the init and menu targets, the toolkit Makefile's bare aliases (`make release`),
  and the 1.7 `imprimatur.mk` (ID-21). The build, release, config, completion, install and path targets
  are ported; include `make/impr.mk` in your own Makefile.

- `--timestamp URL[,URL]` on the command line: put the list in the profile's `platforms.windows.timestamp`,
  which is tried in order (ID-22). The switches `REQUIRE_SIGNING` (use `--strict` or `policy.strict`),
  `IMPR_JSON` (`--json`), `IMPRIMATUR_VERBOSE` (impr always logs each step), `IMPRIMATUR_INTERACTIVE`
  (the menu opens at a terminal unless `CI` is set) and `NO_COLOR` (impr prints no colour) are not read.

- From the menu: the project dashboard, project picker and `config/state.json`, `o`, the init and rules
  entries, and the number keys (ID-18). `b` build, `r` release and `n` install are ported.

- Completion of profile names and config keys, and `completion install --profile FILE` (ID-17): impr
  never edits a shell profile; option values, several shells, `all` and `$SHELL` are ported.

- `impr config KEY=VALUE` (the 1.4 form) and the per-key descriptions of `config list`: the old keys
  no longer exist (ID-16). `impr config list` is `impr config show`; `impr cert show` is `cert list` plus
  the trust steps.

- Short value options (`-p DIR`, `-t LIST`, `-o DIR`, …) and the 1.4 PowerShell style (`-Version 1.2.0`,
  `-Project X`): use the long options (ID-15). `-h` still works. `--no-color` is accepted and changes
  nothing.

- `install.ps1`, `install.sh` and the `imprimatur` command name (ID-14). Install by downloading the
  release asset, checking it against `checksums.txt`, and running `impr install`.

## Feature status

Parity is measured against this list: each line is a PowerShell feature and what
the Go `impr` does instead. Everything left out on purpose is also under
[Dropped by decision](#dropped-by-decision).

| PowerShell feature | Status in the Go impr |
| --- | --- |
| `impr release`, `impr build` (GoReleaser builds, go-winres version info, the GoReleaser signing hook) | **ported** for standalone use as [`impr build`](../tools/build.md) and [`impr release`](../tools/release.md): `go build` into `build/{os}/`, a commit-bound build manifest, then sign and verify. It never runs a repository's GoReleaser config or hooks, and never tags, pushes or publishes. Windows version resources (go-winres) are **ported natively**: impr writes the version information, manifest and icon itself, and reads `winres/winres.json` ([build](../tools/build.md#windows-version-information)). When sange drives a release, its build stage stays the only builder (SD-075). `impr build VERSION` stamps `main.version` as the old build did, and no version gives `<latest v* tag>-snapshot` or `v0.0.0-snapshot`. The old build signed too; in Go `impr build` only builds and refuses `--profile`, `--purpose`, `--platforms` and `--repo`, which belong to `impr release` |
| `impr init` (project template, `.gitignore` edits, `.goreleaser.yaml`), `--main`, `--force` | **ported** as [`impr init`](../tools/init.md): `build/targets.txt` with the template's targets takes the place of `.goreleaser.yaml` (impr builds without GoReleaser, ID-09), the build output goes in `.gitignore`, `--main` chooses the program and `--force` writes the targets again. sange still sets projects up itself when it drives impr |
| `impr sign FILE` (one loose file) and `--signer` | **ported** as `impr sign FILE...`. impr writes a manifest for the files bound to HEAD's commit and tree and signs that, so loose signing is still manifest-bound; a release needs a clean git work tree ([sign](../tools/sign.md#loose-files)). `--signer` stays replaced by profiles |
| `impr config list/get/set/unset/path` (the settings file) | **ported** as [`impr config`](../tools/config.md) (`list` is `show`; `set` joins its words) for the application config (layers, configuration profiles, locked keys); the signing settings became signing profiles and are imported once |
| `impr cert show` and `impr cert create` (the Windows self-signed test certificate) | **ported**: `impr cert show` is `cert list` plus the trust steps (only for a `.cer` that matches the pin), and [`impr cert create`](../tools/cert.md#create-a-test-certificate): a self-signed code-signing certificate in an owner-only file and a `test` profile that signs with it through osslsigncode on any host; `impr cert list` replaces `cert show` |
| `impr rules` reading signed `.exe` files on Windows, with `--scope publisher/product/file/version`, `--include-default-rules`, base WDAC policies, compiling `.cip` with ConvertFrom-CIPolicy, `Test-AppLockerPolicy`, `DEPLOY.md` | **ported**: [`impr rules FILE...`](../tools/rules.md#from-signed-files) (or the build's Windows files with no FILE) on any host, checking each file's signature first, with the same four scopes, the AppLocker publisher name, the PCA and Artifact Signing profile EKU pins, OriginalFilename and minimum versions; `--include-default-rules`; `impr rules test` runs `Test-AppLockerPolicy` (Windows). `DEPLOY.md` became the [deploy allow rules](deploy-allow-rules.md) recipe. Base WDAC policies are rendered only when asked, with `--wdac-base` (owner 2026-11-25; supplemental stays the default, 2026-11-15), and on Windows the WDAC policy is compiled into a `.cip` with `ConvertFrom-CIPolicy` to prove it, as before |
| Signing with a Certum or test certificate chosen by subject alone (exactly one match) | not ported on purpose: `cert-store` and `certum` need a pinned thumbprint |
| Windows store certificate expiry in `cert list` | **ported**: `certutil` exports the pinned certificate and impr reads its expiry from the DER |
| macOS signing from `MACOS_SIGN_P12` and `MACOS_SIGN_PASSWORD` (a temporary keychain) | **ported**: `platforms.macos.certRef` and `passwordRef` put the `.p12` in a keychain that exists for one run and is deleted after it; the import maps both variables |
| Azure login check (`az account show`) before Artifact Signing | **ported**: run before Artifact Signing when the Azure CLI is the credential (`az` allowed in that one form only) |
| GPG keys other than the agent's | **ported**: a `keyRef` of `secret://` or `env://` holding the armored key (with an optional `passwordRef`) is imported into a throwaway gpg home for the run; `publicKey` names the armored public key to verify against |
| `impr install`/`uninstall`, `impr path`, `impr completion`, `impr help <command>` | **ported**: [`impr install`](../tools/install.md) copies the binary to `~/.local/bin` and, on Windows, puts it on the user PATH when you agree or pass `--yes` (`--no-path` leaves it out), then offers completion for your shell as the PowerShell line did; an installed completion follows an upgrade by itself, [`impr completion`](../tools/completion.md) for bash, zsh, fish and PowerShell, `impr help <command>` and `--help` on every command, and the aliases `s`, `v`, `d`, `h` |
| The interactive menu | **ported** as [`impr menu`](../tools/menu.md), also opened by `impr` alone at a terminal, with build (`b`), release (`r`) and install (`n`); the rest is dropped (ID-18) |
| `make/impr.mk` Make integration | **ported**: [`make/impr.mk`](../tools/make.md) with sign, verify, doctor, build, release, config, completion, install and path targets (ID-21) |
| `impr doctor` checks for go, goreleaser, go-winres and git | doctor lists `go` and `git` (with path and digest) among its tools, since `impr build` runs them; goreleaser and go-winres are not needed (impr runs `go build` and writes Windows resources itself). Doctor notes a missing go or git, impr off PATH, missing completion, expiring certificates, Azure sign-in and gpg secret keys (ID-19); colour markers and `~` paths are dropped |
| Moving pre-1.4 files from the toolkit root into `config/` | **ported**: an import from a toolkit moves `imprimatur.settings.json`, `.imprimatur-state.json` and `metadata.json` from its root into `config/` first, as the PowerShell line did; a file already in `config/` wins and the old one is left, reported |

Not in the PowerShell line, and added here: in-toto attestations
([backends](../tools/backends.md#in-toto-attestations)) and signed company or team
profile bundles ([profile](../tools/profile.md#signed-profile-bundles)).

---

[← Docs index](../../README.md#documentation)
