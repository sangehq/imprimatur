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
| `WINDOWS_SIGNER=Certum` + `CERTUM_SUBJECT` | profile `default`: personal, `internal`, certum. Pin the thumbprint, add `allowedRepos`, then add `release` |
| `WINDOWS_SIGNER=Artifact` + `ARTIFACT_DLIB`, `ARTIFACT_METADATA` | profile `default`: personal, `internal`, azure-artifact-signing. Pin the subject, add `allowedRepos`, then `release` |
| `GPG_FINGERPRINT` | `platforms.checksums` of `default`: gpg, `gpg-agent://<fingerprint>` |
| `MACOS_SIGN_P12`, `MACOS_NOTARY_KEY`, `MACOS_NOTARY_KEY_ID`, `MACOS_NOTARY_ISSUER_ID` set in the environment | profile `default-macos`: `env://` references only, never the values. Set `teamId` and `identity` |

The source is only read. A profile that already exists is kept, never
replaced. Imported profiles may have things to finish; `impr profile validate`
lists them, and impr will not sign with an invalid profile.

## Not ported yet

Parity is measured against this list. Each line is a PowerShell feature the Go
`impr` does not have, and why.

| PowerShell feature | Status in the Go impr |
| --- | --- |
| `impr release`, `impr build` (GoReleaser builds, go-winres version info, the GoReleaser signing hook) | **ported** for standalone use as [`impr build`](../tools/build.md) and [`impr release`](../tools/release.md): `go build` into `build/{os}/`, a commit-bound build manifest, then sign and verify. It never runs a repository's GoReleaser config or hooks, and never tags, pushes or publishes. Windows version resources (go-winres) are **ported natively**: impr writes the version information, manifest and icon itself, and reads `winres/winres.json` ([build](../tools/build.md#windows-version-information)). When sange drives a release, its build stage stays the only builder (SD-075) |
| `impr init` (project template, `.gitignore` edits, `.goreleaser.yaml`) | not ported: project setup moves to sange (companion design §2) |
| `impr sign FILE` (one loose file) and `--signer` | **ported** as `impr sign FILE...`. impr writes a manifest for the files bound to HEAD's commit and tree and signs that, so loose signing is still manifest-bound; a release needs a clean git work tree ([sign](../tools/sign.md#loose-files)). `--signer` stays replaced by profiles |
| `impr config list/get/set/unset/path` (the settings file) | **ported** as [`impr config`](../tools/config.md) for the application config (layers, configuration profiles, locked keys); the signing settings became signing profiles and are imported once |
| `impr cert show` and `impr cert create` (the Windows self-signed test certificate) | **ported** as [`impr cert create`](../tools/cert.md#create-a-test-certificate): a self-signed code-signing certificate in an owner-only file and a `test` profile that signs with it through osslsigncode on any host; `impr cert list` replaces `cert show` |
| `impr rules` reading signed `.exe` files on Windows, with `--scope publisher/product/file/version`, `--include-default-rules`, base WDAC policies, compiling `.cip` with ConvertFrom-CIPolicy, `Test-AppLockerPolicy`, `DEPLOY.md` | **partly ported**: [`impr rules FILE...`](../tools/rules.md#from-signed-files) reads the publisher, leaf and issuing CA from the files' own signatures on any host, with scopes `publisher`, `product` and `version` (the `file` hash scope is refused). `DEPLOY.md` is replaced by the [deploy allow rules](deploy-allow-rules.md) recipe, which compiles the `.cip` with ConvertFrom-CIPolicy on the target machine. Base WDAC policies are not ported by owner decision (2026-11-15: supplemental policies only). Still not ported: default rules and `Test-AppLockerPolicy` |
| Signing with a Certum or test certificate chosen by subject alone (exactly one match) | not ported on purpose: `cert-store` and `certum` need a pinned thumbprint |
| Windows store certificate expiry in `cert list` | **ported**: `certutil` exports the pinned certificate and impr reads its expiry from the DER |
| macOS signing from `MACOS_SIGN_P12` and `MACOS_SIGN_PASSWORD` (a temporary keychain) | **ported**: `platforms.macos.certRef` and `passwordRef` put the `.p12` in a keychain that exists for one run and is deleted after it; the import maps both variables |
| Azure login check (`az account show`) before Artifact Signing | **ported**: run before Artifact Signing when the Azure CLI is the credential (`az` allowed in that one form only) |
| GPG keys other than the agent's | **ported**: a `keyRef` of `secret://` or `env://` holding the armored key (with an optional `passwordRef`) is imported into a throwaway gpg home for the run; `publicKey` names the armored public key to verify against |
| `impr install`/`uninstall`, `impr path`, `impr completion`, `impr help <command>` | **ported**: [`impr install`](../tools/install.md) copies the binary to `~/.local/bin` (it never edits PATH), [`impr completion`](../tools/completion.md) for bash, zsh, fish and PowerShell, `impr help <command>` and `--help` on every command, and the aliases `s`, `v`, `d`, `h` |
| The interactive menu | **ported** as [`impr menu`](../tools/menu.md), also opened by `impr` alone at a terminal; build, release and init entries wait for those commands |
| `make/impr.mk` Make integration | **ported**: [`make/impr.mk`](../tools/make.md), targets `impr-sign`, `impr-verify`, `impr-doctor` and more |
| `impr doctor` checks for go, goreleaser, go-winres and git | not ported: they concern building, which impr no longer does |
| Moving pre-1.4 files from the toolkit root into `config/` | not ported: run the PowerShell line once first, or `--from` the file |

Not in the PowerShell line, and added here: in-toto attestations
([backends](../tools/backends.md#in-toto-attestations)) and signed company or team
profile bundles ([profile](../tools/profile.md#signed-profile-bundles)).

---

[← Docs index](../../README.md#documentation)
