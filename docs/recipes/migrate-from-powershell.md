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
| `impr release`, `impr build` (GoReleaser builds, go-winres version info, the GoReleaser signing hook) | not ported: when sange drives a release its build stage is the only builder (SD-075), and impr signs that stage's manifest |
| `impr init` (project template, `.gitignore` edits, `.goreleaser.yaml`) | not ported: project setup moves to sange (companion design §2) |
| `impr sign FILE` (one loose file) and `--signer` | not ported on purpose: impr signs build-manifest entries only, so it is not a signing oracle |
| `impr config list/get/set/unset/path` (the settings file) | replaced by profiles; the settings are imported once |
| `impr cert show` and `impr cert create` (the Windows self-signed test certificate) | not ported: creating a store certificate needs the Windows certificate APIs. `impr cert list` is ported |
| `impr rules` reading signed `.exe` files on Windows, with `--scope publisher/product/file/version`, `--include-default-rules`, base WDAC policies, compiling `.cip` with ConvertFrom-CIPolicy, `Test-AppLockerPolicy`, `DEPLOY.md` | not ported: `impr rules --request` renders from facts sange supplies, supplemental WDAC only, and compiles nothing |
| Signing with a Certum or test certificate chosen by subject alone (exactly one match) | not ported on purpose: `cert-store` and `certum` need a pinned thumbprint |
| Windows store certificate expiry in `cert list` | partly: presence is checked with `certutil`; expiry comes from a declared `notAfter` |
| macOS signing from `MACOS_SIGN_P12` and `MACOS_SIGN_PASSWORD` (a temporary keychain) | not ported: the identity must already be in a keychain |
| Azure login check (`az account show`) before Artifact Signing | not ported: `az` is not on the exec allow-list; signtool fails instead |
| GPG keys other than the agent's | not ported: `keyRef` must be `gpg-agent://<fingerprint>` |
| The interactive menu, `impr install`/`uninstall`, `impr path`, `impr completion`, `impr help <command>` | not ported: impr prints one usage text |
| `make/impr.mk` Make integration | not ported |
| `impr doctor` checks for go, goreleaser, go-winres and git | not ported: they concern building, which impr no longer does |
| Moving pre-1.4 files from the toolkit root into `config/` | not ported: run the PowerShell line once first, or `--from` the file |

Not in the PowerShell line either, and not here yet: in-toto attestations, and
signed company or team profile bundles (impr honours `managed` but cannot
install a bundle).

---

[← Docs index](../../README.md#documentation)
