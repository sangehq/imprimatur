# Troubleshooting

What impr's refusals mean, and what to do about each. Every refusal prints a `fix:` line too; this page
explains the common ones.

## Exit codes

| Exit | Meaning | First thing to check |
| --- | --- | --- |
| 1 | usage: a flag, a file or the config is wrong | the message and its `fix:` line |
| 2 | skipped: this host cannot sign a platform, and `--strict` was not set | `impr doctor` |
| 3 | sign failed: a rule refused the run, before anything was signed | the profile, the purpose, `allowedRepos`, approvals |
| 4 | verify failed: a signature, pin or digest does not match | the file changed, or the profile was re-pinned |
| 5 | unavailable: a tool, key or certificate is missing on this host | `impr doctor`, `impr cert list` |
| 130 | interrupted (Ctrl-C or SIGTERM): the running tool was stopped and temporary keychains and credential files were removed; a second Ctrl-C ends impr at once | run it again |

## Signing

- **"is for [test], not release" / "can never sign a release".** The profile's purposes do not include
  the one asked for. A test profile never signs a release; use a release profile.
- **"may not sign …" / "--repo is required to sign a release".** The repository is not in the profile's
  `allowedRepos`, or `--repo` is missing. `impr profile show NAME` lists the allowed repositories.
- **"differs from the build manifest".** A file changed after the build. Rebuild, then sign the new build
  manifest.
- **"changed after it was checked".** Something wrote to a binary while impr was signing it. impr signs a
  private copy of the bytes it checked and refuses when they no longer match; find the writer (a watcher,
  a second build), then sign again.
- **"needs N approval(s) and has 0 valid".** The profile requires approval and `approvals.enforce` is on.
  An approver runs `impr approve`; see [two-person release](recipes/two-person-release.md).
- **"no terminal to ask".** The profile's approval is `confirm`, which only a person at a terminal can
  give. Run it at a terminal, or use signed approvals.
- **"managed profile … differs from its signed bundle".** Someone edited a profile your organisation
  manages. Reinstall the signed bundle with `impr profile bundle install`.
- **"pins gpg key …, a short id".** Re-pin the full fingerprint: `gpg --fingerprint <id>`, then
  `impr profile edit NAME --set platforms.checksums.fingerprint=<full>`.

## Hosts and tools

- **"signing is not available on this host".** The platform's tool is missing: `signtool` or
  `osslsigncode` for Windows, `codesign` for macOS, `gpg`, `minisign`, `ssh-keygen` or `cosign` for
  checksums. `impr doctor` names it. On Windows, impr finds `signtool` on `PATH` or, where the Windows SDK
  puts it, under `%ProgramFiles(x86)%\Windows Kits\10\bin\<version>\<arch>\signtool.exe`: the newest
  SDK version, this machine's architecture first, then x64. Install the SDK's "Signing Tools for Desktop
  Apps" if neither has it.
- **"refused to run: sha256 … is not the pin".** A pinned tool (`tools.<name>`) was upgraded. Pin the
  new file: `impr tools pin <name>`, then `impr config set tools.<name> …` with what it prints.
- **"has no private key here" (Windows).** The pinned certificate is in the store without its key: a
  Certum card needs SimplySign Desktop logged in, and a certificate imported from a `.cer` has no key
  (import the `.pfx`).
- **"there is no certificate with thumbprint …" (Windows).** Nothing in `Cert:\CurrentUser\My` has the
  pinned thumbprint. List them with `Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert` and pin the
  right one.
- **"is not signed in" (Azure).** Run `az login`, or give CI a service principal or managed identity.
- **Artifact Signing answers 403 Forbidden.** Usually the `Endpoint` in `metadata.json` names another
  region than the code signing account's (`https://weu.codesigning.azure.net` for West Europe,
  `https://eus.codesigning.azure.net` for East US, …). Match the account's region in the Azure portal;
  then check that your identity holds the certificate-profile signer role on the account.
- **"expired on …".** The certificate is past its `notAfter`. Renew it, then re-pin the profile.

## Verifying

- **"has been re-pinned since … was signed".** The profile's pinned identity changed after signing. Verify
  with the profile as it was, or re-sign.
- **"does not match the signed checksum".** A listed file changed after signing.
- **"… names other files or digests" (in-toto).** The attestation belongs to another build.

## The server and notifications

- **"no API token or inbound endpoint is configured".** `impr server token add --scopes read,verify`.
- **A token stopped working.** `impr server token revoke` takes effect when the server restarts.
- **No desktop notifications.** `impr notify doctor` says which notifier this host has and why it is off:
  `notify.desktop` is false, `IMPR_NOTIFY_DESKTOP=0` is set, or it is CI. On macOS, allow
  "impr Notifier" in System Settings > Notifications.

## Still stuck

`impr events tail` shows what each run did, and `impr audit verify` shows whether the audit trail is
intact. Report a bug with that output, minus anything you would not publish, at
<https://github.com/sangehq/imprimatur/issues>.

---

[← Docs index](../README.md#documentation)
