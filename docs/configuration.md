# Configuration

impr has no settings file: everything it needs is in signing profiles, which
hold credential references and pinned identities, never a secret.

## Files

| File | What |
| --- | --- |
| `<config>/profiles/<name>.json` | one profile (`imprimatur.signing-profile/v1`) |
| `<config>/profiles.json` | `{"default": "<name>", "migratedFrom": "...", "migratedAt": "..."}` |

`<config>` is `~/.config/imprimatur` (or `$XDG_CONFIG_HOME/imprimatur`) on every
Unix, macOS included, and `%AppData%\imprimatur` on Windows
([installation](installation.md)).

## The profile

```json
{
  "schema": "imprimatur.signing-profile/v1",
  "name": "acme-release",
  "scope": "company",
  "owner": "acme",
  "purpose": ["release"],
  "allowedRepos": ["github.com/acme/**"],
  "requiresApproval": true,
  "platforms": {
    "windows":    { "kind": "authenticode", "backend": "certum", "subject": "CN=Acme Ltd, O=Acme Ltd, C=GB",
                    "thumbprint": "<40 hex>", "timestamp": "http://time.certum.pl" },
    "macos":      { "kind": "developer-id", "teamId": "ABCDE12345",
                    "identity": "Developer ID Application: Acme Ltd (ABCDE12345)",
                    "notary": { "apiKeyRef": "env://ASC_KEY", "keyId": "env://ASC_KEY_ID", "issuer": "env://ASC_ISSUER" } },
    "checksums":  { "kind": "ssh", "keyRef": "env://RELEASE_SSH_KEY", "fingerprint": "SHA256:..." },
    "containers": { "kind": "cosign", "mode": "keyless", "identity": "https://github.com/acme/tool/.github/workflows/release.yml@refs/tags/v1.0.0",
                    "issuer": "https://token.actions.githubusercontent.com" }
  }
}
```

| Field | Rule |
| --- | --- |
| `name` | lower-case letters, digits, `.` `_` `-`, up to 64 |
| `scope` | `personal`, `company`, `team`, `project` or `client:<name>` (then `owner` is that name) |
| `owner` | required |
| `purpose` | `release`, `test`, `internal`; never `test` and `release` together |
| `allowedRepos` | required for `release`; host/owner/repo globs (`*`, `?`, `**`); `*` and `**` alone are refused |
| `requiresApproval` | read by the caller (sange's APR-11); impr does not enforce approvals |
| `managed` | an organisation's profile: impr refuses to edit, replace or remove it |

Per platform, the pin verification checks and the fields each backend reads
are in [backends](tools/backends.md). Fields impr adds to the schema sange
reads, all optional: `windows.passwordRef`, `windows.notAfter`,
`macos.entitlements`, `macos.notAfter`, `checksums.publicKey`,
`checksums.namespace`, `checksums.notAfter`, `containers.publicKey`,
`containers.passwordRef`. A field impr does not know, or anything that looks
like key material (a `password` field, a PEM private key), makes the profile
invalid.

## Credential references

| Reference | Resolves to |
| --- | --- |
| `env://NAME` | the variable's value: a file path, or the key itself |
| `secret://NAME` | the OS secret store, service `imprimatur`, account `NAME`: the macOS keychain (`security find-generic-password`) or the Linux secret service (`secret-tool`); unavailable on Windows |
| `keychain://NAME`, `cert-store://NAME`, `gpg-agent://NAME` | the name; the platform tool reads the store itself |

A value that is key material is written to an owner-only temporary file for
the one tool call that needs it and removed afterwards. Nothing is printed.

## Environment variables

| Variable | Effect |
| --- | --- |
| `IMPR_CONFIG_DIR`, `IMPR_STATE_DIR` | override the config and state directories |
| `IMPR_LEGACY_CONFIG` | the PowerShell toolkit's `config/` (or its settings file) to import from; `off` disables discovery |
| `XDG_CONFIG_HOME`, `XDG_STATE_HOME` | the XDG roots (absolute paths only) |
| `COSIGN_PASSWORD` | set by impr for cosign from `containers.passwordRef`, never read from you |

---

[← Docs index](../README.md#documentation)
