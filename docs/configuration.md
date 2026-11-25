# Configuration

impr has no settings file: everything it needs is in signing profiles, which
hold credential references and pinned identities, never a secret.

## Files

| File | What |
| --- | --- |
| `<config>/profiles/<name>.json` | one profile (`imprimatur.signing-profile/v1`) |
| `<config>/profiles.json` | `{"default": "<name>", "migratedFrom": "...", "migratedAt": "..."}` |

`<config>` is `~/.config/imprimatur` (or `$XDG_CONFIG_HOME/imprimatur`) on every
OS, Windows included ([installation](installation.md)).

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
| `requiresApproval` | the run needs approval. sange enforces it (APR-11); impr enforces it too when `approvals.enforce` is on ([`impr approve`](tools/approve.md)) |
| `approval` | with `requiresApproval`: `signed` (default, approvers' SSH-signed approvals) or `confirm` (typed at a terminal) |
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
| `file:///ABS/PATH` | a key file, which must be a regular file only its owner can read or write |
| `keychain://NAME`, `cert-store://NAME`, `gpg-agent://NAME` | the name; the platform tool reads the store itself |

Because a store reference resolves to a name, it is refused where impr needs the secret's value: every
`passwordRef` takes `env://` or `secret://`, and key material (`notary.apiKeyRef`, a minisign or ssh
`checksums.keyRef`, a cosign `containers.keyRef`) takes `env://`, `secret://` or `file://`. A gpg
`keyRef` may still be `gpg-agent://<fingerprint>`.

A value that is key material is written to an owner-only temporary file for
the one tool call that needs it and removed afterwards. Nothing is printed.

## The web UI

Two settings under `server.web` in `config.json` shape the [web UI](tools/web-ui.md). `impr config set`
checks each value, and `impr serve` reads them when it starts.

| Key | Values | Default | Effect |
| --- | --- | --- | --- |
| `server.web.tokenAccess` | `secrets`, `scopes` | `secrets` | What signing in with an API token at `/signin` reaches: the Secrets page only, or whatever the token's scopes allow ([web UI](tools/web-ui.md#signing-in)) |
| `server.web.webhookAdmin` | `allowAdmin`, `owner` | `allowAdmin` | Whether adding or removing a webhook in the web UI needs `server.allowAdmin`, as over the API, or is open to the owner signed in with `impr serve`'s link |

```bash
impr config set server.web.tokenAccess scopes
impr config set server.allowAdmin true          # or: impr config set server.web.webhookAdmin owner
```

## Environment variables

| Variable | Effect |
| --- | --- |
| `IMPR_CONFIG_DIR`, `IMPR_STATE_DIR` | override the config and state directories |
| `IMPR_LEGACY_CONFIG` | the PowerShell toolkit's `config/` (or its settings file) to import from; `off` disables discovery |
| `XDG_CONFIG_HOME`, `XDG_STATE_HOME` | the XDG roots (absolute paths only) |
| `COSIGN_PASSWORD` | set by impr for cosign from `containers.passwordRef`, never read from you |
| `NO_COLOR` | nothing to turn off: impr prints no colour. `--no-color` is accepted anywhere on the line for the same reason |

## Help

`impr CMD --help`, `impr help CMD` or `impr -h CMD` (also `--help`, `-?` and `/?`) prints what the command does, its usage lines, the exit codes and
its page under `docs/tools/`. A mistyped command or option gets the nearest name: `impr relase` answers
`did you mean: impr release`. An option before the command is refused with the line to run instead:
`impr --profile p sign` answers `put the command first` and `impr sign --profile p`.

---

[← Docs index](../README.md#documentation)
