# `impr profile`

Eleven subcommands manage signing profiles: `list`, `show`, `add`, `edit`, `rm`,
`import`, `export`, `validate`, `default`, `capabilities` and `import-legacy`.

```bash
impr profile list [--json]
impr profile show NAME [--json]
impr profile add NAME [--scope S] [--owner O] [--purpose P[,P]] [--allowed-repo GLOB]...
                      [--requires-approval] [--notes TEXT] [--set KEY=VALUE]... [--unset KEY]...
                      [--from-file FILE] [--force]
impr profile edit NAME [the same options as add, except --from-file and --force]
impr profile rm NAME [--force]
impr profile import FILE [--force]
impr profile export NAME [--out-file FILE]
impr profile validate [NAME] [--json]
impr profile default [NAME] [--json]
impr profile capabilities [NAME] [--json]
impr profile import-legacy [--from PATH] [--json]
```

`impr profile` with no subcommand is `list`. The format is in
[configuration](../configuration.md).

## Subcommands

| Subcommand | What it does |
| --- | --- |
| `list` | every profile and the default. `--json`: `{"contract":1,"default":"me-test","profiles":[<profile>...]}` |
| `show` | one profile as JSON on stdout, and its identity digest on stderr. `--json` adds `"contract": 1` to the profile document |
| `add` | creates a profile and validates it; nothing is saved if it is invalid. The first profile becomes the default. `--force` replaces an existing one |
| `edit` | changes a profile; `--set` reaches any field by dotted path, `--unset` removes one |
| `rm` | removes a profile; the default needs `--force` |
| `import` | adds a profile from a file, which must be valid |
| `export` | the profile as JSON, on stdout or to `--out-file` (0600) |
| `validate` | every problem in one or all profiles; exit 1 when any has one. `--json`: `{"contract":1,"ok":false,"profiles":[{"name":"...","identityDigest":"sha256:...","problems":["code: detail"]}]}` |
| `default` | prints the default, or sets it |
| `capabilities` | per profile and platform, whether this host can sign and verify, with the reason when it cannot. `--json`: `{"contract":1,"host":"macos","profiles":[{"name":"...","valid":true,"platforms":{"checksums":{"platform":"checksums","kind":"ssh","sign":true,"verify":true,"tools":["ssh-keygen"],"supported":true}},"ready":["checksums"]}]}` |
| `import-legacy` | imports the PowerShell line's configuration ([migration](../recipes/migrate-from-powershell.md)) |

## Options

- `--purpose` and `--allowed-repo` take several values, comma-separated or
  repeated.
- `--set KEY=VALUE` reads `VALUE` as JSON when it is `true`, `false`, `null`, a
  list or an object, and as a string otherwise:
  `--set platforms.macos.teamId=ABCDE12345`, `--set requiresApproval=true`.
- A profile cannot be renamed with `--set name=...`; export it, change the name,
  and import it.

## Several certificates

A profile's Windows spec can list several certificates. For example, Certum for `.exe` files on amd64 and
Azure Artifact Signing for arm64, or an old and a new certificate during a renewal:

```json
"windows": {
  "kind": "authenticode",
  "signers": [
    {"id": "ev-2026", "backend": "certum", "thumbprint": "3F…", "notBefore": "2026-01-01T00:00:00Z",
     "notAfter": "2027-01-01T00:00:00Z", "select": {"arch": ["amd64", "386"]}},
    {"id": "azure-arm", "backend": "azure-artifact-signing", "subject": "CN=Acme Ltd",
     "dlibPath": "…", "metadataPath": "…", "select": {"arch": ["arm64"]}},
    {"id": "installers", "backend": "certum", "thumbprint": "3F…", "select": {"glob": ["*.msi"]}}
  ]
}
```

- **Each signer is a whole certificate.** It has its own backend, pin (`thumbprint` or exact `subject`),
  references, timestamp server, and `notBefore` and `notAfter` dates.
- **Selectors.** `select.arch` matches the PE machine (386, amd64, arm, arm64). `select.glob` matches the
  file name or its path in the manifest. An empty selector matches every file.
- **One signer per file.** impr signs each Windows file with exactly one signer: the one whose selector
  matches and whose dates include now. A file with no such signer stops the whole run before anything is
  signed. So does a file that several signers match, unless every one of them has a `notBefore`; then the
  newest wins, which is how a renewal overlaps.
- **Recording and verifying.** `impr-manifest.json` records each file's `signerId`, and `impr verify
  --signed` checks the file against exactly that signer. A loose file passes if any signer whose selector
  matches it verifies it.
- **Pinned identity.** The profile's pinned identity lists every signer, so adding or re-pinning one
  changes the identity digest. A profile without `signers` keeps exactly the pin and digest it had.
- **Not supported yet.** `mode: "all"` (dual signing) is refused for now.

Edit signers as JSON, for example
`impr profile edit acme-release --set 'platforms.windows.signers=[{"id":"ev-2026",…}]'`.

## What is refused

- An unknown field, or anything that looks like key material, in a profile.
- A credential written as a value rather than a reference.
- `test` and `release` together, a release profile with no `allowedRepos`, and
  `*` or `**` as an allowed repository.
- Changing, replacing or removing a `managed` profile.
- Signing with no `--profile` and no default: impr never falls back to the
  first profile, a test certificate, or the first certificate whose subject
  matches.

---

[← Docs index](../../README.md#documentation)
