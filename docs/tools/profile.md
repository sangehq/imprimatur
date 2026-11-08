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
