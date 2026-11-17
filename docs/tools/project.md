# `.imprimatur/project.json`

A repository can commit `.imprimatur/project.json` to tighten how impr signs and verifies it. A project file
can never loosen anything.

```json
{
  "schema": "imprimatur.project/v1",
  "profile": "acme-release",
  "purposes": ["release"],
  "platforms": ["windows", "checksums"],
  "strict": true,
  "requireRepo": true
}
```

| Field | Effect |
| --- | --- |
| `profile` | `sign` and `verify` in this repository use only this signing profile |
| `purposes` | `sign` accepts only these purposes |
| `platforms` | `sign` signs only these platforms; requesting another is refused |
| `strict` | every `sign` and `verify` must run with `--strict` |
| `requireRepo` | every `sign` must name the repository with `--repo`, whatever the purpose |
| `requireApproval` | every release signed here needs approval, in the profile's mode, whatever `approvals.enforce` says ([`impr approve`](approve.md)) |

## Rules

- **Where impr reads it.** impr reads the file from the signing root (`--root`) of every `sign` and
  `verify`, including `impr release` and the REST API.
- **Refused before anything is signed.** A run the file refuses exits 3 (sign) or 4 (verify).
- **Tighten only.** The file can only restrict. There is no field to add hooks, webhooks, tools or
  servers, or to change a profile. An unknown field, a second JSON object, a symlink or anything over
  64 KiB is an error, never a file read halfway.
- **Repository versus host.** The repository is not trusted to decide what runs. That stays with the host
  owner's [configuration](config.md).

---

[← Docs index](../../README.md#documentation)
