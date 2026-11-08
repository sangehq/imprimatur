# `impr companion info`

The contract v1 that sange, CI and other tools call, and the command that
negotiates it.

```bash
impr companion info [--json]
```

## The contract

- **Transport.** Exec. With `--json`, stdout carries exactly one JSON document
  and every human line goes to stderr. Every document carries `"contract": 1`;
  shapes only ever gain fields.
- **`--strict`.** A platform that would be skipped is an error instead.
- **Exit codes:**

| Code | Meaning |
| --- | --- |
| 0 | ok |
| 1 | usage: a bad command line, a missing or invalid argument, an unknown profile |
| 2 | skipped: a platform this host cannot sign (only without `--strict`) |
| 3 | signing failed, or refused (purpose, repository, digest, pin, expiry) |
| 4 | verification failed |
| 5 | unavailable: a tool, certificate, key or secret this host does not have |

- **Errors.** A failed `--json` call prints an error document on stdout and the
  message, details and fix lines on stderr:

```json
{"contract":1,"ok":false,"exitCode":3,
 "error":{"message":"signing profile me-test is for [test], not release","details":["..."],"fix":["..."]}}
```

`impr sign` without `--strict` that skipped a platform prints its normal result
(with `"ok": false` and `skipped`) and exits 2; a failed `impr verify` prints
its report and exits 4 or 5.

## The info document

```json
{
  "contract": 1,
  "version": "v1.8.0",
  "commands": ["companion info","profile list","profile show","cert list","sign","verify",
               "doctor","profile validate","profile capabilities","rules"],
  "capabilities": {"windows":false,"macos":true,"checksums":true,"containers":false,"attestations":false,"rules":true},
  "capabilityList": ["macos","checksums","rules"],
  "backends": {"authenticode/azure-artifact-signing":false,"authenticode/certum":false,"authenticode/cert-store":false,
               "authenticode/pfx":false,"developer-id/codesign":true,"developer-id/notarytool":true,
               "checksums/gpg":false,"checksums/minisign":false,"checksums/ssh":true,"containers/cosign":false,
               "attestations/in-toto":false},
  "host": "macos",
  "exitCodes": {"ok":0,"usage":1,"skipped":2,"signFailed":3,"verifyFailed":4,"unavailable":5},
  "tools": ["certutil","codesign","cosign","ditto","gpg","minisign","osslsigncode","secret-tool","security",
            "signtool","spctl","ssh-keygen","xcrun"]
}
```

`version` is the `git describe` of the build (`dev` for an unstamped `go build`).
`capabilities` is a map, which is the shape sange reads; `capabilityList` is the
same facts as a list. A platform is `true` when at least one of its backends
can sign on this host. `rules` is always `true`: rendering allow rules needs no
tool. `tools` is the exec allow-list ([architecture](../architecture.md)).

---

[← Docs index](../../README.md#documentation)
