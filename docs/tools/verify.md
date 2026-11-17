# `impr verify`

Checks signatures against exactly one profile's pinned identity, never "signed
by someone".

```bash
impr verify --signed impr-manifest.json [--manifest build-manifest.json] --profile NAME [--root DIR] [--json] [--strict]
impr verify FILE... --profile NAME [--root DIR] [--json] [--strict]
```

## With `--signed`

- The record's profile must be `--profile`, and its pinned identity must still
  be the profile's (a re-pinned profile fails).
- With `--manifest`, the record must belong to that build manifest (its digest,
  commit and tree).
- Every artifact must still have the digest recorded after signing, and verify
  on its platform. The `SHA256SUMS` the run wrote is checked with the checksum
  and cosign backends that signed it.

## With files

Each file is checked by its kind: a PE or `.msi` as Windows, a Mach-O, `.dmg` or
`.pkg` as macOS, and any other file as a checksum file when it has a
`.sig`/`.minisig` (checksums) or `.sigstore.json` (cosign) beside it.

## Checks per platform

| Platform | Check |
| --- | --- |
| Windows | the signer certificate in the file's own Authenticode signature has the pinned thumbprint and/or exact subject, and a timestamp; `signtool verify /pa` (Windows) or `osslsigncode verify` succeeds. A `test` profile also accepts a signature whose only fault is an untrusted root |
| macOS | `codesign --verify --deep --strict`; `TeamIdentifier` is the pinned team and an `Authority` line is the pinned identity; `spctl -a -t exec` when the run was notarised |
| gpg | a `VALIDSIG` status line from the pinned fingerprint |
| minisign | the signature's key id is the pinned one, and `minisign -V` passes with the profile's public key |
| ssh | the key inside the signature has the pinned fingerprint, and `ssh-keygen -Y verify` passes against exactly that key |
| cosign | `cosign verify-blob` with the profile's public key (key mode), or the pinned identity and issuer (keyless) |

## Output

```json
{"contract":1,"ok":false,"profile":"acme-release",
 "artifacts":[{"path":"build/SHA256SUMS","sha256":"<hex>","platform":"checksums","ok":false,
               "problems":["the file is not the one that was signed"]}]}
```

A passing entry has `"ok": true` and `found`, the pinned identity it matched.
Exit 0 when every entry passes, 4 when one fails, 5 with `--strict` when a
platform cannot be checked on this host. The report is printed in every case.

---

[← Docs index](../../README.md#documentation)
