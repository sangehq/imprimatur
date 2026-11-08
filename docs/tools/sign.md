# `impr sign`

Signs exactly the files a build manifest lists, with one profile's pinned
identity, and writes `impr-manifest.json`, the chain-of-custody record.

```bash
impr sign --manifest FILE --commit SHA --tree ID --profile NAME --purpose release|test|internal
          [--platforms windows,macos,checksums,containers,attestations] [--root DIR] [--repo URL]
          [--json] [--strict]
```

| Option | Meaning |
| --- | --- |
| `--manifest` | a `sange.build-manifest/v1` file. Required |
| `--commit`, `--tree` | must equal the manifest's. Required |
| `--profile` | the profile; without it, the default you chose. Never anything else |
| `--purpose` | required; must be one of the profile's purposes. A test profile never signs `release` |
| `--repo` | the push target, checked against `allowedRepos`. Required for `release` |
| `--platforms` | which of the profile's platforms to sign; default all of them |
| `--root` | the directory manifest paths are relative to; default the current directory |
| `--strict` | a platform this host cannot sign is an error (exit 5), not a skip (exit 2) |

impr refuses files named on the command line: it signs build-manifest entries
only, so it is never a signing oracle.

## What it does

1. Checks, before anything changes: the commit and tree; the profile is valid;
   the purpose and repository; every manifest path stays under `--root`
   (no absolute paths, no `..`, no symlink out) and every file's sha256 matches;
   for every platform with work, the host can sign, the backend's preflight
   passes, and the pinned certificate or key is present and not expired.
2. Signs Windows files (PE, `.msi`) and macOS files (Mach-O, `.dmg`, `.pkg`) in
   place, then notarises the macOS files in one submission when the profile has
   `notary`. Files of other kinds are listed in the checksum file only.
3. With `checksums`, `containers` or `attestations` requested, writes
   `SHA256SUMS` beside the build manifest, over the post-sign digests, and
   signs it: `SHA256SUMS.sig` (gpg, ssh), `SHA256SUMS.minisig` (minisign),
   `SHA256SUMS.sigstore.json` (cosign).
4. Writes `impr-manifest.json` beside the build manifest.

## Output

```json
{
  "contract": 1,
  "ok": true,
  "manifest": {
    "schema": "imprimatur.manifest/v1",
    "signer": "imprimatur v1.8.0",
    "profile": "acme-release",
    "purpose": "release",
    "identity": {"profile":"acme-release","scope":"company","owner":"acme","purpose":["release"],
                 "allowedRepos":["github.com/acme/**"],"checksums":"ssh:SHA256:..."},
    "identityDigest": "sha256:<hex of the identity's canonical JSON>",
    "commit": "<sha>", "tree": "<id>", "repo": "git@github.com:acme/tool.git",
    "buildManifestDigest": "sha256:<hex of the build manifest file's bytes>",
    "artifacts": [{"path":"build/windows/tool.exe","inputSha256":"<hex>","outputSha256":"<hex>",
                   "platform":"windows","kind":"authenticode","signer":"CN=Acme Ltd, O=Acme Ltd, C=GB",
                   "timestamp":"time.certum.pl"}],
    "outputs": [{"path":"build/SHA256SUMS","inputSha256":"","outputSha256":"<hex>","platform":"checksums","kind":"sha256sums","signer":""},
                {"path":"build/SHA256SUMS.sig","inputSha256":"","outputSha256":"<hex>","platform":"checksums","kind":"ssh","signer":"SHA256:..."}],
    "signedAt": "2026-11-07T12:00:00Z"
  },
  "manifestPath": "/abs/build/impr-manifest.json",
  "manifestSha256": "<hex of impr-manifest.json>"
}
```

- Digests of files are lower-case hex; digests of documents are `sha256:<hex>`.
- `identity` is the profile's pinned identity in the canonical form sange
  computes; `identityDigest` is the sha256 of its JSON.
- Paths are relative to `--root` with forward slashes.
- `notarization` (the notarytool submission id) appears on macOS artifacts of a
  notarised run; `skipped` lists platforms skipped without `--strict`.

Exit codes are in [companion](companion.md). A failure after signing has begun
leaves the files signed so far changed in place; rebuild and sign the new
manifest.

---

[← Docs index](../../README.md#documentation)
