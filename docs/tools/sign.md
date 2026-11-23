# `impr sign`

Signs exactly the files a build manifest lists, with one profile's pinned
identity, and writes `impr-manifest.json`, the chain-of-custody record.

```bash
impr sign --manifest FILE --commit SHA --tree ID --profile NAME --purpose release|test|internal
          [--platforms windows,macos,checksums,containers,attestations] [--root DIR] [--repo URL]
          [--json] [--strict] [--approval FILE]...
```

| Option | Meaning |
| --- | --- |
| `--manifest` | a `sange.build-manifest/v1` file. Required |
| `--commit`, `--tree` | must equal the manifest's. Required |
| `--profile` | the profile; without it, the default you chose. Never anything else |
| `--purpose` | required; must be one of the profile's purposes. A test profile never signs `release` |
| `--repo` | the push target, checked against `allowedRepos`. Required for `release`; it must also be one of the checkout's remotes, and `--commit` must be in the checkout with `--tree` as its tree. A release outside a git work tree is refused |
| `--platforms` | which of the profile's platforms to sign; default all of them |
| `--root` | the directory manifest paths are relative to; default the current directory |
| `--strict` | a platform this host cannot sign is an error (exit 5), not a skip (exit 2); a Windows or macOS certificate whose expiry this host cannot read is refused (exit 3), not a warning. Declare it with `platforms.<os>.notAfter`; Artifact Signing is exempt |
| `--dry-run` | run every check and print, per certificate or key, the command it would run; sign nothing, write no record, run no hook. Exit 5 lists what a real run would stop at |
| `--approval` | an approval from [`impr approve`](approve.md), with its `.sig` beside it; repeat for several approvers |

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
   `SHA256SUMS.sigstore.json` (cosign), and `SHA256SUMS.intoto.jsonl` (an in-toto attestation, see
   [backends](backends.md#in-toto-attestations)).
4. Writes `impr-manifest.json` beside the build manifest.

## Loose files

```bash
impr sign dist/tool.tar.gz dist/tool.exe --profile dev --purpose internal --root .
```

- **What impr writes.** For files named on the command line, impr writes `impr-loose-manifest.json` at
  the signing root, listing each file's sha256 and bound to `git rev-parse HEAD` and its tree. It then
  signs that manifest exactly as it signs a build stage's, with every check.
- **Where the files may be.** Every file must be under `--root`.
- **Releases.** A `release` signature needs a git work tree with no uncommitted changes to tracked files,
  so the record names the commit the files came from.
- **Outside git.** Only `test` and `internal` sign, and their record names commit `000…0`, never one that
  does not exist.
- **Not with `--manifest`.** Naming files together with `--manifest`, `--commit` or `--tree` is a usage
  error.

## Output

```json
{
  "contract": 1,
  "ok": true,
  "manifest": {
    "schema": "imprimatur.manifest/v1",
    "signer": "imprimatur v0.1.0",
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
- `uncovered` (in the result and the signed manifest) lists build-manifest files no requested platform
  signs, such as a Linux binary when only `windows` is signed. With `checksums` requested there are none,
  since the checksum file covers every file. It does not change the exit code.

Exit codes are in [companion](companion.md). A failure after signing has begun
leaves the files signed so far changed in place; rebuild and sign the new
manifest.

---

[← Docs index](../../README.md#documentation)
