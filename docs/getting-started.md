# Getting started

From nothing to a signed, verified build manifest, using an SSH key: the one
backend every host has.

## 1. Check what this host can do

```bash
impr companion info
```

It lists, per platform kind, whether this host can sign. On a Mac with no extra
tools that is `macos` (codesign) and `checksums` (ssh-keygen).

## 2. Add a profile

A profile names who signs, for what, and the identity verification must find.
Make a throwaway key and pin its fingerprint:

```bash
ssh-keygen -t ed25519 -N '' -f ~/.ssh/impr_test
ssh-keygen -l -E sha256 -f ~/.ssh/impr_test        # prints SHA256:...
impr profile add me-test --scope personal --owner me --purpose test \
  --set platforms.checksums.kind=ssh \
  --set platforms.checksums.keyRef=env://IMPR_SSH_KEY \
  --set platforms.checksums.fingerprint=SHA256:<printed above>
```

The first profile you add becomes the default. `keyRef` is a reference: the
variable holds the key's path (or the key itself), and nothing secret is
written to the profile. `impr profile validate me-test` lists anything missing.

## 3. Sign a build manifest

impr signs only the files a `sange.build-manifest/v1` lists, bound to a commit
and tree. A minimal one:

```json
{
  "schema": "sange.build-manifest/v1",
  "commit": "<commit sha>", "tree": "<tree id>", "version": "v0.1.0",
  "artifacts": [ { "path": "build/linux/tool_linux_amd64", "sha256": "<hex>", "size": 123 } ]
}
```

```bash
export IMPR_SSH_KEY=~/.ssh/impr_test
impr sign --manifest build/build-manifest.json --commit <sha> --tree <tree> \
  --profile me-test --purpose test --json --strict
```

impr checks every file's digest first and signs nothing if one differs. With
an SSH profile it writes `build/SHA256SUMS` and `build/SHA256SUMS.sig`, then
`build/impr-manifest.json`: the record of what was signed, by which pinned
identity, with each file's digest before and after
([sign](tools/sign.md)).

## 4. Verify

```bash
impr verify --signed build/impr-manifest.json --manifest build/build-manifest.json \
  --profile me-test --json --strict
```

Exit 0 means every file is the one that was signed and carries a signature by
exactly the pinned key. Change a byte of `SHA256SUMS` and it exits 4
([verify](tools/verify.md)).

## Next

- A release profile needs `--purpose release`, `allowedRepos`, and `--repo` on
  every sign: [profile](tools/profile.md).
- Windows and macOS binaries: [backends](tools/backends.md),
  [macOS notarisation](recipes/macos-notarization.md).
- Coming from the PowerShell imprimatur: [migration](recipes/migrate-from-powershell.md).

---

[← Docs index](../README.md#documentation)
