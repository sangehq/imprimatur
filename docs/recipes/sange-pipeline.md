# Use impr from sange's pipeline

The calls sange's signing stage makes, in order, and what each must return.

```bash
impr companion info --json
impr profile show acme-release --json
impr cert list --json
impr sign --json --strict --root "$ROOT" --manifest "$ROOT/build/build-manifest.json" \
  --commit "$SHA" --tree "$TREE" --profile acme-release --purpose release \
  --platforms windows,macos,checksums --repo git@github.com:acme/tool.git
impr verify --json --strict --root "$ROOT" --manifest "$ROOT/build/build-manifest.json" \
  --signed "$ROOT/build/impr-manifest.json" --profile acme-release
impr rules --json --strict --request rules-request.json      # SIG-03, when info reports "rules"
```

- `companion info` must report contract 1 and list `companion info`,
  `profile list`, `profile show`, `cert list`, `sign` and `verify`, or sange
  treats imprimatur as absent ([companion](../tools/companion.md)).
- sange recomputes the pinned identity's digest from `manifest.identity` and
  compares it with the one its approval bound, so swapping or re-pinning the
  profile after approval is caught.
- sange accepts only the build manifest's files in `artifacts`, each signed from
  its listed digest, and only `SHA256SUMS`, `checksums.txt` and `.sig`,
  `.asc`, `.minisig`, `.sigstore.json` files in `outputs`.
- impr does not enforce `requiresApproval`; sange does (APR-11).

> sange runs this binary once it is pinned by absolute path and SHA-256 with
> `sange release signing tools pin impr <absolute path>` (a typed `pin impr`
> confirmation). It asks `impr companion info --json` for contract 1 before any
> other call, and refuses a binary whose hash changed rather than falling back.
> With no binary pinned, sange still starts the deprecated PowerShell toolkit.
> The pin command ships in sange's Phase 9 build.

---

[← Docs index](../../README.md#documentation)
