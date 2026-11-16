# Sign checksums with minisign

Sign each build's checksum file with a minisign key, pinned by its key id.

```bash
minisign -G -W -p minisign.pub -s ~/.minisign/release.key   # -W: no password, for CI
pub=$(tail -n 1 minisign.pub)
impr profile add me-release --scope personal --owner me --purpose release \
  --allowed-repo 'github.com/me/**' \
  --set platforms.checksums.kind=minisign \
  --set platforms.checksums.keyRef=env://MINISIGN_KEY \
  --set "platforms.checksums.publicKey=$pub" \
  --set platforms.checksums.fingerprint=<KEY ID>
export MINISIGN_KEY=~/.minisign/release.key
impr sign --manifest build/build-manifest.json --commit "$sha" --tree "$tree" \
  --profile me-release --purpose release --repo git@github.com:me/tool.git --platforms checksums --strict
```

The key id is the 16 hex digits on the first line of `minisign.pub` (`untrusted comment: minisign
public key <KEY ID>`); impr refuses a `publicKey` whose id is not the pinned one. The run writes
`build/SHA256SUMS.minisig`, which anyone checks with `minisign -Vm build/SHA256SUMS -p minisign.pub`.

Details: [backends](../tools/backends.md#checksums-and-cosign).

---

[← Docs index](../../README.md#documentation)
