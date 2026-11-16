# Sign checksums with a GPG key

Sign each build's checksum file with a GPG key held by gpg-agent, pinned by its full fingerprint.

```bash
fpr=$(gpg --with-colons --list-secret-keys release@example.com | awk -F: '/^fpr/ {print $10; exit}')
impr profile add me-release --scope personal --owner me --purpose release \
  --allowed-repo 'github.com/me/**' \
  --set platforms.checksums.kind=gpg \
  --set "platforms.checksums.keyRef=gpg-agent://$fpr" \
  --set "platforms.checksums.fingerprint=$fpr"
impr sign --manifest build/build-manifest.json --commit "$sha" --tree "$tree" \
  --profile me-release --purpose release --repo git@github.com:me/tool.git --platforms checksums --strict
```

The run writes `build/SHA256SUMS.sig`. Anyone with the public key checks it with
`gpg --verify build/SHA256SUMS.sig build/SHA256SUMS`.

- **Full fingerprint.** The pin must be the full 40- or 64-hex fingerprint. impr refuses a short id
  unless `policy.gpgFullFingerprint` is `false`.
- **A key held in a secret.** In CI, where there is no gpg-agent, `keyRef` can be a `secret://` or
  `env://` reference to the armored secret key, with `passwordRef` for its passphrase. impr imports it
  into a throwaway gpg home for the one run.

Details: [backends](../tools/backends.md#checksums-and-cosign).

---

[← Docs index](../../README.md#documentation)
