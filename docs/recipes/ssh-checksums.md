# Sign checksums with an SSH key

Sign the checksum file of every build with an SSH key: the backend that works
on every host.

```bash
ssh-keygen -t ed25519 -N '' -C release -f ~/.ssh/release_ed25519
fp=$(ssh-keygen -l -E sha256 -f ~/.ssh/release_ed25519 | awk '{print $2}')
impr profile add me-release --scope personal --owner me --purpose release \
  --allowed-repo 'github.com/me/**' \
  --set platforms.checksums.kind=ssh \
  --set platforms.checksums.keyRef=env://RELEASE_SSH_KEY \
  --set "platforms.checksums.fingerprint=$fp"
export RELEASE_SSH_KEY=~/.ssh/release_ed25519
impr sign --manifest build/build-manifest.json --commit "$sha" --tree "$tree" \
  --profile me-release --purpose release --repo git@github.com:me/tool.git --platforms checksums --json --strict
```

The run writes `build/SHA256SUMS`, `build/SHA256SUMS.sig` and
`build/impr-manifest.json`. Anyone can check the signature with OpenSSH alone,
given the public key:

```bash
echo "release $(cat ~/.ssh/release_ed25519.pub)" > allowed_signers
ssh-keygen -Y verify -f allowed_signers -I release -n file -s build/SHA256SUMS.sig < build/SHA256SUMS
```

In CI, put the private key in a secret and point `keyRef` at the variable
holding it: impr writes it to an owner-only temporary file for the one call and
removes it. Details: [backends](../tools/backends.md).

---

[← Docs index](../../README.md#documentation)
