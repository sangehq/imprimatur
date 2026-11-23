# Sign and notarise for macOS

Sign macOS binaries with a Developer ID, notarise them, and pin the team and
identity verification must find.

1. The owner creates the Developer ID Application certificate and an App Store
   Connect API key. The certificate goes into a keychain (on a runner, the
   sign-macos workflow imports it); the `.p8` key goes into a secret. No agent
   handles either.
2. Add the profile:

   ```bash
   impr profile add acme-mac --scope company --owner acme --purpose release \
     --allowed-repo 'github.com/acme/**' --requires-approval \
     --set platforms.macos.kind=developer-id \
     --set platforms.macos.teamId=ABCDE12345 \
     --set 'platforms.macos.identity=Developer ID Application: Acme Ltd (ABCDE12345)' \
     --set platforms.macos.notary.apiKeyRef=env://ASC_API_KEY \
     --set platforms.macos.notary.keyId=env://ASC_KEY_ID \
     --set platforms.macos.notary.issuer=env://ASC_ISSUER_ID
   impr cert list                      # the certificate must be present and not expired
   ```

   To add the `.p8` key later, without putting it in a CI secret, store it through
   [`impr secret`](../tools/secret.md) or the local [secrets page](../tools/serve.md#the-secrets-page);
   the profile's `apiKeyRef=env://ASC_API_KEY` then reads it from the keychain:

   ```bash
   impr secret set ASC_API_KEY --file ~/Downloads/AuthKey_ABC123.p8
   ```

   On a Mac you sign from, store the notary credentials in the login keychain once
   instead, so impr never handles the `.p8` (the owner runs this, not an agent):

   ```bash
   xcrun notarytool store-credentials acme-notary --key AuthKey_ABC123.p8 --key-id ABC123 --issuer <issuer-id>
   impr profile edit acme-mac --unset platforms.macos.notary \
     --set platforms.macos.notary.keychainProfile=acme-notary
   ```

   CI keeps `apiKeyRef`, from a secret.

3. Sign on a Mac:

   ```bash
   impr sign --manifest build/build-manifest.json --commit "$sha" --tree "$tree" \
     --profile acme-mac --purpose release --repo git@github.com:acme/tool.git \
     --platforms macos --json --strict
   ```

impr runs `codesign` with the hardened runtime and a secure timestamp, checks
`TeamIdentifier` and `Authority`, submits every signed file in one zip with
`notarytool submit --wait`, staples `.dmg` and `.pkg` files, and records the
submission id as `notarization` in `impr-manifest.json`. A bare Mach-O binary
cannot carry a stapled ticket; Gatekeeper fetches it online.
`impr verify --signed build/impr-manifest.json --profile acme-mac` adds
`spctl -a -t exec` for notarised files.

Per-binary entitlements: `--set platforms.macos.entitlements=packaging/tool.entitlements`
(relative to `--root`). Details: [backends](../tools/backends.md).

---

[← Docs index](../../README.md#documentation)
