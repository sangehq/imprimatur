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

## Signing off a Mac

From Windows or Linux, as the PowerShell line's GoReleaser template did, impr signs and notarises macOS
binaries itself (design ID-36). The identity comes as a `.p12`, and notarisation uses the App Store Connect
key (a keychain profile exists only on a Mac):

```bash
impr profile edit acme-mac \
  --set platforms.macos.certRef=env://MACOS_SIGN_P12 \
  --set platforms.macos.passwordRef=env://MACOS_SIGN_PASSWORD
```

- **Signing.** impr signs each Mach-O file in Go with anchore/quill's code-signing packages: the hardened
  runtime, a secure timestamp from `timestamp.apple.com`, and a universal binary slice by slice. The
  `.p12` (a file, or base64 in a variable) and its password are read through impr's references, in memory.
  Before anything is signed, the certificate must be the pinned identity (its common name) and team (its
  first organisational unit), must chain to Apple Root CA through a Developer ID Certification Authority
  (G1 or G2), must carry the code-signing extended key usage, and must be within its validity period. Apple's
  three public certificates are embedded in impr with their SHA-256 fingerprints
  (`src/internal/backend/applecerts/`, copied from anchore/quill v0.7.1, which took them from
  apple.com/certificateauthority), and the `.p12`'s own chain is not trusted: a self-signed certificate, or
  one from any other CA, is refused. The G1 CA expires on 2027-02-01, so a certificate it issued stops
  verifying then; G2 runs to 2031-09-17.
- **Notarising.** impr talks to Apple's notary API itself, with the standard library: an ES256 token made in
  memory from the `.p8` key (`notary.apiKeyRef`, `notary.keyId`, `notary.issuer`), the zip uploaded to the
  S3 bucket Apple names (only Apple's notary bucket, in `us-west-2`, over HTTPS, signed with the session
  credentials Apple returns), and the status polled until Apple accepts or refuses it. Every call has a
  timeout, a capped answer and no redirects; the hosts are `appstoreconnect.apple.com` and the bucket's.
- **What still needs a Mac.** Checking a signature (`impr verify`, which runs `codesign` and `spctl`), and
  stapling a `.dmg` or `.pkg` (refused off a Mac). A bare Mach-O carries no stapled ticket either way;
  Gatekeeper fetches it online.

On a Mac, impr uses `codesign` and `notarytool` as above, whatever the profile holds.

Per-binary entitlements: `--set platforms.macos.entitlements=packaging/tool.entitlements`
(relative to `--root`). Details: [backends](../tools/backends.md).

---

[← Docs index](../../README.md#documentation)
