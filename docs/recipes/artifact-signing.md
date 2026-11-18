# Sign Windows binaries with Azure Artifact Signing

Sign `.exe` and `.dll` files with Azure Artifact Signing, on a Windows host or runner with the Windows SDK.

```bash
impr profile add acme-release --scope company --owner acme --purpose release \
  --allowed-repo 'github.com/acme/**' \
  --set platforms.windows.kind=authenticode \
  --set platforms.windows.backend=azure-artifact-signing \
  --set "platforms.windows.subject=CN=Acme Ltd, O=Acme Ltd, L=London, C=GB" \
  --set 'platforms.windows.dlibPath=C:\tools\Azure.CodeSigning.Dlib.dll' \
  --set 'platforms.windows.metadataPath=C:\tools\metadata.json'
```

`metadata.json` names the account:

```json
{"Endpoint": "https://weu.codesigning.azure.net", "CodeSigningAccountName": "acme", "CertificateProfileName": "acme-release"}
```

- **Sign-in.** Locally, sign in with `az login` first; impr checks `az account show` and stops before
  signing if you are not signed in. In CI, a service principal or managed identity
  (`AZURE_CLIENT_ID`, `AZURE_FEDERATED_TOKEN_FILE`) needs no `az`.
- **The pin.** Artifact Signing issues short-lived certificates, so pin the exact `subject`, not a
  thumbprint.
- **Allow rules.** [`impr rules`](../tools/rules.md#from-signed-files) pins your certificate profile's own
  EKU and the CA below the root, never the generic Artifact Signing EKU. Keep the certificate profile: a
  new one has a new EKU, and every rule pinned to the old one stops matching. Give `impr rules` builds
  signed on different days if you want to see that they share one CA.
- **Several certificates.** To use Artifact Signing for some files and another certificate for others,
  list `signers` ([profile](../tools/profile.md#several-certificates)).

## Test and release profiles

Artifact Signing has a certificate profile for each kind of trust, and an impr profile names one through
its `metadata.json`. Keep a test profile, pointing at a Public Trust Test certificate profile, beside the
release profile above; a test profile never signs a release.

```bash
impr profile add acme-test --scope company --owner acme --purpose test \
  --set platforms.windows.kind=authenticode \
  --set platforms.windows.backend=azure-artifact-signing \
  --set "platforms.windows.subject=CN=Acme Ltd, O=Acme Ltd, L=London, C=GB" \
  --set 'platforms.windows.dlibPath=C:\tools\Azure.CodeSigning.Dlib.dll' \
  --set 'platforms.windows.metadataPath=C:\tools\metadata-test.json'
```

`metadata-test.json` is the same as `metadata.json` with `"CertificateProfileName": "acme-test"`.

## Check the setup, then sign

`impr sign --dry-run` runs every check a real run makes (the build manifest, the commit and repository,
the profile, the dlib and metadata paths, `az account show`) and prints the `signtool` command it would
run, without signing anything or writing a record. It exits 5 and names each problem when a real run
would stop.

```bash
impr sign --dry-run --manifest build/build-manifest.json --commit "$commit" --tree "$tree" \
  --profile acme-release --purpose release --repo git@github.com:acme/tool.git --platforms windows
```

The real run, once the account and certificate profile exist and the dry run is ready:

1. `az login` (or the CI identity); `az account show` succeeds.
2. Run the same command without `--dry-run`, then `impr verify --signed build/impr-manifest.json --profile acme-release --strict`.
3. Check one file by hand: `signtool verify /pa /v build\windows\tool_windows_amd64.exe`.

Details: [backends](../tools/backends.md#authenticode).

---

[← Docs index](../../README.md#documentation)
