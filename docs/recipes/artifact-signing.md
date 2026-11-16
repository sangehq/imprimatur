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
- **Several certificates.** To use Artifact Signing for some files and another certificate for others,
  list `signers` ([profile](../tools/profile.md#several-certificates)).

Details: [backends](../tools/backends.md#authenticode).

---

[← Docs index](../../README.md#documentation)
