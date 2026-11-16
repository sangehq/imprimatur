# Sign Windows binaries with a Certum certificate

Sign `.exe` and `.dll` files with a Certum code-signing certificate held in the Windows certificate store
(SimplySign or a smart card), pinned by its thumbprint.

```powershell
Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Format-List Subject, Thumbprint, NotAfter
impr profile add acme-release --scope company --owner acme --purpose release `
  --allowed-repo 'github.com/acme/**' `
  --set platforms.windows.kind=authenticode `
  --set platforms.windows.backend=certum `
  --set platforms.windows.thumbprint=3F2504E04F8911D39A0C0305E82C3301AB12CD34 `
  --set platforms.windows.notAfter=2027-01-01T00:00:00Z
impr cert list
```

- **Thumbprint, always.** `certum` and `cert-store` sign only with a pinned thumbprint, because
  `signtool /n` would pick any certificate whose name matches.
- **Expiry.** `impr cert list` reads the real expiry from the store, and raises `cert.expiring` at 30,
  14 and 7 days ([notify](../tools/notify.md)).
- **Renewal.** List the old and new certificates as `signers` with `notBefore` dates, so the new one
  takes over on the day ([profile](../tools/profile.md#several-certificates)).

Details: [backends](../tools/backends.md#authenticode).

---

[← Docs index](../../README.md#documentation)
