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

## Test and release profiles

A profile signs for its purposes only, and a test profile never signs a release, so keep two: the
release profile above and a test profile for internal and test builds. Each can point at its own
certificate (a Certum test certificate, or a throwaway one from [`impr cert create`](../tools/cert.md)
in the `cert-store` or `pfx` backend), or both at the same Certum certificate:

```powershell
impr profile add acme-test --scope company --owner acme --purpose test `
  --set platforms.windows.kind=authenticode `
  --set platforms.windows.backend=certum `
  --set platforms.windows.thumbprint=3F2504E04F8911D39A0C0305E82C3301AB12CD34 `
  --set platforms.windows.notAfter=2027-01-01T00:00:00Z
```

## Check the setup, then sign

`impr sign --dry-run` runs every check a real run makes (the build manifest, the commit and repository,
the profile, SimplySign's certificate in the store, its expiry) and prints the `signtool` command it would
run, without signing anything or writing a record. It exits 5 and names each problem when a real run
would stop.

```powershell
impr sign --dry-run --manifest build\build-manifest.json --commit $commit --tree $tree `
  --profile acme-release --purpose release --repo git@github.com:acme/tool.git --platforms windows
```

The real run, once SimplySign Desktop is signed in and the dry run is ready:

1. Sign in to SimplySign Desktop; `Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert` lists the certificate.
2. Run the same command without `--dry-run`, then `impr verify --signed build\impr-manifest.json --profile acme-release --strict`.
3. Check one file by hand: `signtool verify /pa /v build\windows\tool_windows_amd64.exe`.

Details: [backends](../tools/backends.md#authenticode).

---

[← Docs index](../../README.md#documentation)
