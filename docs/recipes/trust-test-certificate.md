# Trust a test certificate on a Windows test machine

Sign test builds with a throwaway certificate, and trust it on the machines that run them.

```bash
impr cert create --name ci-test --subject "CN=Acme CI test" --days 90
impr sign dist/tool.exe --profile ci-test --purpose test --root .
```

Copy `ci-test.cer` from `<config>/test-certs/` to the test machine, then:

```powershell
certutil -user -addstore Root C:\path\to\ci-test.cer
certutil -user -addstore TrustedPublisher C:\path\to\ci-test.cer
```

Undo it with `certutil -user -delstore Root <thumbprint>` and the same for `TrustedPublisher`.

- **Test only.** The profile's purpose is `test`, so it can never sign a release.
- **The private key stays put.** Only the `.cer` (the public certificate) leaves your machine.

Details: [`impr cert`](../tools/cert.md#create-a-test-certificate).

---

[← Docs index](../../README.md#documentation)
