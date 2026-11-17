# `impr cert`

Lists every certificate or key the profiles use, with whether this host has it
and when it expires, where that can be read.

```bash
impr cert list [--json]
impr cert show [--json]          # cert list, plus how to trust a test certificate impr made
```

```json
{"contract":1,"certificates":[
  {"profile":"acme-release","platform":"macos","subject":"Developer ID Application: Acme Ltd (ABCDE12345)",
   "teamId":"ABCDE12345","notAfter":"2031-02-01T00:00:00Z","present":true,"source":"keychain"},
  {"profile":"acme-release","platform":"checksums","fingerprint":"SHA256:...","present":true,"source":"file"}]}
```

| Platform | How it is read | `source` |
| --- | --- | --- |
| Windows, cert-store and Certum | on Windows, `certutil -user -verifystore My <thumbprint>` says whether it is present; expiry is the declared `notAfter` | `store`, else `declared` or `unknown` |
| Windows, Azure Artifact Signing | present when the dlib and metadata files exist; expiry declared | `declared` |
| Windows, pfx | present when its reference resolves to a file or base64 content; expiry declared | `file` |
| macOS | `security find-certificate -a -c <identity> -p`: an exact common-name match, the latest expiry of several | `keychain` |
| gpg | `gpg --list-secret-keys <fingerprint>`, the expiry field | `gpg` |
| minisign | present when the key reference resolves | `file` |
| ssh | present when the key reference resolves to a key with the pinned fingerprint | `file` |
| cosign | key: the reference resolves; keyless: always present (certificates are issued per run) | `file`, `declared` |

`impr sign` refuses an expired certificate (exit 3), and a `store`, `keychain`,
`gpg` or `file` entry that is not present (exit 5), before signing anything.
sange raises its expiry triage items from this list.

## Windows store expiry

`cert show` prints what `cert list` prints (its `--json` is the same document) and, for each test
certificate `impr cert create` made, the `certutil` lines that trust it on a Windows test machine. It
prints them only when the `.cer` beside the key is the certificate the profile pins by thumbprint;
otherwise it says the file does not match.

For a `cert-store` or `certum` certificate on Windows, `cert list` asks `certutil` to export the pinned
certificate and reads its real expiry from the exported file. A declared `notAfter` is used only when the
store cannot be read.

## Create a test certificate

```bash
impr cert create                          # profile test-signer, valid 365 days
impr cert create --name ci-test --subject "CN=Acme CI test" --days 90 --json
```

- **What it makes.** A self-signed RSA 3072 code-signing certificate.
- **Where the files go.** `<config>/test-certs/`:
  - `<name>.pem` holds the certificate and its private key, owner-only (0600).
  - `<name>.cer` is the public certificate.
- **The profile.** A profile of the same name, scope `personal` and purpose `test`. It uses the `pfx`
  backend with `certRef: file://…/<name>.pem` and the certificate's thumbprint pinned. It signs through
  osslsigncode on any host, and can never sign a release.
- **Trusting it on a Windows test machine.**

  ```powershell
  certutil -user -addstore Root C:\path\to\test-signer.cer
  certutil -user -addstore TrustedPublisher C:\path\to\test-signer.cer
  ```

  Undo it with `certutil -user -delstore Root <thumbprint>`, and the same for `TrustedPublisher`.
- **No overwriting.** An existing profile of the same name is never overwritten.

---

[← Docs index](../../README.md#documentation)
