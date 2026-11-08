# `impr cert list`

Lists every certificate or key the profiles use, with whether this host has it
and when it expires, where that can be read.

```bash
impr cert list [--json]
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

---

[← Docs index](../../README.md#documentation)
