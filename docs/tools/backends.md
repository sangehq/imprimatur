# Backends

Ten backends implement the signing port, one per platform kind and credential
type. Each runs only allow-listed tools, by absolute path, with no shell.

| Platform | Backend | Host | Tools | Pin verification checks |
| --- | --- | --- | --- | --- |
| windows | `azure-artifact-signing` | Windows | `signtool` with the Artifact Signing dlib | thumbprint and/or exact subject |
| windows | `certum` | Windows | `signtool /sha1 <thumbprint>` | thumbprint and/or exact subject |
| windows | `cert-store` | Windows | `signtool /sha1 <thumbprint>` | thumbprint and/or exact subject |
| windows | `pfx` | any | `osslsigncode` | thumbprint and/or exact subject |
| macos | `developer-id` | macOS | `codesign`; `xcrun notarytool`, `ditto`, `xcrun stapler` with `notary`; `spctl` to verify | team ID and identity |
| checksums | `gpg` | any | `gpg` | key fingerprint |
| checksums | `minisign` | any | `minisign` | key id |
| checksums | `ssh` | any | `ssh-keygen -Y` | key fingerprint (`SHA256:...`) |
| containers | `cosign` key / keyless | any | `cosign sign-blob`, `verify-blob` | public-key sha256 / identity and issuer |
| attestations | `in-toto` | none | none | not implemented: reported unavailable |

## Authenticode

- Signs with SHA-256 and an RFC 3161 timestamp, trying the profile's
  `timestamp` or, when it names none, each default server in turn
  (cert-store: DigiCert, Sectigo, GlobalSign; Certum: Certum, DigiCert; Azure:
  Microsoft's; pfx: DigiCert, Sectigo).
- `cert-store` and `certum` sign only with a pinned `thumbprint`; a profile
  pinned by subject alone is refused before signtool runs, because
  `signtool /n` picks any certificate whose name matches.
- `azure-artifact-signing` needs `dlibPath` and `metadataPath`; the metadata
  must have `Endpoint` (`https://<region>.codesigning.azure.net`),
  `CodeSigningAccountName` and `CertificateProfileName`.
- `pfx` reads the `.pfx` from `certRef` (a path or base64 content) and its
  password from `passwordRef`, handed to osslsigncode in a file, never on a
  command line.
- After signing, and on verify, the signer is read from the file's own PKCS#7
  signature: thumbprint, subject and timestamp. The cryptographic check is
  `signtool verify /pa` on Windows, `osslsigncode verify` elsewhere.

## Developer ID

- `codesign --force --options runtime --timestamp [--entitlements <file>] --sign <identity>`;
  `entitlements` is relative to `--root`. The identity must already be in a
  keychain (on a runner, the sign-macos workflow imports it).
- With `notary`, the signed files are zipped with `ditto` and submitted once
  with `xcrun notarytool submit --wait`, using the `.p8` key from `apiKeyRef`
  and `keyId` and `issuer` (literal or `env://`). `.dmg` and `.pkg` files are
  stapled; a bare Mach-O cannot carry a ticket and is not.

## Checksums and cosign

- **gpg**: `keyRef` must be `gpg-agent://<the pinned fingerprint>`; impr signs
  with `--local-user` set to that fingerprint.
- **minisign**: `keyRef` names the secret key, which must be unencrypted
  (`minisign -G -W`), since a CI run has no terminal for a password;
  `publicKey` is the base64 line of `minisign.pub` and its key id must be the
  pinned `fingerprint`.
- **ssh**: `keyRef` names the private key; its fingerprint must be the pinned
  one before anything is signed. `namespace` defaults to `file`.
- **cosign**: key mode needs `publicKey` (a PEM file) whose sha256 is the pinned
  `keyFingerprint`; an `env://` `keyRef` is passed to cosign as is, and
  `passwordRef` becomes `COSIGN_PASSWORD`. Keyless mode pins `identity` and
  `issuer`. cosign signs the checksum file, not container images.

---

[← Docs index](../../README.md#documentation)
