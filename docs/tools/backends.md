# Backends

Eleven backends implement the signing port, one per platform kind and credential
type. Each runs only allow-listed tools, by absolute path, with no shell.

| Platform | Backend | Host | Tools | Pin verification checks |
| --- | --- | --- | --- | --- |
| windows | `azure-artifact-signing` | Windows | `signtool` with the Artifact Signing dlib | thumbprint and/or exact subject |
| windows | `certum` | Windows | `signtool /sha1 <thumbprint>` | thumbprint and/or exact subject |
| windows | `cert-store` | Windows | `signtool /sha1 <thumbprint>` | thumbprint and/or exact subject |
| windows | `pfx` | any | `osslsigncode` | thumbprint and/or exact subject |
| macos | `developer-id` | macOS; Windows and Linux with a `.p12` (in Go, ID-36) | `codesign`; `xcrun notarytool`, `ditto`, `xcrun stapler` with `notary`; `spctl` to verify. Off a Mac: none (anchore/quill's signing packages and impr's own notary client); verifying needs a Mac | team ID and identity |
| checksums | `gpg` | any | `gpg` | key fingerprint |
| checksums | `minisign` | any | `minisign` | key id |
| checksums | `ssh` | any | `ssh-keygen -Y` | key fingerprint (`SHA256:...`) |
| containers | `cosign` key / keyless | any | `cosign sign-blob`, `verify-blob` | public-key sha256 / identity and issuer |
| attestations | `in-toto` | wherever its signer works | the checksum key's tool, or `cosign` | the signer's pin, the checksum file's entries, and with `--signed` the commit, tree, build manifest digest and repository |

## in-toto attestations

With `attestations` requested, impr writes `SHA256SUMS.intoto.jsonl` beside the checksum file: one DSSE
envelope holding an in-toto Statement v1.

- **Subjects.** Every entry of `SHA256SUMS`, by path and sha256, so the attestation covers the signed
  binaries and every other file the build manifest lists.
- **Predicate.** SLSA provenance v1 (`https://slsa.dev/provenance/v1`). The build type and the builder
  id follow [`events.source`](events.md#event-source):

  | `events.source` | Build type written | Builder id written |
  | --- | --- | --- |
  | `sange.sh` (the default, also when unset) | `https://sange.sh/imprimatur/buildtypes/manifest/v1` | `https://sange.sh/imprimatur` |
  | `simtabi.com` | `https://simtabi.com/sange/imprimatur/buildtypes/manifest/v1` | `https://simtabi.com/sange/imprimatur` |

  `impr verify` accepts both forms of each, whatever the setting, so attestations made before the setting
  existed, and under either value, all verify. Any other build type or builder id is refused. The
  external parameters are the commit, tree and repository, the build manifest's digest is an internal
  parameter, and the source is a resolved dependency (`git+<repo>`, `gitCommit`, `gitTree`).
- **Signature.** The profile's own pinned signer signs DSSE's pre-authentication encoding:
  `platforms.attestations.signer` is `checksums` (the gpg, minisign or ssh key) or `cosign`. An ssh key
  signs in the `in-toto` namespace, so neither signature can stand in for the other.
- **Verifying.** `impr verify --signed` checks the envelope against the pinned signer, then checks that
  the statement names exactly the checksum file's entries and exactly the signed commit and tree, and
  re-hashes every listed file.

```json
"attestations": {"kind": "in-toto", "signer": "checksums"}
```

## Authenticode

- Signs with SHA-256 and an RFC 3161 timestamp, trying the profile's
  `timestamp` servers in order (one URL, or several separated by commas:
  `--set "platforms.windows.timestamp=http://ts.a,http://ts.b"`) or, when it
  names none, each default server in turn
  (cert-store: DigiCert, Sectigo, GlobalSign; Certum: Certum, DigiCert; Azure:
  Microsoft's; pfx: DigiCert, Sectigo).
- `cert-store` and `certum` sign only with a pinned `thumbprint`; a profile
  pinned by subject alone is refused before signtool runs, because
  `signtool /n` picks any certificate whose name matches.
- `azure-artifact-signing` needs `dlibPath` and `metadataPath`, and `impr profile validate` reports a
  profile missing either (`platforms.windows.dlibPath`, `…metadataPath`); the metadata
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
  with `xcrun notarytool submit --wait`. The credentials are either
  `keychainProfile`, a name notarytool stored in the login keychain
  (`xcrun notarytool store-credentials NAME`), so impr never handles the key,
  or the `.p8` key from `apiKeyRef` with `keyId` and `issuer` (literal or
  `env://`), written 0600 in a private folder for the one notarytool call (it
  takes the key only as a file: it refuses a pipe). Name one, not both. `.dmg`
  and `.pkg` files are stapled; a bare Mach-O cannot carry a ticket and is not.

## Artifact Signing sign-in

Before an `azure-artifact-signing` run, impr checks the Azure CLI is signed in with `az account show`.
It does this only when the CLI is the credential: `az` is installed and no service-principal or
managed-identity variables (`AZURE_CLIENT_ID`, `AZURE_FEDERATED_TOKEN_FILE`, `IDENTITY_ENDPOINT`,
`MSI_ENDPOINT`) are set. If not signed in, the run stops before anything is signed, with the fix
`az login`.

## A certificate and key in one PEM file

The `pfx` backend also accepts a PEM bundle, which is what `impr cert create` writes: a certificate and
its private key in one file, referenced as `file://<absolute path>` and readable by its owner only. impr
splits it into owner-only temporary files and runs `osslsigncode sign -certs … -key …`.

## Keys that are not in a keyring

- **gpg.** `keyRef` may be `secret://` or `env://` holding the armored secret key, instead of
  `gpg-agent://<fingerprint>`. impr imports the key into a fresh 0700 gpg home for one run and checks it
  is the pinned key. It signs, with `passwordRef` passed through a file and loopback pinentry, then
  deletes the home, so your own keyring is never touched. Set `publicKey` to the armored public key so
  `impr verify` checks against it rather than your keyring.
- **Developer ID.** `certRef` may hold a `.p12` (a path, or base64 in a CI secret), with `passwordRef`.
  impr creates a keychain in a private temporary folder with a random password, imports the `.p12` there
  for `/usr/bin/codesign`, signs with `codesign --keychain`, and deletes the keychain afterwards, even
  when a step fails. The keychain is never added to your search list.
- **The `.p12` password stays off command lines.** `security import` takes a password only as an
  argument, which other processes run by the same user can see. So impr first re-wraps the `.p12` with
  `openssl pkcs12`: openssl reads the real password from an environment variable, and writes a new
  `.p12` under a random one-time password, with the PBE-SHA1-3DES encryption and SHA-1 MAC that
  `security import` accepts. Only that one-time password reaches `security import`, and it opens
  nothing but this run's temporary keychain. The decrypted key exists for a moment in an owner-only
  temporary folder and is removed straight after. A `.p12` that OpenSSL 3 can open only with its legacy
  provider is retried with `-legacy`. Both the system openssl (LibreSSL) and OpenSSL 3 work.

## Checksums and cosign

- **gpg**: `keyRef` is `gpg-agent://<the pinned fingerprint>` for a key in your
  keyring, signed with `--local-user` set to that fingerprint; or a `secret://`
  or `env://` reference to an armored secret key, which impr imports into a
  throwaway gpg home for the run, with `passwordRef` for its passphrase.
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
