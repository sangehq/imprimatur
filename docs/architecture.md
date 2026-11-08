# Architecture

impr is one Go binary built around a signing-profile domain, one backend port
with a backend per platform kind, and a single adapter that is the only code
allowed to start another program.

## Layout

```text
src/cmd/impr/          thin entrypoint: calls internal/cli
src/internal/cli/      the command line: a stdlib flag parser, the commands, the contract output
src/internal/contract/ exit codes 0-5, the error type and the error document
src/internal/profile/  the profile model, validation, pinned identity, storage, legacy import
src/internal/backend/  the port and its backends (authenticode, apple, gpg, minisign, ssh, cosign)
src/internal/signing/  signing and verifying a build manifest; certificates; capability reports
src/internal/rules/    AppLocker and WDAC supplemental policies from a request
src/internal/artifact/ the build manifest, safe path resolution, digests, file kinds
src/internal/secrets/  credential references to values, temporary files for tools
src/internal/execx/    the allow-listed exec adapter (the only importer of os/exec)
src/internal/paths/    XDG and Windows config and state directories
src/internal/guardtest/ repository guards: exec, workflows, build layout, docs, community files
```

The module has no dependency outside the Go standard library.

## The backend port

```go
type Backend interface {
    Capability(h Host) Capability                                // can this host sign and verify?
    Certificate(ctx context.Context, p profile.Profile) CertEntry // the pinned certificate or key, as far as this host can read it
    Sign(ctx context.Context, a Artifact, p profile.Profile) (Signature, error)
    Verify(ctx context.Context, a Artifact, p profile.Profile) error
}
```

A backend may also implement `Preflight`, which refuses before anything is
signed (an Authenticode certificate pinned by subject only, a key reference of
the wrong shape, a minisign or cosign public key that is not the pinned one).
[Backends](tools/backends.md) lists each one.

## A signing run

`impr sign` checks everything before it changes a byte: the build manifest's
commit and tree, the profile's validity, the purpose (a test profile never
signs a release), `--repo` against `allowedRepos`, every file's sha256, the
host's capability for every platform with work, each backend's preflight, and
every certificate's presence and expiry. Then it signs Windows binaries, then
macOS binaries (and notarises them in one submission), then writes
`SHA256SUMS` over the post-sign digests and signs it with the checksum and
cosign backends, and finally writes `impr-manifest.json`. A failure after
signing has started stops the run with an error; files already signed in
place stay signed, and their build digests no longer match, so the build is
rebuilt rather than resumed.

## Why

- **Why a profile, not a settings file?** The PowerShell line picked a
  certificate from one settings file, fell back to a test certificate when
  nothing was set, and chose "the first certificate whose subject matches".
  A profile names one identity and pins it; impr signs with it or refuses.
- **Why a build manifest?** imprimatur is not a signing oracle: it signs the
  files a build stage produced, bound to a commit and tree, and records the
  digest of each before and after (SD-075, SD-098).
- **Why one exec adapter?** Every tool impr can start is on one allow-list,
  resolved to an absolute path and run with no shell; a guard test fails if any
  other package imports `os/exec`, and another pins the list itself.
- **Why read Authenticode signers in Go?** The pin (thumbprint, subject,
  timestamp) is read from the PE's own PKCS#7 signature, so it does not depend
  on parsing a tool's localised output; `signtool verify` or `osslsigncode
  verify` still does the cryptographic check.
- **Why no file-hash allow rules?** Windows matches the Authenticode hash,
  which no build manifest records, so impr renders publisher rules only.

---

[← Docs index](../README.md#documentation)
