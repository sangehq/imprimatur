# Security policy

imprimatur signs release artifacts and holds the profiles that say which identity may sign them, so a
defect in it can let the wrong key sign, or let a tampered file through as signed. Reports are welcome and
handled privately.

## Reporting a vulnerability

Email **[security@simtabi.com](mailto:security@simtabi.com)**. Do not open a public issue, pull request or
discussion for a suspected vulnerability.

Include what you can of:

- the imprimatur version (`impr version`), the operating system, and the signing backend involved
  (Authenticode, Apple, GPG, minisign, SSH or cosign);
- the steps, profile file and build manifest that reproduce it, with real certificates, keys, passwords
  and tokens removed;
- what an attacker gains, and what they need first (a crafted manifest or artifact, a local account, write
  access to the profile store, a network position);
- any proof of concept.

## What to expect

- An acknowledgement within three working days.
- An assessment, and a fix or mitigation plan, as soon as the issue is understood.
- Credit in the release notes when the fix ships, unless you ask to stay anonymous.

Please give us a reasonable window to ship a fix before disclosing publicly.

## Supported versions

The Go line has not had its first release. Until it does, fixes land on `main` only. After `v0.1.0`,
security fixes go to the latest minor release. The PowerShell 1.8.x line stays in use until the Go line
reaches parity, and receives security fixes until then.

## Scope

In scope:

- the `impr` binary and everything under `src/`;
- the profile store, the legacy settings import, and the `impr-manifest.json` and checksum files it writes;
- how it chooses, pins and checks a signing identity, and the AppLocker and WDAC rules it renders.

Out of scope:

- vulnerabilities in the signing tools it runs (signtool, osslsigncode, codesign, notarytool, gpg,
  minisign, ssh-keygen, cosign) or in a signing service (report those upstream);
- findings that need an already-compromised account on the signing machine or runner.
