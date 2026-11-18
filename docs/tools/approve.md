# `impr approve`

Signs an approval for one signing run, so a profile with `requiresApproval` needs a second person
before it signs a release.

```bash
impr approve --manifest FILE --profile NAME --purpose release|test|internal --approver NAME --key SSH-KEY
             [--expires 24h] [--out FILE] [--json]
```

| Option | Meaning |
| --- | --- |
| `--manifest` | the build manifest to approve. Its commit, tree and digest go into the approval. Required |
| `--profile`, `--purpose` | the run being approved. Required |
| `--approver` | the approver's name, as listed in `approvals.approvers`. Required |
| `--key` | the approver's SSH private key, or a public key whose private half is in ssh-agent. Required |
| `--expires` | how long the approval is valid; default `24h`, at most `168h` |
| `--out` | where to write it; default `impr-approval-<approver>.json` beside the build manifest |

The approver runs it on their own machine, with their own key. It writes the approval and its
signature, `FILE.sig`, which the person signing passes on:

```bash
impr sign --manifest build/build-manifest.json --commit "$C" --tree "$T" --profile acme-release \
  --purpose release --repo git@github.com:acme/tool.git --approval build/impr-approval-alice.json
```

## Turning it on

sange enforces approval itself (APR-11) before it calls `impr sign`, so impr enforces a profile's
`requiresApproval` only when the config says so. Where impr is the gate (standalone use, CI or the
REST API), an administrator turns it on in the system config and locks it, so a signer cannot add
their own key or switch it off:

```json
{
  "locked": ["approvals"],
  "approvals": {
    "enforce": true,
    "required": 1,
    "approvers": [{"name": "alice", "publicKey": "ssh-ed25519 AAAA..."}]
  }
}
```

A repository can require approval for its own releases with `"requireApproval": true` in
[`.imprimatur/project.json`](project.md). That applies whatever `approvals.enforce` says.

## Modes

A profile's `approval` field chooses how a run is approved:

| `approval` | How |
| --- | --- |
| `signed` (default) | `approvals.required` valid approvals from distinct approvers (distinct keys: one key listed under two names is a configuration problem), passed with `--approval` |
| `confirm` | the person signing types the commit's first 12 characters at a terminal |

`confirm` needs a person at a terminal. A piped run, CI (`CI` set) and the REST API refuse it, and
nothing they run can answer the prompt.

## What is checked

An approval counts only when all of these hold:

- **Signature.** It verifies with the approver's configured key, in the `imprimatur-approval`
  namespace, so no other SSH signature from that key can pass for one.
- **Binding.** Its profile, purpose, commit, tree and build manifest digest are exactly the run's.
- **Time.** It has not expired and was not issued in the future (5 minutes of clock skew allowed).
- **Approvers.** Each approver counts once, however many approvals they sign.

Anything else refuses the run before anything is signed (exit 3), naming each approval and why it
failed. The signed record, `impr-manifest.json`, lists the approvals under `approvals`: each one's
mode, approver and the sha256 of the approval document.

Building with `impr release` and approving cannot be one step, because the approval binds the build
manifest's digest. Build with `impr build`, have the approver run `impr approve`, then run
`impr sign --approval`.

---

[← Docs index](../../README.md#documentation)
