# Require a second person to approve a release

Make a release profile sign only after someone else has approved that exact build.

In the system config (an administrator, once):

```json
{"locked": ["approvals"],
 "approvals": {"enforce": true, "approvers": [{"name": "alice", "publicKey": "ssh-ed25519 AAAA..."}]}}
```

Then for each release:

```bash
impr profile edit acme-release --set requiresApproval=true          # once
impr build --version v1.2.3                                         # the person releasing
impr approve --manifest build/build-manifest.json --profile acme-release --purpose release \
  --approver alice --key ~/.ssh/id_ed25519                          # alice, on her machine
impr sign --manifest build/build-manifest.json --commit "$sha" --tree "$tree" \
  --profile acme-release --purpose release --repo git@github.com:acme/tool.git \
  --approval build/impr-approval-alice.json                         # the person releasing
```

- **Bound to the build.** An approval names the build manifest's digest, commit and tree, the profile
  and the purpose, and it expires (24 hours by default). It approves nothing else.
- **Under sange.** sange enforces approval itself (APR-11), so leave `approvals.enforce` off on hosts
  where sange runs impr.

Details: [`impr approve`](../tools/approve.md).

---

[← Docs index](../../README.md#documentation)
