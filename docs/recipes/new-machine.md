# Set up a new machine

Install impr, bring your profiles over, and check what this host can sign.

```bash
impr install                                   # copies impr to ~/.local/bin; edits no PATH
impr profile export me-release --out-file me-release.json     # on the old machine
impr profile import me-release.json            # on the new one
impr profile bundle install acme.json          # your organisation's managed profiles, if any
impr doctor
impr cert list
```

- **Keys stay where they are.** A profile holds references (`env://`, `secret://`, `keychain://`,
  `gpg-agent://`), never key material, so the export carries no secret. Put the keys themselves in
  the new machine's keychain, gpg-agent or secret store.
- **Check before you need it.** `impr doctor` says, per profile and platform, whether this host can
  sign and verify, and why not.
- **Completion.** `impr completion install` adds tab completion for your shell.

Details: [installation](../installation.md), [`impr profile`](../tools/profile.md).

---

[← Docs index](../../README.md#documentation)
