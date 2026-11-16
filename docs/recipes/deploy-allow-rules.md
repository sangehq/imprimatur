# Deploy allow rules for a signed release

Allow exactly your signed Windows binaries on managed machines, with an AppLocker policy and a WDAC
supplemental policy built from the signed files themselves.

```bash
impr rules build/windows/tool.exe build/windows/core.dll --scope version --product "Acme Tool" \
  --file-version 1.2.0.0 --base-policy {6b2a1c3d-0000-4000-8000-00000000abcd} --out-dir policies
```

On a test machine, in audit mode first (the default):

```powershell
Set-AppLockerPolicy -XmlPolicy policies\applocker.xml -Merge
ConvertFrom-CIPolicy -XmlFilePath policies\wdac.xml -BinaryFilePath policies\wdac.cip
CiTool --update-policy policies\wdac.cip
```

- **Audit, then enforce.** Policies are AuditOnly unless you pass `--enforce`. Check the event log for
  what would have been blocked before you enforce.
- **Supplemental only.** impr writes a WDAC supplemental policy for your existing base policy
  (`--base-policy`), never a base policy of its own.
- **Scope.** `version` allows this product from this version on; `product` allows any version; `publisher`
  allows anything the publisher signs.

Details: [`impr rules`](../tools/rules.md).

---

[← Docs index](../../README.md#documentation)
