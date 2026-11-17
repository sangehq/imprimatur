# Deploy allow rules for a signed release

Allow exactly your signed Windows binaries on managed machines, with an AppLocker policy and a WDAC
supplemental policy built from the signed files themselves.

```bash
impr rules build/windows/tool.exe build/windows/core.dll --scope version --product "Acme Tool" \
  --file-version 1.2.0.0 --base-policy {6b2a1c3d-0000-4000-8000-00000000abcd} \
  --include-default-rules --out-dir policies
```

impr writes `policies/applocker.xml` and, with `--base-policy`, `policies/wdac-supplemental.xml`. Check the
AppLocker policy against the files before deploying it (on Windows):

```powershell
impr rules test --policy policies\applocker.xml build\windows\tool.exe build\windows\core.dll
```

On a test machine, in audit mode first (the default).

**AppLocker.** Windows 10 2004 and later, and every Windows 11, enforce AppLocker on any edition, Pro
included (KB5024351). The Application Identity service (AppIDSvc) must run:

```powershell
Set-AppLockerPolicy -XmlPolicy policies\applocker.xml -Merge
Start-Service AppIDSvc
Get-AppLockerFileInformation -Path build\windows\tool.exe     # the publisher Windows reads
```

To start AppIDSvc at every boot, set Application Identity to Automatic in Group Policy (Computer
Configuration > Windows Settings > Security Settings > System Services). `sc.exe config AppIDSvc` is
refused on Windows 10 and later, where the service is protected. Events: Event Viewer > Applications and
Services Logs > Microsoft > Windows > AppLocker > EXE and DLL (8002 allowed, 8003 would have been blocked,
8004 blocked).

**WDAC (App Control for Business).** The base policy (`--base-policy`) must have the option
`Enabled:Allow Supplemental Policies`. Compile the supplemental policy and deploy it:

```powershell
ConvertFrom-CIPolicy -XmlFilePath policies\wdac-supplemental.xml -BinaryFilePath policies\wdac-supplemental.cip
CiTool --update-policy policies\wdac-supplemental.cip      # Windows 11 22H2+, Windows Server 2025
CiTool --list-policies
```

On older Windows (no CiTool), copy the `.cip` to
`%SystemRoot%\System32\CodeIntegrity\CiPolicies\Active\{<its PolicyID>}.cip`, then run RefreshPolicy.exe or
reboot. Events: Event Viewer > Applications and Services Logs > Microsoft > Windows > CodeIntegrity >
Operational (3076 would have been blocked, 3077 blocked).

- **Audit, then enforce.** AppLocker collections are AuditOnly unless you pass `--enforce`. The WDAC
  supplemental policy has no mode of its own: it audits or enforces as its base policy does, so
  `--enforce` does not change it (impr says so). Check the event log for what would have been blocked
  before you enforce.
- **Redeploying.** The WDAC `PolicyID` comes from the base policy, publisher, product and `--name`, so
  every build of one product gets the same one, and deploying a new build replaces the supplemental
  policy instead of adding another.
- **Default rules.** `--include-default-rules` keeps Windows and Program Files running once you enforce;
  leave it out only when the machine's existing policy already has them.
- **Artifact Signing rotates its issuing CAs.** The rules pin the certificate below the root and your
  certificate profile's EKU, which outlive the issuing CAs. Give `impr rules` builds signed on different
  days: those under one PCA make one set of rules, and a build under another PCA is refused.
- **Supplemental only.** impr writes a WDAC supplemental policy for your existing base policy
  (`--base-policy`), never a base policy of its own.
- **Scope.** `version` allows these binaries from this version on; `file` allows them at any version;
  `product` allows any file of the product; `publisher` allows anything the publisher signs.

Details: [`impr rules`](../tools/rules.md).

---

[← Docs index](../../README.md#documentation)
