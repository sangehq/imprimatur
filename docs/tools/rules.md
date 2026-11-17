# `impr rules`

Renders an AppLocker policy and a WDAC supplemental policy that allow exactly
the signed Windows files a request lists.

```bash
impr rules --request FILE [--json] [--strict] [--out-dir DIR]
```

The request is what sange writes from a signed manifest (SD-099); fields impr
does not know are ignored, since shapes only gain fields:

```json
{
  "contract": 1,
  "manifestDigest": "sha256:<hex>", "commit": "<sha>", "version": "v0.1.0", "fileVersion": "0.1.0.0", "scope": "version",
  "publisher": {"subject": "O=ACME LTD, L=LONDON, C=GB", "leafCn": "Acme Ltd", "issuerName": "Acme Issuing CA",
                "issuerTbs": "<hex TBS hash of the CA below the root>", "eku": "1.3.6.1.4.1.311.97.1.0", "product": "tool"},
  "files": [{"path": "build/windows/tool.exe", "sha256": "<hex>", "collection": "Exe", "binaryName": "tool.exe"}],
  "options": {"name": "tool", "enforce": false, "basePolicyId": "{GUID}", "appLocker": true, "wdac": true,
              "userOrGroupSid": "S-1-1-0", "binaryNames": {}}
}
```

`scope` is optional: `publisher`, `product`, `file` or `version`, as under [From signed files](#from-signed-files).
Without it, a request with no `product` gets publisher rules and one with a `product` gets `version` rules
(`file` when `fileVersion` is empty), which is what every request before `scope` existed meant.

## From signed files

```bash
impr rules build/windows/tool.exe build/windows/core.dll --scope version --product "Acme Tool" \
  --file-version 1.2.0.0 --base-policy {6b2a1c3d-0000-4000-8000-00000000abcd} --out-dir policies
```

- **What it reads.** Instead of a `--request`, impr reads each named `.exe` or `.dll`'s Authenticode
  signature. It takes the publisher's subject and the leaf's common name. It also takes the issuing CA,
  pinned by its TBS hash, computed with the same hash as the CA certificate's own signature.
- **One publisher.** Every file must share one publisher and issuing CA, which is one set of rules.
- **Scopes.** The same four as the PowerShell toolkit; none is a hash rule.
  - `publisher` allows anything that publisher signs.
  - `product` (the default) allows any file of the named product, any version (AppLocker
    `ProductName=PRODUCT BinaryName=*`; WDAC `ProductName`).
  - `file` allows the named product's listed binaries, any version (`BinaryName=TOOL.EXE`, low `0.0.0.0`;
    WDAC `FileName`).
  - `version` is `file` at `--file-version` or newer.

  Before 2026-11-17 `product` wrote what `file` writes now, and `file` was refused.
- **WDAC needs a base policy.** A WDAC supplemental policy is rendered only with `--base-policy`, the base
  policy's `{GUID}`. Without one, the output is AppLocker only, and impr says so.
- **Product name.** Without `--product`, impr reads the ProductName from the files' own version information
  (which `impr build` embeds), and every file must name the same product. `--product` overrides it, and a
  file with no ProductName needs it.
- **Default rules.** `--include-default-rules` (or `"includeDefaultRules": true` in a request) adds
  AppLocker's standard default rules to each collection: Program Files and the Windows folder for
  everyone, and everything for Administrators. Without them, enforcing a collection also blocks Windows
  itself, so add them unless the machine already has them. The Windows folder rule also allows the
  user-writable folders under it, such as `Windows\Temp`, a known AppLocker bypass, and the answer's notes
  say so.
- **Same output as a request.** Everything else (AuditOnly unless `--enforce`, Everyone unless `--sid`) is
  exactly what a request produces.

## Test a policy on Windows

```powershell
impr rules test --policy policies\applocker.xml --user Everyone build\windows\tool.exe build\windows\core.dll
```

- **What it asks.** It asks Windows, through `Test-AppLockerPolicy`, whether the policy would allow each
  file for that user (default `Everyone`), without deploying anything. It exits 4 when any file would be
  denied. `--json`: `{"contract":1,"ok":true,"policy":"…","user":"Everyone","results":[{"path":"…","decision":"Allowed","rule":"…"}]}`.
- **Windows only.** Elsewhere it exits 5.
- **How PowerShell runs.** impr writes its own fixed script to a temporary file. The tool allow-list runs
  PowerShell only with that script, byte for byte. Paths and the user reach it as parameters, never as
  code, and a value starting with `-` is refused, so it cannot bind as another parameter.

## The answer

```json
{"contract":1,"renderer":"imprimatur v0.1.0","manifestDigest":"sha256:<hex>","files":[...],
 "appLocker":"<?xml ...><AppLockerPolicy ...>","wdac":"<?xml ...><SiPolicy ...>","notes":["..."]}
```

`files` are the request's, sorted by path, and `manifestDigest` is the
request's: sange accepts the answer only when both match. Without `--json` the
XML is printed on stdout; `--out-dir` also writes `applocker.xml` and
`wdac-supplemental.xml`.

## What the policies allow

- With `publisher.product`: one AppLocker rule per collection (`Exe`, `Msi`,
  `Script`, `Dll`) and binary name, for that publisher and product, at
  `fileVersion` or newer; WDAC file attributes with the same names and minimum
  version. Without it: anything the publisher signs.
- AppLocker collections are `AuditOnly` unless `options.enforce`.
- WDAC is always a supplemental policy of `basePolicyId`, its signer pinned by
  the issuing CA's TBS hash, the leaf's common name and, when given, the EKU.
- No file-hash rules, no base policy, and no randomness: rule and policy ids
  are derived from the inputs, so the same request renders the same bytes.

A request with no files, a non-Windows file, a wrong collection, a missing
publisher fact, no base policy id for WDAC, or another contract version is a
usage error (exit 1). Unlike the PowerShell line, impr does not read signatures
from files on Windows or compile the policy; see
[migration](../recipes/migrate-from-powershell.md).

---

[← Docs index](../../README.md#documentation)
