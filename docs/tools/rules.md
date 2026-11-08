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
  "manifestDigest": "sha256:<hex>", "commit": "<sha>", "version": "v1.8.0", "fileVersion": "1.8.0.0",
  "publisher": {"subject": "O=ACME LTD, L=LONDON, C=GB", "leafCn": "Acme Ltd", "issuerName": "Acme Issuing CA",
                "issuerTbs": "<hex TBS hash of the CA below the root>", "eku": "1.3.6.1.4.1.311.97.1.0", "product": "tool"},
  "files": [{"path": "build/windows/tool.exe", "sha256": "<hex>", "collection": "Exe", "binaryName": "tool.exe"}],
  "options": {"name": "tool", "enforce": false, "basePolicyId": "{GUID}", "appLocker": true, "wdac": true,
              "userOrGroupSid": "S-1-1-0", "binaryNames": {}}
}
```

## The answer

```json
{"contract":1,"renderer":"imprimatur v1.8.0","manifestDigest":"sha256:<hex>","files":[...],
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
