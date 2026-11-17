# `impr doctor`

Reports the config and state directories, the default profile, every
profile's problems and what this host can sign with it.

```bash
impr doctor [--json]
```

```json
{"contract":1,"version":"v0.1.0","config":"/Users/me/.config/imprimatur","state":"/Users/me/.local/state/imprimatur",
 "capabilities":{"windows":false,"macos":true,"checksums":true,"containers":false,"attestations":true,"rules":true,"strictReads":true,"events":true,"hooks":true,"webhooks":true,"server":true,"multiSigner":true,"configProfiles":true},
 "defaultProfile":"me-test",
 "profiles":[{"name":"me-test","valid":true,"platforms":{"checksums":{"platform":"checksums","kind":"ssh","sign":true,"verify":true,"tools":["ssh-keygen"],"supported":true}},"ready":["checksums"]}],
 "problems":[],"ok":true}
```

It exits 0 when there are no problems and 1 when there are: an invalid
profile, or no default profile. The `profiles` entries are the ones
[`impr profile capabilities`](profile.md) prints.

## Permissions and tools

- **Folders others could change.** impr's config and state folders are a problem when group or others can
  write them: profiles, bundles, the event log and the audit trail. Anyone who can write there could swap a
  profile, a hook pin or a log. A folder others can only read, such as a usual `~/.config` at 0755, is fine.
- **Keys others could read.** Each `file://` key reference in a profile, and the server's TLS key, is a
  problem when group or others can read it. Fix it with `chmod 600`.
- **Tools.** The report lists every allow-listed tool with its path and SHA-256, and whether it is pinned
  (`--json`: `tools`). A pinned tool whose file changed is a problem.
- **Windows.** It has no Unix mode bits, so the permission checks report nothing there.

---

[← Docs index](../../README.md#documentation)
