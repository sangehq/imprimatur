# `impr doctor`

Reports the config and state directories, the default profile, every
profile's problems and what this host can sign with it.

```bash
impr doctor [--json]
```

```json
{"contract":1,"version":"v1.8.0","config":"/Users/me/.config/imprimatur","state":"/Users/me/.local/state/imprimatur",
 "capabilities":{"windows":false,"macos":true,"checksums":true,"containers":false,"attestations":false,"rules":true},
 "defaultProfile":"me-test",
 "profiles":[{"name":"me-test","valid":true,"platforms":{"checksums":{"platform":"checksums","kind":"ssh","sign":true,"verify":true,"tools":["ssh-keygen"],"supported":true}},"ready":["checksums"]}],
 "problems":[],"ok":true}
```

It exits 0 when there are no problems and 1 when there are: an invalid
profile, or no default profile. The `profiles` entries are the ones
[`impr profile capabilities`](profile.md) prints.

---

[← Docs index](../../README.md#documentation)
