# `impr hooks`

Hooks are programs you name in your own config. impr runs them before it signs or verifies, or when it
records an event.

## Configure

Hooks live in `<config>/config.json`, schema `imprimatur.config/v1`. The file must be owner-only (0600):
it decides what runs on a signing host.

```json
{
  "schema": "imprimatur.config/v1",
  "hooks": [
    {"name": "release-freeze", "phase": "pre-sign", "exec": "/usr/local/libexec/impr-freeze",
     "sha256": "3f1c…", "timeout": "10s", "veto": true},
    {"name": "notify", "phase": "event", "on": ["signing.run.*", "verification.run.failed"],
     "exec": "/usr/local/libexec/impr-notify", "sha256": "9ab2…"}
  ]
}
```

| Field | Meaning |
| --- | --- |
| `phase` | `pre-sign`, `pre-verify` or `event` |
| `on` | event type globs, for `event` hooks; omit to receive every type. A glob that matches no type is refused |
| `exec` | absolute path. Symlinks are not followed. The file must not be writable by group or others |
| `sha256` | the program's digest. `impr hooks pin FILE` prints it. A changed program is refused |
| `args` | fixed arguments |
| `timeout` | Go duration. The default is 30s and the maximum is 5m |
| `veto` | for `pre-*` hooks: a non-zero exit stops the run |

## How a hook runs

- **Startup.** impr starts the program directly, with no shell.
- **Input.** The event is on stdin as one CloudEvents JSON document. A `pre-sign` hook sees
  `signing.run.started`; a `pre-verify` hook sees `verification.run.started`.
- **Environment.** The program sees `PATH`, `HOME`, temp and locale, plus `IMPR_HOOK`, `IMPR_HOOK_PHASE`,
  `IMPR_EVENT_TYPE` and `IMPR_EVENT_ID`. It never sees impr's other variables, so an `env://` secret never
  reaches a hook.
- **Output.** At most 64 KiB of output is kept for the warning line.
- **Pre-hooks are gates.** A `pre-*` hook runs after every other check has passed, and before the first
  signature or verification.
  - With `veto`, a non-zero exit stops the run. `impr sign` then exits 3 and `impr verify` exits 4.
    Nothing is signed, and `hook.vetoed` is recorded.
  - A hook that fails its pin or times out stops the run too.
- **Event hooks.** `event` hooks run after the event is in the log. Their failures are warnings only and
  never change the command's result.
- **Where hooks come from.** Hooks come only from the user's own config, never from a repository.

## Commands

```bash
impr hooks pin /usr/local/libexec/impr-freeze   # print the sha256 to paste
impr hooks list --json                          # each hook, and whether its pin holds
impr hooks test release-freeze                  # run one hook with a sample event
```

`companion info` reports the `hooks` capability.

---

[← Docs index](../../README.md#documentation)
