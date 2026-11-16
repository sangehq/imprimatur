# `impr config`

`impr config` reads and edits impr's layered configuration: hooks, webhooks and the server. Signing
profiles are separate; see [`impr profile`](profile.md).

## Layers

The effective configuration merges these files, each over the one before:

| Layer | File | Who writes it |
| --- | --- | --- |
| system | `/etc/imprimatur/config.json`; macOS `/Library/Application Support/imprimatur/config.json`; Windows `%ProgramData%\imprimatur\config.json` | an administrator |
| user | `~/.config/imprimatur/config.json` | you |
| configuration profile | `~/.config/imprimatur/config.d/<name>.json` | you |

- **How layers merge.** Each layer is a JSON merge patch over the ones before:
  - objects merge key by key;
  - `null` removes a key;
  - anything else, arrays included, replaces the value below.
- **Which profile is active.** `IMPR_CONFIG_PROFILE` wins, then `activeProfile` in the user config, then
  in the system config. A selected profile that does not exist is an error.
- **Overrides.** `IMPR_SYSTEM_CONFIG_DIR` overrides the system location, and `off` disables the system
  layer.
- **Checks.** Every layer must be writable only by its owner, and unknown keys are refused, so a typo
  cannot quietly turn a check off.

## Locked keys

The system config can lock dotted keys:

```json
{"locked": ["server.allowSign", "hooks"], "server": {"allowSign": false}}
```

- **Nothing below can set a locked key.** If the user config or a profile sets one, or replaces its parent
  object, the configuration does not load. A command that would introduce such a change is refused and
  rolled back.
- **Only the system config may lock.**
- **Locking `activeProfile`** also refuses `IMPR_CONFIG_PROFILE`.

## Tool pins and policy

- **Tool pins.** `tools.<name>` pins an external tool to an absolute path and sha256:

  ```bash
  impr tools pin gpg                    # prints {"path": …, "sha256": …} for the gpg PATH finds
  impr config set tools.gpg '{"path":"/opt/homebrew/Cellar/gnupg/2.4.7/bin/gpg","sha256":"…"}'
  impr tools list                       # each tool: path, digest, pinned or from PATH
  ```

  A pinned tool is never looked up on PATH, and a file whose digest no longer matches is refused before
  it runs. After an upgrade, pin the new file. The system config can lock `tools` for a fleet.
- **Full gpg fingerprints.** At sign and verify time, impr refuses any gpg pin shorter than a full 40- or
  64-hex fingerprint. This is on by default. Re-pin an older profile that carries a 16-hex id with
  `gpg --fingerprint <id>` and `impr profile edit NAME --set platforms.checksums.fingerprint=<full>`.
  Setting `policy.gpgFullFingerprint: false` allows short pins again.
- **Fail closed.** `policy.strict: true` runs every `sign` and `verify` as if `--strict` were given, so a
  platform this host cannot sign or check is an error (exit 5), never a skip. Set it in a `ci` or `prod`
  configuration profile (`impr config set policy.strict true --profile ci`), or lock it in the system
  config.
- **A record or nothing.** `events.required: true` makes `sign` and `verify` exit 5 when the event log
  cannot be written ([events](events.md)).
- **Approvals.** `approvals.enforce`, `approvals.required` and `approvals.approvers` decide whether impr
  itself requires approval for profiles with `requiresApproval`, and whose SSH keys may give it. Lock
  `approvals` in the system config, or a signer could add their own key. See
  [`impr approve`](approve.md).

## Commands

```bash
impr config path                      # every layer, and whether it is present
impr config show --json               # the effective configuration, its layers and locked keys
impr config get server.roots
impr config set server.roots '["/Users/me/builds"]'
impr config unset server.listen
impr config validate

impr config profile create ci
impr config set server.allowSign true --profile ci
impr config profile use ci             # or: IMPR_CONFIG_PROFILE=ci impr …
impr config profile use --none
impr config profile list --json
impr config profile rm ci              # refused while it is active
```

- **Values.** A `set` value is parsed as JSON when it is JSON, and kept as a string otherwise.
- **Safe edits.** A change is written, the configuration is reloaded, and the file is put back as it was
  if the result does not load.
- **Events.** Changes are recorded as `config.changed` in the [event log](events.md).
- **Capability.** `companion info` reports the `configProfiles` capability.

---

[← Docs index](../../README.md#documentation)
