# `impr audit`

`impr audit` reads the audit trail. impr appends one record to it for every command that signs or changes
something.

## What is recorded

- **Commands recorded:** `sign`, `verify`, `build`, `release`, `install` and `uninstall`; `profile` add,
  edit, rm, import, default and import-legacy; `config` set, unset and profile; `server token`;
  `webhooks secret`; and `completion` install and uninstall. Read-only commands are not recorded.
- **Each record holds:** the user, the command and its arguments, the exit code and the duration. It is a
  CloudEvent of type `com.simtabi.sange.imprimatur.audit.command.completed`
  (`sh.sange.imprimatur.audit.command.completed` before 2026-11-17; see [type names](events.md#type-names)).
- **Secrets are kept out.** An argument shaped like a secret (`whsec_…`, an API token, a private key,
  `password=`) is written as `[redacted]`. Secrets themselves never appear in arguments; impr takes only
  references.
- **Location.** Records go to `<state>/audit/YYYY-MM.jsonl` (files 0600, in a 0700 folder). They are
  chained like the [event log](events.md), and `head` holds the newest line's hash, so an edit to any
  record, the newest included, breaks `impr audit verify`.
- **A failed write never fails the command.** The command has already run, so a record that cannot be
  written is a warning.

## Usage

```bash
impr audit tail --limit 20
impr audit tail --json
impr audit verify          # exit 4 if any record was edited, removed or reordered
impr audit anchor --json   # both chain heads now, emitted as an audit.head event
impr audit verify --against anchor.json   # also check a saved anchor
```

## Anchoring off the machine

The hash chain catches an edited, removed or reordered record. It cannot catch malware with your rights
rewriting the whole trail and its head file consistently. Anchoring closes that: impr sends each chain's
head off the machine, and a later check compares the local trail with what was sent.

```json
"audit": {"anchor": {"enabled": true, "everyHours": 6}},
"webhooks": {"outbound": [
  {"name": "anchor", "url": "https://anchors.example.com/hooks/impr", "types": ["audit.head"],
   "secretRef": "secret://webhooks/anchor"}
]}
```

- **When.** With `audit.anchor.enabled`, impr emits an `audit.head` event after each audited command,
  and every `everyHours` (default 6) while `impr serve` runs. `impr audit anchor` emits one at any time.
  The event holds both chains' heads: `{"audit":{"head":"sha256:…","count":42},"events":{"head":"sha256:…","count":310}}`.
- **Where to.** Any outbound webhook subscribed to `audit.head` delivers it, signed with Standard
  Webhooks. sange's server is one such receiver; any service that keeps the deliveries works.
- **Checking.** `impr audit verify --against FILE` takes a kept `audit.head` event, or the `--json`
  output of `impr audit anchor`. It fails (exit 4) when a line up to the anchored count no longer
  hashes to the anchored head, or when lines were removed. Records added after the anchor are fine.
- **Lock it.** Lock `audit` and the webhook in the system config, or the malware the anchor guards
  against could switch it off. Anchors already delivered still catch a rewrite of what came before.

### The receiver contract

A receiver for sange's server, or any other, needs to do three things:

1. Verify each delivery as a Standard Webhook (`webhook-id`, `webhook-timestamp`, `webhook-signature`)
   with the subscription's secret, and refuse a replayed `webhook-id`.
2. Keep each `com.simtabi.sange.imprimatur.audit.head` CloudEvent (`sh.sange.imprimatur.audit.head`
   from an impr before 2026-11-17), keyed by its `source` (one per impr install) and `time`. Only append:
   never let a later delivery replace an earlier one. The `source` is
   `https://sange.sh/imprimatur/install/<id>`, or `https://simtabi.com/sange/imprimatur/install/<id>` when
   the install sets `events.source` to `simtabi.com` ([event source](events.md#event-source)).
3. Hand a kept event back on request, so `impr audit verify --against` can check it.

---

[← Docs index](../../README.md#documentation)
