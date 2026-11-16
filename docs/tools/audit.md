# `impr audit`

`impr audit` reads the audit trail. impr appends one record to it for every command that signs or changes
something.

## What is recorded

- **Commands recorded:** `sign`, `verify`, `build`, `release`, `install` and `uninstall`; `profile` add,
  edit, rm, import, default and import-legacy; `config` set, unset and profile; `server token`;
  `webhooks secret`; and `completion` install and uninstall. Read-only commands are not recorded.
- **Each record holds:** the user, the command and its arguments, the exit code and the duration. It is a
  CloudEvent of type `sh.sange.imprimatur.audit.command.completed`.
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
```

---

[← Docs index](../../README.md#documentation)
