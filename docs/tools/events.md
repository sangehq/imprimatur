# `impr events`

`impr events` reads the event log. impr writes one CloudEvents 1.0 event to the log for each signing or
verification step it takes.

## What is recorded

- **Format.** Each event is a structured CloudEvents 1.0 JSON document of type
  `sh.sange.imprimatur.<context>.<noun>.<verb>`. It carries:
  - `source`: `https://sange.sh/imprimatur/install/<install id>`. The install id is 64 random bits, never
    the host or user name.
  - `subject`: the repository key, or the profile name. It is never a local path.
  - `imprclass`: `internal` or `local`, saying who may store the event.
- **Location.** Events go to `<state>/events/YYYY-MM.jsonl`. Files are 0600, in a 0700 folder.
- **Chain.** Each line carries `imprprev`, the sha256 of the line before it, and `<state>/events/head`
  holds the hash of the newest line. `impr events verify` uses both to detect an edited, removed or
  reordered line, the newest included.
- **Not on stdout.** Events never appear on stdout, so every `--json` document is unchanged.
- **Failure does not stop the command.** If the log cannot be written, impr prints a warning and the
  command carries on.
- **No secrets.** Event data holds ids, names, paths relative to the signing root, and digests. It never
  holds a key, a password or a reference value.

| Type (after `sh.sange.imprimatur.`) | When |
| --- | --- |
| `signing.run.started` | every pre-check of `impr sign` passed, just before the first signature |
| `signing.artifact.signed` | one per signed binary, with its input and output sha256 |
| `signing.run.completed` / `.skipped` / `.failed` | the run's end, with the `impr-manifest.json` digest and exit code |
| `verification.run.completed` / `.failed` | the end of `impr verify` |
| `cert.expiring` / `cert.expired` | `impr cert list` or `impr serve` found a certificate past a warning threshold, or expired; once per threshold ([notify](notify.md)) |
| `approval.created` | `impr approve` wrote an approval |
| `profile.created` / `.changed` / `.removed` | a profile was added, imported, edited or removed: its name, scope, owner, purposes and identity digest |
| `config.changed`, `hook.*` | configuration changes, and hook failures and vetoes |
| `webhook.delivery.dead` | an outbound delivery ran out of attempts and moved to the dead letter. Written to the log only, never delivered |
| `webhook.secret.rotated` | `impr webhooks rotate` started (`step: started`) or finished (`step: finished`) a key overlap |
| `server.auth.refused` | `impr serve` refused a request for its token or an inbound signature; at most once a minute per caller, named by a short hash of its address |
| `audit.head` | both chain heads, for anchoring off the machine ([audit](audit.md#anchoring-off-the-machine)) |

`impr events types --json` prints the full catalogue, with each type's class and schema URL.

## Usage

```bash
impr events tail                                  # the last 50 events
impr events tail --type 'signing.*' --limit 10 --json
impr events verify                                # walk the hash chain
impr events types --json
```

- `impr events verify` exits 4 when the chain is broken. The `--json` document is
  `{contract, ok, checked, problem}`.
- `companion info` reports the `events` capability.
- `impr events replay --to WEBHOOK` resends logged events to one outbound webhook (see below).
- To follow events as they happen from another program, use `impr serve`'s
  [event stream](serve.md#event-stream).

## Replay

```bash
impr events replay --to ci-bus --since 24h --dry-run   # what would be sent
impr events replay --to ci-bus --since 2026-11-16T00:00:00Z --type 'signing.*'
```

Replay resends logged events to one outbound webhook: a receiver that was down, or one added after the
events happened.

- **What it sends.** Only what that subscription would have received: its types, and never a local-class
  event. `--type` narrows it further, and `--since` takes a duration or a time.
- **No duplicates.** Events the receiver already acknowledged are skipped. `--force` sends them again.
- **Signed and retried.** Each delivery is signed and retried exactly like a live one.
- **Bounded.** A run stops at `--limit` (default 1000). Run it again for the rest.
- **Output.** `--json`: `{"contract":1,"ok":true,"subscription":"…","matched":12,"sent":9,"pending":0,"alreadyDelivered":3}`.

---

[← Docs index](../../README.md#documentation)
