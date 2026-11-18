# `impr events`

`impr events` reads the event log. impr writes one CloudEvents 1.0 event to the log for each signing or
verification step it takes.

## What is recorded

- **Format.** Each event is a structured CloudEvents 1.0 JSON document of type
  `com.simtabi.sange.imprimatur.<context>.<noun>.<verb>` (`sh.sange.imprimatur.…` before 2026-11-17; see
  [Type names](#type-names)). It carries:
  - `source`: `https://sange.sh/imprimatur/install/<install id>` by default, or
    `https://simtabi.com/sange/imprimatur/install/<install id>` with `events.source` set to `simtabi.com`
    ([Event source](#event-source)). The install id is 64 random bits, never the host or user name.
  - `subject`: the repository key, or the profile name. It is never a local path.
  - `imprclass`: `internal` or `local`, saying who may store the event.
- **Location.** Events go to `<state>/events/YYYY-MM.jsonl`. Files are 0600, in a 0700 folder.
- **Chain.** Each line carries `imprprev`, the sha256 of the line before it, and `<state>/events/head`
  holds the hash of the newest line. `impr events verify` uses both to detect an edited, removed or
  reordered line, the newest included.
- **One writer at a time.** A writer holds an exclusive lock on `<state>/events/.lock` while it reads the
  chain's head and appends, so `impr serve` and a CLI run writing at once keep one chain (on macOS, Linux,
  the BSDs and Windows). To chain a new line it reads only the end of the newest month file, so
  appending costs the same however long the log is.
- **Not on stdout.** Events never appear on stdout, so every `--json` document is unchanged.
- **Failure does not stop the command.** If the log cannot be written, impr prints a warning and the
  command carries on.
- **Unless the log is required.** With `events.required: true`, `impr sign` and `impr verify` exit 5
  when the log cannot be written: before the first signature or verification if the start event fails,
  or at the end if the last event fails. Turn it on where a run with no record is worse than no run
  (`impr config set events.required true --profile prod`).
- **No secrets.** Event data holds ids, names, paths relative to the signing root, and digests. It never
  holds a key, a password or a reference value.

| Type (after `com.simtabi.sange.imprimatur.`) | When |
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
| `webhook.inbound.received` | a `github` inbound endpoint accepted a delivery: event name, delivery id, repository, ref ([serve](serve.md#github-deliveries)) |
| `server.auth.refused` | `impr serve` refused a request for its token or an inbound signature; at most once a minute per caller, named by a short hash of its address |
| `audit.head` | both chain heads, for anchoring off the machine ([audit](audit.md#anchoring-off-the-machine)) |

`impr events types --json` prints the full catalogue, with each type's class and schema URL.

## Type names

On 2026-11-17 every type moved from the `sh.sange.imprimatur.` prefix to `com.simtabi.sange.imprimatur.`,
the reverse-DNS namespace of Simtabi LLC, which owns sange and its family. The part after the prefix is
unchanged.

| Before 2026-11-17 | Since |
| --- | --- |
| `sh.sange.imprimatur.signing.run.started` | `com.simtabi.sange.imprimatur.signing.run.started` |
| `sh.sange.imprimatur.signing.run.completed` | `com.simtabi.sange.imprimatur.signing.run.completed` |
| `sh.sange.imprimatur.webhook.secret.rotated` | `com.simtabi.sange.imprimatur.webhook.secret.rotated` |
| `sh.sange.imprimatur.cert.expiring` / `.expired` | `com.simtabi.sange.imprimatur.cert.expiring` / `.expired` |
| `sh.sange.imprimatur.audit.head` | `com.simtabi.sange.imprimatur.audit.head` |
| `sh.sange.imprimatur.<any other type>` | `com.simtabi.sange.imprimatur.<the same type>` |

- **What changes.** New events, webhook deliveries, the [event stream](serve.md#event-stream), hooks'
  `IMPR_EVENT_TYPE` and `impr events types` all carry the new name. A receiver or hook that compares the
  full type must accept it. sange's server accepts both for `audit.head`.
- **What still works.** A filter written with the old prefix selects the same events: hook `on`, webhook
  `types`, `--type` and the stream's `type`. Short names (`signing.*`) never carried a prefix and are
  unaffected. Events logged before the change keep their old type, are matched by either prefix, and
  still verify, since the hash chain covers the lines as written.
- **Deprecated.** Reading the old prefix in filters may be removed no earlier than v0.2.0. Write filters
  with short names, or with the new prefix.

## Event source

`events.source` chooses the domain of this install's `source`:

| `events.source` | `source` |
| --- | --- |
| `sange.sh` (the default, also when unset) | `https://sange.sh/imprimatur/install/<install id>` |
| `simtabi.com` | `https://simtabi.com/sange/imprimatur/install/<install id>` |

```bash
impr config set events.source simtabi.com
```

- **Anything else is refused** when the configuration loads.
- **The install id is the same under either.** Only the base before `/install/` changes.
- **It also chooses the provenance build type and builder id** an in-toto attestation is written with:
  `https://sange.sh/imprimatur/buildtypes/manifest/v1` and `https://sange.sh/imprimatur` under `sange.sh`,
  `https://simtabi.com/sange/imprimatur/buildtypes/manifest/v1` and `https://simtabi.com/sange/imprimatur`
  under `simtabi.com`. `impr verify` accepts both forms under either setting
  ([backends](backends.md#in-toto-attestations)).
- **`dataschema` does not change.** It names where the schemas are published,
  `https://sange.sh/schemas/imprimatur/events/<type>/v1.json`.
- **Tell your receivers first.** A receiver that checks `source`, as sange's server does for `audit.head`
  anchors, must accept the new one before you switch.

## Usage

```bash
impr events tail                                  # the last 50 events
impr events tail --type 'signing.*' --limit 10 --json
impr events tail --follow --type 'signing.*'       # then print each new event until Ctrl-C
impr events verify                                # walk the hash chain
impr events types --json
```

- `--follow` keeps printing events as they are written, until Ctrl-C. It cannot be combined with `--json`,
  which prints one document; for a machine-readable stream, use `GET /v1/events/stream` on
  [`impr serve`](serve.md).
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
