# `impr webhooks`

impr sends its events to other apps as signed webhooks. A receiver can verify a delivery with any
Standard Webhooks library.

## Configure

Each subscription goes under `webhooks.outbound` in `<config>/config.json`:

```json
{
  "schema": "imprimatur.config/v1",
  "webhooks": {
    "outbound": [
      {"name": "ci-bus", "url": "https://bus.example.com/hooks/impr",
       "types": ["signing.run.*", "verification.run.failed"],
       "secretRef": "secret://webhooks/ci-bus"}
    ]
  }
}
```

1. Make a secret with `impr webhooks secret`. It prints a new `whsec_` value once, on stdout.
2. Store it under the name `secretRef` gives:
   - **macOS:** `security add-generic-password -s imprimatur -a webhooks/ci-bus -w`.
   - **Linux:** `secret-tool store --label impr service imprimatur account webhooks/ci-bus`.
   - **CI:** use an `env://` variable.
3. Give the same value to the receiver.

## What is sent

```
POST <url>
Content-Type: application/cloudevents+json; charset=utf-8
webhook-id: <event id>
webhook-timestamp: <unix seconds>
webhook-signature: v1,<base64 HMAC-SHA256 of "id.timestamp.body">
```

- **Body.** The body is the structured CloudEvent, exactly as it appears in the [event log](events.md).
- **Which events.** `types` filters by event type glob. Local-class events (`config.changed`, `hook.*`)
  are never sent.
- **Rotation.** Set `previousSecretRef` while a receiver switches secrets. Every delivery then carries
  two `v1` entries, and the receiver accepts either one.

## Safety

- **https only.** Plain http is allowed only to a loopback address, and only with `allowPrivate`. A URL
  with user info or a fragment is refused.
- **No private targets.** The address actually dialled is checked after DNS resolution, so a public name
  that resolves to a private, loopback, link-local (cloud metadata), carrier-grade NAT or multicast
  address is refused. `allowPrivate` lifts this check for one subscription.
- **Limits.** Redirects are never followed, the timeout is 15 s, and an event over 256 KiB is not sent.
- **Secrets never stored in config.** Secrets are only ever references. impr never writes one to disk.

## Delivery, retries, dead letter

- **Outbox.** Each delivery is stored in `<state>/outbox/` and tried once when the event happens.
- **Retries.** A failure is retried on `impr webhooks retry`, following a schedule of 5 s, 5 m, 30 m,
  2 h, 5 h, 10 h and 10 h. `429` and `503` back off twice as long.
- **Dead letter.** After the last attempt, or at once on `410 Gone`, the delivery moves to `dead`.
- **Never fails the command.** A failed delivery never changes the result of the command that emitted
  the event.

```bash
impr webhooks list --json        # subscriptions, and how many deliveries are pending or dead
impr webhooks retry              # send what is due (--all: everything pending)
impr webhooks deliveries --json  # pending, dead and done, with attempts and the last error
```

`companion info` reports the `webhooks` capability. Receiving webhooks from other apps is part of
[`impr serve`](serve.md#inbound-webhooks).

## Managing subscriptions

```bash
impr webhooks add ci-bus --url https://bus.example.com/hooks/impr --secret-ref secret://webhooks/ci-bus \
  --types 'signing.*,cert.*'
impr webhooks test ci-bus                                     # one signed test delivery
impr webhooks rotate ci-bus --secret-ref secret://webhooks/ci-bus-2   # sign with both keys
impr webhooks rotate ci-bus --finish                          # the receiver switched: drop the old one
impr webhooks rm ci-bus
```

- **The same checks as `impr config set`.** Each change goes through the same validation as
  `impr config set webhooks.outbound …`: locked keys are refused, the URL is SSRF-checked, the secret must
  be a reference, and an invalid result is rolled back.
- **Where it goes.** The change lands in the user config, or in a configuration profile with `--profile`.
  A subscription from the system config is never copied into it.
- **Testing.** `impr webhooks test` sends a `webhook.test` event straight to that subscription, whatever
  its types, and leaves the event log alone. It exits 5 if the receiver does not accept it.
- **`Retry-After`.** A receiver answering 429 or 503 is retried no sooner than its `Retry-After`
  (seconds or a date, capped at a day).

---

[← Docs index](../../README.md#documentation)
