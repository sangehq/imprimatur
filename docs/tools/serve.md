# `impr serve`

`impr serve` runs impr as a local REST API. Other apps can then list profiles, verify signatures, and, if
you allow it, sign build manifests, without running the CLI themselves.

## Start it

```bash
impr server token add --scopes read,verify     # prints the token once; only its sha256 is kept
impr serve --check-config                      # validate config.json without listening
impr serve                                     # Unix socket at <state>/server/impr.sock
impr serve --listen 127.0.0.1:8743             # or a loopback port
```

- **Socket.** The socket is 0600, in a 0700 directory, so only your user can connect.
- **Addresses.** A loopback port is the other everyday choice. An address other machines can reach is
  allowed only with `server.allowRemote` and `server.tls` set (see below).
- **Stopping.** Ctrl-C or SIGTERM stops it gracefully.

```bash
curl --unix-socket ~/.local/state/imprimatur/server/impr.sock \
  -H "Authorization: Bearer $IMPR_TOKEN" http://impr/v1/profiles
```

## Configure

These settings go under `server` in `<config>/config.json`:

```json
{
  "schema": "imprimatur.config/v1",
  "server": {
    "listen": "unix",
    "roots": ["/Users/me/builds"],
    "allowSign": false,
    "tokens": [{"id": "tok_…", "sha256": "…", "scopes": ["read", "verify"]}],
    "inbound": [{"name": "sange", "secretRef": "secret://webhooks/sange-in", "allow": ["verify"]}]
  }
}
```

## Serving other machines (mTLS)

To serve other machines, set `allowRemote` and `tls` under `server` in `config.json`:

```json
{"server": {"listen": "0.0.0.0:8743", "allowRemote": true,
            "tls": {"certFile": "/etc/impr/server.pem", "keyFile": "/etc/impr/server-key.pem",
                    "clientCaFile": "/etc/impr/clients-ca.pem"}}}
```

- **impr refuses to start without both.** A non-loopback `listen` without `allowRemote` and `tls` fails.
- **What a caller needs.** The server speaks TLS 1.3 only, and every caller must present a client
  certificate that chains to `clientCaFile` as well as a valid token. A missing certificate, or one from
  another CA, is refused during the handshake.
- **The key file must be owner-only** (0600). You make the certificates; impr only reads them.
- **The prompt.** At a terminal, impr names the address and the CA, and listens only after you type `yes`.
  Under a service manager there is no prompt, because `allowRemote` in the config is the consent. `--yes`
  skips the prompt.
- **On loopback.** `tls` can be set on a loopback address too, if you want mTLS there.

## Endpoints

Every response is the same JSON document the matching `impr … --json` command prints. Exit codes map to
HTTP status:

| Exit code | HTTP status |
| --- | --- |
| 0 (ok), 2 (skipped) | 200 |
| 1 (usage) | 400 |
| 3 (sign failed), 4 (verify failed) | 422 |
| 5 (unavailable) | 503 |

| Endpoint | Scope | Runs |
| --- | --- | --- |
| `GET /v1/health` | none | — |
| `GET /v1/openapi.json` | none | — (the OpenAPI 3.1 description of this API) |
| `GET /v1/companion` | read | `companion info` |
| `GET /v1/doctor` | read | `doctor` |
| `GET /v1/profiles`, `GET /v1/profiles/{name}` | read | `profile list`, `profile show` |
| `GET /v1/certs` | read | `cert list` |
| `GET /v1/events?type=GLOB&limit=N` | events | `events tail` |
| `GET /v1/events/stream?type=GLOB` | events | — (Server-Sent Events, below) |
| `POST /v1/verify` | verify | `verify` |
| `POST /v1/sign` | sign, and `allowSign` | `sign` |

`POST /v1/verify` takes:

```json
{"root": "/Users/me/builds/tool", "profile": "acme-release",
 "signed": "build/impr-manifest.json", "manifest": "build/build-manifest.json", "strict": true}
```

Instead of `signed`, it can take `"files": ["build/windows/tool.exe"]`. `POST /v1/sign` takes `root`,
`manifest`, `commit`, `tree`, `profile`, `purpose`, and optionally `platforms`, `repo` and `strict`.

## Event stream

`GET /v1/events/stream` sends events as they are written, as Server-Sent Events. It reads the event log,
which every impr process writes, so it carries CLI runs as well as API ones.

```bash
curl -N --unix-socket ~/.local/state/imprimatur/server/impr.sock \
  -H "Authorization: Bearer $IMPR_TOKEN" "http://impr/v1/events/stream?type=signing.*"
```

```text
id: 6f0c…
event: sh.sange.imprimatur.signing.run.completed
data: {"specversion":"1.0","id":"6f0c…","type":"sh.sange.imprimatur.signing.run.completed",…}
```

- **Messages.** `id` is the CloudEvent id, `event` its type, and `data` the CloudEvent as one JSON line.
- **Where it starts.** At the end of the log. A client that reconnects with `Last-Event-ID` resumes just
  after that event; an id that is not in the log gets 409.
- **Filters.** `type` takes event type globs and may repeat; a glob that matches no known type is a 400.
- **Limits.** A comment line every 15 seconds keeps proxies from closing the connection. A stream closes
  after an hour, so the client reconnects and its token is checked again. At most 8 streams are open at
  once; the next gets 503 with `Retry-After`.

## Safety

- **Tokens.**
  - Every endpoint but `/v1/health` and `/v1/openapi.json` needs a bearer token with the endpoint's
    scope. Inbound webhooks use their signature instead.
  - impr keeps only the token's sha256 and compares tokens in constant time.
  - Every refusal is the same 401 body.
  - Each token may make 120 requests a minute.
- **Requests.**
  - Bodies are strict JSON (unknown fields are refused), one object, at most 1 MiB.
  - A request carries paths and names, never artifacts.
- **Roots.**
  - `root` must be under one of `server.roots`, and every path must stay inside it. The command checks
    every artifact path against the root and symlinks again.
  - With no roots configured, verify and sign refuse.
- **Arguments.** The server builds each command's arguments only from validated fields. File names go
  after `--`, so a name like `--json` can never act as an option.
- **Signing.**
  - `/v1/sign` is off unless `allowSign` is true. It needs the `sign` scope, and a build manifest bound to
    the commit and tree, exactly as the CLI does.
  - Only one signing run happens at a time.
  - impr is never a signing oracle.
- **Revoking.** `impr server token revoke` takes effect when the server restarts.

## Inbound webhooks

Other apps can call `POST /v1/hooks/{name}` with a Standard Webhooks delivery, signed with the endpoint's
`whsec_` secret (`impr webhooks secret` makes one):

```json
{"action": "verify", "verify": {"root": "/Users/me/builds/tool", "profile": "acme-release", "files": ["tool.exe"]}}
```

- **Signature.** The signature must verify within 5 minutes (`tolerance`, at most 15 m), under the current
  or the previous secret. Every failure is the same 401.
- **Replays.** A `webhook-id` already processed answers 409. The ledger survives restarts.
- **Actions.**
  - `allow` lists the actions the endpoint accepts: `verify`, `doctor`, `cert.list` or `profile.list`.
  - Signing is never an inbound action.
  - `verify` follows the same rules as `POST /v1/verify`.

`companion info` reports the `server` capability. `server.started` and `server.stopped` are recorded in the
[event log](events.md).

---

[← Docs index](../../README.md#documentation)
