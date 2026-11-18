# `impr serve`

`impr serve` runs impr as a local REST API. Other apps can then list profiles, verify signatures, and, if
you allow it, sign build manifests, without running the CLI themselves.

## Start it

```bash
impr server token add --scopes read,verify     # prints the token once; only its sha256 is kept
impr serve --check-config                      # validate config.json without listening
impr serve                                     # Unix socket at <state>/server/impr.sock (Windows: a named pipe)
impr serve --listen 127.0.0.1:8743             # or a loopback port
```

- **Socket.** The socket is 0600, in a 0700 directory, so only your user can connect.
  On Linux (`SO_PEERCRED`) and macOS (`LOCAL_PEERCRED`) impr also reads each connection's peer uid
  and closes any from another user, root included, recording `server.auth.refused`.
- **Windows.** With `listen` unset, impr serves a named pipe, `\\.\pipe\imprimatur-<hash of the state
  folder>`, printed when it starts. The pipe's DACL is protected and grants access to your user only,
  remote clients are refused, and impr creates it as the first instance, so it will not start if another
  process already holds the name. File modes mean nothing on Windows, so a Unix socket there
  (`"listen": "unix"`, still accepted) relies on the profile folder's permissions and the token alone.
  A client that finds every instance busy (`ERROR_PIPE_BUSY`) waits and tries again, as .NET's
  `NamedPipeClientStream` does; impr opens the next instance as it accepts each connection.
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
| `GET /v1/profiles/{name}/capabilities` | read | `profile capabilities` |
| `POST /v1/rules` | read | `rules --request`, with the request as the body |
| `GET /v1/webhooks` | admin | `webhooks list` |
| `POST /v1/webhooks` | admin, and `allowAdmin` | `webhooks add` (body: `name`, `url`, `secretRef`, `types`, `allowPrivate`) |
| `DELETE /v1/webhooks/{name}` | admin, and `allowAdmin` | `webhooks rm` |
| `POST /v1/webhooks/{name}/test` | admin | `webhooks test` |

`POST /v1/verify` takes:

```json
{"root": "/Users/me/builds/tool", "profile": "acme-release",
 "signed": "build/impr-manifest.json", "manifest": "build/build-manifest.json", "strict": true}
```

Instead of `signed`, it can take `"files": ["build/windows/tool.exe"]`. `POST /v1/sign` takes `root`,
`manifest`, `commit`, `tree`, `profile`, `purpose`, and optionally `platforms`, `repo` and `strict`. With `approvals` (paths under `root`, each with its `.sig`), it passes [approvals](approve.md) on; a profile whose `approval` is `confirm` is refused over the API, since nobody can type it.

## Running it as a service

`impr serve install-unit --print` prints a unit that keeps `impr serve` running for you, and how to
install it. impr installs nothing itself: where and how a service runs is your decision.

```bash
impr serve install-unit --print                  # the unit for this OS
impr serve install-unit --print --for systemd    # systemd, launchd or task
```

| `--for` | Unit | Notes |
| --- | --- | --- |
| `systemd` (Linux default) | a user service, `~/.config/systemd/user/impr.service` | Sandboxed: `ProtectSystem=strict`, a read-only home, `NoNewPrivileges`. It writes only impr's state directory and the configured `server.roots` |
| `launchd` (macOS default) | a launch agent, `~/Library/LaunchAgents/com.simtabi.sange.imprimatur.serve.plist` | Restarted when it exits with an error; logs to `<state>/server/serve.log` |
| `task` (Windows default) | a Task Scheduler task that starts at logon and restarts on failure | impr is not a Windows service, which would need a service control handler |

- **Checks first.** It refuses when the config is not valid or no token or inbound endpoint is
  configured, because the service would not start.
- **The binary path.** The unit runs this binary by its absolute path, symlinks resolved. `--exe`
  names another one.
- **After an upgrade.** Re-run it when the binary moves, and after you add a signing root, so the
  systemd unit can write there.

### The launchd label

The launch agent's label was `sh.sange.imprimatur.serve` before 2026-11-17, and is
`com.simtabi.sange.imprimatur.serve` since. impr installs no agent, so it moves none itself:

- **`install-unit --print` replaces the old one.** When `~/Library/LaunchAgents/sh.sange.imprimatur.serve.plist`
  is there, the printed steps stop and remove it before installing the new one:

  ```bash
  launchctl bootout gui/$(id -u)/sh.sange.imprimatur.serve; rm -f ~/Library/LaunchAgents/sh.sange.imprimatur.serve.plist; launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.simtabi.sange.imprimatur.serve.plist
  ```

  Each step is safe to run again. Once the old plist is gone, the steps are the `bootstrap` alone.
- **`impr doctor` reports an agent under the old label** as a problem, with the same steps.
- **`impr uninstall` names every agent left behind**, under either label, with the commands to remove it.
  It removes none.
- **Deprecated.** Recognising the old label may be removed no earlier than v0.2.0.

The daily certificate check moved the same way, from `sh.sange.imprimatur.cert-check` to
`com.simtabi.sange.imprimatur.cert-check` ([notify](notify.md#certificate-expiry)).

## Event stream

`GET /v1/events/stream` sends events as they are written, as Server-Sent Events. It reads the event log,
which every impr process writes, so it carries CLI runs as well as API ones.

```bash
curl -N --unix-socket ~/.local/state/imprimatur/server/impr.sock \
  -H "Authorization: Bearer $IMPR_TOKEN" "http://impr/v1/events/stream?type=signing.*"
```

```text
id: 6f0c…
event: com.simtabi.sange.imprimatur.signing.run.completed
data: {"specversion":"1.0","id":"6f0c…","type":"com.simtabi.sange.imprimatur.signing.run.completed",…}
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
  - `root` must be under one of `server.roots`, and every path must stay inside it, both as written and
    with symbolic links resolved, so a link inside a root cannot point the request elsewhere. The
    command checks every artifact path against the root and symlinks again.
  - With no roots configured, verify and sign refuse.
- **Arguments.** The server builds each command's arguments only from validated fields. File names go
  after `--`, so a name like `--json` can never act as an option.
- **Changing configuration.** Adding or removing a webhook over the API needs a token with the `admin`
  scope and `server.allowAdmin`, which is off by default. A webhook can carry internal events off the
  machine, so adding one weighs as much as signing. Config locks still apply, and every change is audited.
  `POST /v1/rules` writes the request to a private temporary file under the state directory and removes it
  afterwards. It reads nothing else from disk: the request names files by digest.
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
- **`v1a`.** An endpoint can take ed25519 deliveries instead: set `publicKey` (and, during a rotation,
  `previousPublicKey`) to the sender's `whpk_` key, in place of or beside `secretRef`. A public key is not
  secret, so it is written in the config rather than referenced. A `v1` entry is checked only against
  secrets and a `v1a` entry only against public keys.
- **Replays.** A `webhook-id` already processed answers 409. The ledger survives restarts.
- **Actions.**
  - `allow` lists the actions the endpoint accepts: `verify`, `doctor`, `cert.list` or `profile.list`.
  - Signing is never an inbound action.
  - `verify` follows the same rules as `POST /v1/verify`.

### GitHub deliveries

An endpoint with `"kind": "github"` takes GitHub's own webhooks. Its `secretRef` names the secret set on
the GitHub webhook, at least 16 characters.

```json
"inbound": [
  {"name": "gh-audit", "kind": "github", "secretRef": "secret://webhooks/gh", "allow": ["doctor"],
   "githubEvents": ["push", "release"]},
  {"name": "gh-doctor", "kind": "github", "secretRef": "secret://webhooks/gh", "allow": ["doctor"], "run": "doctor"}
]
```

- **Signature.** `X-Hub-Signature-256` must match the HMAC-SHA256 of the body. Every failure is the
  same 401.
- **Replays.** GitHub signs no timestamp, so the delivery id (`X-GitHub-Delivery`) is remembered for 7
  days and a repeat answers 409.
- **`ping`** is always answered with `{"result": "pong"}`.
- **Which events.** `githubEvents` limits the endpoint to those event names; others answer
  `{"result": "ignored"}`. Empty accepts every event.
- **What happens.** Every accepted delivery is recorded as `webhook.inbound.received`, with the event
  name, delivery id, repository, ref and action. That is all, unless `run` is set: then the delivery also
  runs that action (`doctor`, `cert.list` or `profile.list`, and one of `allow`) and answers with its
  document. `verify` cannot be run this way, because a GitHub event carries no verify request.

`companion info` reports the `server` capability. `server.started` and `server.stopped` are recorded in the
[event log](events.md).

---

[← Docs index](../../README.md#documentation)
