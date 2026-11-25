# Web UI

`impr serve` starts a web UI on this machine's loopback address, beside the API, so you can see and change
impr's state from a browser without a terminal.

## Start it

```bash
impr serve                  # the API as before, and the web UI on http://127.0.0.1:7823/
impr serve --port 7900      # pin the web UI's port; fails if it is taken
impr serve --no-open        # print the sign-in link, open no browser
impr serve --no-web         # the API alone, as before this UI existed
impr serve --verbose        # log page views too, not only changes
```

- **The address.** 127.0.0.1, port 7823 by default. When 7823 is taken it tries the next 20 ports, then any
  free port, and prints the address it bound. `--port` pins one and fails rather than serve elsewhere;
  `--port 0` takes any free port. The web UI is never offered to other machines, whatever `server.listen`
  says. The three sange projects use fixed, distinct defaults: sange 7821, authama 7822, imprimatur 7823.
- **No API token needed.** The web UI signs in with a one-time link. The API answers 401 to any call
  without a token, as it always did, and `impr serve --no-web` with no token or inbound endpoint is still
  refused.
- **One server per state directory.** A second `impr serve` finds the running one through
  `<state>/web/serve.json`, asks it for a fresh link, prints or opens that, and exits. Stop the server with
  Ctrl-C where it runs.
- **Stopping.** Ctrl-C or SIGTERM stops the API and the web UI together.

## Signing in

`impr serve` prints a one-time sign-in link, `http://127.0.0.1:7823/?token=…`:

- **At a terminal with a desktop**, it opens the link in your browser. It hands the browser an owner-only
  page (0600, in `<state>/web/`) that redirects to the link, so the link is never on a command line another
  user could read. Over SSH, or on Linux without `DISPLAY` or `WAYLAND_DISPLAY`, it says why and opens
  nothing.
- **With nobody at a terminal** (the service unit, a script), it writes the link to
  `<state>/web/signin-link` (0600) and logs only that file's path, never the link.
- **The link works once**, by a GET, within 10 minutes. The server swaps it for a session cookie and
  redirects (303) to the same page without the token, so it leaves the address bar and the history.
- **The session** is an HttpOnly, `SameSite=Strict` cookie for the whole UI. It ends after 8 hours without
  a request, 24 hours after sign-in, or at Sign out (in the user menu).
- **An API token still signs in** at `/signin`; 5 failed sign-ins a minute, then a minute's wait. What it
  reaches is `server.web.tokenAccess` ([configuration](../configuration.md#the-web-ui)):
  - `secrets`, the default: a token with the `secrets` scope opens the Secrets page only, as the old secrets
    page did.
  - `scopes`: the token's scopes decide. `read` opens the read-only pages (Overview, Doctor, Profiles,
    Certificates, Audit, About), `secrets` the Secrets page and its form, `events` the Events page, and
    `admin` API tokens, Webhooks and every other change (set default, remove, create a test certificate).
    A token with none of these cannot sign in.

  Pages, menu entries, palette entries and buttons the session cannot use are not shown, and a request
  for one answers 403. The one-time link's session reaches everything.

## Pages

Every page runs the same command the CLI does, with `--json`, through the same bridge as the API, and shows
its document. Every change is that command too: nothing in the UI is a second implementation.

| Page | Shows | Changes |
| --- | --- | --- |
| Overview (`/`) | the doctor's verdict, counts of profiles, certificates, secrets, tokens and webhooks, recent events | — |
| Doctor | `impr doctor`: problems, notes, profiles, tools | — |
| Profiles | `impr profile list`, `show`, `capabilities`, `validate` | set default (`profile default`), remove (`profile rm`) |
| Certificates | `impr cert list` | create a test certificate (`cert create --name --days`, and `--subject` when given; empty takes impr's default) |
| Secrets | the names and references in `.env` | store a value or a `.p8` file in the OS secret store |
| API tokens | `impr server token list` | add with scopes (shown once), revoke |
| Webhooks | `impr webhooks list`, `deliveries` | add, remove, test, retry, retry all |
| Events | `impr events tail`, live as events are written, filtered by type | — |
| Audit | `impr audit tail` and `audit verify` | — |
| About | the version, `impr path`, `impr companion info`, the third-party licences | — |

- **Forms open in a side panel**, and work as ordinary pages without JavaScript. A change redirects
  (303) to the page it affects, which shows what happened as a toast.
- **Remove and revoke ask first**, in a danger dialog. Without JavaScript the server asks on a page of its
  own, so nothing is removed unasked either way.
- **A new API token is shown once**, with a copy button, and never again; it is not logged. A running API
  reads its tokens when it starts, so a token added or revoked here takes effect there on restart.
- **A secret's value** goes to the OS secret store as data, never on a command line, is never shown back,
  and is held to 64 KiB.
- **Webhooks** are added through the API's own checks: a name, an http(s) URL, and a `secret://` or
  `env://` reference, never the secret itself. Adding or removing one needs `server.allowAdmin`, as over
  the API, unless `server.web.webhookAdmin` is `owner`, which lets the session from `impr serve`'s link do
  it without ([configuration](../configuration.md#the-web-ui)). When it is off, the Webhooks page and its
  form show the controls disabled, with the reason and the setting that turns it on, and a post is refused
  (403) without running anything. Test, retry and retry all change no configuration and always work.
- **Ctrl-K** (⌘K on a Mac) opens the command palette; **?** lists the keyboard shortcuts, such as `g p` for
  Profiles and `n c` for a new test certificate. The moon and sun switch the theme.

## Safety

- **Loopback only.** The listener is 127.0.0.1, and a request is answered only when its `Host` is
  `127.0.0.1`, `localhost` or `[::1]` at the bound port; anything else gets 421, which stops a page that
  points its own name at 127.0.0.1 (DNS rebinding).
- **Every change** needs an `Origin` naming this server (or, without one, `Sec-Fetch-Site: same-origin`)
  and the session's CSRF token, compared in constant time. A body is at most 1 MiB.
- **Headers on every response:** a Content-Security-Policy with nothing inline (`default-src 'none';
  script-src 'self'; style-src 'self'; …`), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: same-origin`, same-origin COOP and CORP, a Permissions-Policy that turns off every
  device API, and `Cache-Control: no-store` on pages.
- **Everything is embedded.** Tabler, its icons and the Inter font are vendored and served from the binary at
  `/assets/<hash>/…`, immutable; a page makes no request beyond this server.
- **The log** records each change, and with `--verbose` each page view, by path only, never the query.
- **The server's limits:** headers in 10 seconds, a body in 30, idle connections closed after 60 seconds,
  64 KiB of headers. There is no overall write timeout, so the events stream stays open; each of its writes
  has its own deadline, and at most 8 streams are open at once.

## The old secrets page

The API listener's own page at `/ui/`, on a loopback `server.listen`, still works as before, and is
superseded by this UI's Secrets page ([serve](serve.md#the-secrets-page)).

---

[← Docs index](../../README.md#documentation)
