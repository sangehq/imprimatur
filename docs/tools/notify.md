# `impr notify`

Desktop notifications for what a person should act on: a failed run, a hook's veto, and a
certificate that is about to expire or has expired.

```bash
impr notify send --title "Release signed" --body "acme/tool v1.2.3"   # one notification, by hand
impr notify ping                                                       # through a running impr serve
impr notify doctor                                                     # which notifier this host uses, and why not
```

impr shows notifications through go-notifykit, the library every Go program in the estate shares.
They appear under impr's own name and icon (`sh.sange.imprimatur`): on macOS through a helper app
impr builds, signs ad hoc and registers on first use, on Linux through `notify-send`, and on Windows
as a toast.

## What is shown

| Event | Notification |
| --- | --- |
| `signing.run.failed`, `verification.run.failed` | the first line of the reason, and `impr events tail` |
| `hook.vetoed` | the phase and the hook's reason |
| `cert.expiring` | the profile, platform and signer, its expiry date, and `impr cert list` |
| `cert.expired` | the same, once |

- **One per event.** Repeats of one group within 30 seconds are suppressed.
- **Never in tests or CI.** go-notifykit shows nothing under `go test` or when `CI` is set.
  `IMPR_NOTIFY_DESKTOP=0` turns it off for one shell.
- **Never a failure.** A notification that cannot be shown never fails the command that raised it.

## Certificate expiry

`impr cert list` checks every certificate and key whose expiry it can read. Three things run it for
you, and you can use any of them:

- **`impr serve`** checks every six hours while it runs.
- **A daily scheduled check.** `impr cert install-check --print` prints a systemd timer, a launchd job or
  a Windows task that runs `impr cert list` once a day, and how to install it. impr installs nothing
  itself.
- **On every command.** With `notify.checkOnCommand` on, any other impr command runs the check, at most
  once a day. It is off by default, because it runs the certificate tools (gpg, `security`, certutil)
  when nobody asked for them. sange's own calls (`companion`, `profile`, `cert`) never trigger it.

 It raises `cert.expiring` once at each threshold a
certificate crosses, and `cert.expired` once. The events go to the log, hooks and webhooks as well
as the desktop. impr records which threshold it last raised for each certificate, in
`<state>/notify/expiry.json`, so running `cert list` every hour does not repeat a warning. A renewed
certificate (a new expiry date) starts again.

## Configuration

```json
"notify": {"desktop": true, "certExpiryDays": [30, 14, 7], "checkOnCommand": false}
```

| Key | Meaning |
| --- | --- |
| `notify.desktop` | show desktop notifications on this machine; on unless set `false` |
| `notify.certExpiryDays` | the warning thresholds, in days (1 to 365); default 30, 14 and 7 |
| `notify.checkOnCommand` | run the expiry check after other commands, at most once a day; off unless set `true` |

The system config can lock `notify`.

---

[← Docs index](../../README.md#documentation)
