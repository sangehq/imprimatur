# `impr secret`

Stores a signing secret, such as an App Store Connect key, in this computer's secret store, and records only
its reference in `~/.config/imprimatur/.env`.

```bash
impr secret set IMPR_NOTARY_KEY --file ~/Downloads/AuthKey_ABC123.p8   # from a file
printf '%s' "$VALUE" | impr secret set IMPR_TOKEN                        # from stdin
impr secret list                                                         # names and references, never values
```

A profile then names the secret as `env://NAME`, for example
`--set platforms.macos.notary.apiKeyRef=env://IMPR_NOTARY_KEY`.

## Where a secret goes

impr tries the operating system's own store first (owner decision ID-33):

| Host | Store | Reference |
|---|---|---|
| macOS | the login keychain, service `imprimatur` | `secret://NAME` |
| Linux, FreeBSD | the Secret Service (`secret-tool`), service `imprimatur` | `secret://NAME` |
| Windows | the Credential Manager, target `imprimatur/NAME` | `secret://NAME` |
| any other, or when the store refuses | a 0600 file in `~/.config/imprimatur/secrets/` (0700) | `file://PATH` |

The value reaches the store's tool on stdin, never on a command line, where other processes could read it.
impr never prints it, and `impr secret list` shows only names and references.

On macOS the keychain path is checked against the real login keychain by an opt-in test, which writes a
throwaway `IMPR_SELFTEST` item, reads it back, deletes it and checks it is gone:

```bash
cd src && IMPR_LIVE_KEYCHAIN=1 go test ./internal/secrets/ -run TestLiveKeychainRoundTrip -count=1 -v
```

## The config folder

```text
~/.config/imprimatur/          0700
  .env                         0600  NAME=reference lines, never a value
  config.json                        the configuration
  profiles/*.json              0700  signing profiles (references only)
  secrets/                     0700  a secret's file where no OS store exists
```

impr creates the folder, `profiles/`, `secrets/` and an empty `.env` owner-only the first time it needs them,
and never loosens an existing one. When the variable `NAME` is not set, `env://NAME` reads the `.env` line and
resolves its reference once (owner decision ID-32). A `.env` line holding a value, or another `env://`, is
refused. [`impr doctor`](doctor.md) reports a `.env` or `secrets/` others can read, a `.env` holding a value,
and a profile file others can write.

## Rules

- **Names** are `A-Z`, `0-9` and `_`, starting with a letter, up to 63 characters.
- **Values** come from `--file` or stdin, up to 64 KiB. A value is never read from a prompt, where it would
  show on screen.
- **Audit.** `impr secret set` is recorded in the audit trail by name only.

## The secrets page

[`impr serve`](serve.md#the-secrets-page) serves the same thing as a local page, for adding a key without a
terminal.

---

[← Docs index](../../README.md#documentation)
