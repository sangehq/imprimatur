# `make/impr.mk`

`make/impr.mk` turns impr's commands into Make targets, so a project's own Makefile can build, release,
sign and verify through them. It needs GNU make.

## Use it

```make
include path/to/imprimatur/make/impr.mk
```

```bash
make impr-sign PROFILE=acme-release PURPOSE=release MANIFEST=build/build-manifest.json
make impr-verify PROFILE=acme-release SIGNED=build/impr-manifest.json STRICT=1
make impr-doctor JSON=1
make impr-release PROFILE=acme-release PURPOSE=release VERSION=v1.4.0 ARCHIVES=1
```

## Targets

| Target | Runs | Alias |
| --- | --- | --- |
| `impr-sign` | `impr sign` (needs `PROFILE`, `PURPOSE`, `MANIFEST`) | `impr-s` |
| `impr-verify` | `impr verify` (needs `PROFILE`; `SIGNED` or `FILE`) | `impr-v` |
| `impr-doctor` | `impr doctor` | `impr-d` |
| `impr-cert` | `impr cert list` | |
| `impr-profiles` | `impr profile list` | |
| `impr-rules` | `impr rules` (needs `REQUEST`) | |
| `impr-events`, `impr-events-verify` | `impr events tail`, `impr events verify` | |
| `impr-build` | `impr build [VERSION]` (`MAIN`, `TARGETS`, `ARCHIVES`) | `impr-b` |
| `impr-release` | `impr release [VERSION]` (needs `PROFILE`, `PURPOSE`; `PLATFORMS`, `REPO`, build variables) | `impr-r` |
| `impr-config` | `impr config show` | |
| `impr-config-get`, `impr-config-set` | `impr config get KEY`, `impr config set KEY VALUE` | |
| `impr-completion`, `impr-completion-uninstall` | `impr completion install/uninstall [SHELLS]` (default: `$SHELL`) | |
| `impr-install`, `impr-uninstall` | `impr install`, `impr uninstall` (`DIR`, `FORCE`) | |
| `impr-path` | `impr path` | |
| `impr-companion`, `impr-version`, `impr-help` | the commands of those names | |

Every target is prefixed `impr-`, so it never clashes with the project's own targets.

## Variables

- **From git.** `COMMIT`, `TREE` and `REPO` default to `git rev-parse HEAD`, `git rev-parse HEAD^{tree}` and
  `git remote get-url origin`, so a signing run is bound to what is checked out.
- **Defaults.** `ROOT` defaults to the current folder, and `IMPR` to `impr` on PATH.
- **Switches.** `STRICT=1` and `JSON=1` add `--strict` and `--json`.
- **Anything else.** `ARGS` passes any other option through.
- **Required variables.** A missing required variable stops make with a message naming it.
- **Tested.** Each target is run with `IMPR=echo` in the test suite, and every `$(IMPR) CMD` must name a
  command impr has.

---

[← Docs index](../../README.md#documentation)
