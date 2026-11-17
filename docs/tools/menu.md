# `impr menu`

`impr menu` is an interactive menu for a person at a terminal. Running `impr` with no arguments in a terminal
opens it too.

## Entries

| Key | Runs |
| --- | --- |
| `d` | `impr doctor` |
| `p` | `impr profile list` |
| `c` | `impr cert list` |
| `b` | `impr build` (asks for the repository and version) |
| `r` | `impr release` (guided, below; asks for `yes`) |
| `s` | sign a build manifest (guided, below) |
| `v` | verify a signed manifest (guided) |
| `e` | `impr events tail --limit 20` |
| `g` | `impr config path` |
| `w`, `k` | `impr webhooks list`, `impr hooks list` |
| `i` | `impr path` |
| `n` | `impr install` |
| `h`, `q` | help, quit |

Every entry runs the same command the CLI does, so nothing is reachable only through the menu.

## Signing from the menu

The menu asks for the following, in order:

1. the build manifest;
2. the signing profile (the default is offered);
3. the purpose;
4. the repository, for a release;
5. the signing root.

Then it shows the manifest's commit, tree and file count, and signs only after you type `yes`. The commit and
tree come from the manifest you just confirmed. The run is `impr sign … --strict`, exactly as on the command
line.

## Releasing from the menu

`r` asks for the repository (default `.`), the version (default the latest `v*` tag plus `-snapshot`), the
signing profile (the default is offered), the purpose and the platforms (default the profile's). It shows
what it will do and runs `impr release` only after you type `yes`. A release never tags, pushes or publishes.

## Scripts and sange

The menu opens only when stdin is a terminal and `CI` is unset. Otherwise (a pipe, CI, or sange calling impr)
`impr` with no arguments prints the usage text and exits 1, as before.

From the PowerShell toolkit's menu, build (`b`), release (`r`) and install (`n`) are ported. The project
dashboard, the project picker and its remembered last project, `o` (open the build folder), the init and
rules entries and the number keys are not (design ID-18); project setup (init) moved to sange.

---

[← Docs index](../../README.md#documentation)
