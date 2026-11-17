# `impr build`

`impr build` cross-compiles a Go module into the estate's `build/` layout. It writes the build manifest
`impr sign` signs, bound to the git commit and tree.

## Usage

```bash
impr build                                   # targets from build/targets.txt, else this host
impr build --targets linux/amd64,windows/arm64,darwin/arm64
impr build v1.2.3                            # stamps main.version, as the PowerShell build did
impr build --version v1.2.3 --version-var github.com/acme/tool/src/internal/cli.version
impr build --main ./cmd/tool --module src --clean --json
```

| Option | Default |
| --- | --- |
| `--repo-root` | the current folder; `build/` is written here |
| `--module` | `src` when it holds a `go.mod`, else the repository root |
| `--main` | the only package under `cmd/` |
| `--binary` | the main package's folder name |
| `--targets` | `build/targets.txt` (`GOOS GOARCH [GOARM]` per line), else this host |
| `VERSION` or `--version` | the latest `v*` tag plus `-snapshot` (`v1.4.0-snapshot`), else `v0.0.0-snapshot` with a warning |
| `--version-var` | `main.version` |
| `--archives` | off; see [Archives](#archives) |

`VERSION` and `--version` are the same setting; give one, or both with the same value. `impr build` refuses
`--profile`, `--purpose`, `--platforms` and `--repo`: it only builds, and signing is
[`impr release`](release.md)'s job.

## What it writes

```
build/linux/tool_linux_amd64
build/windows/tool_windows_arm64.exe
build/macos/tool_macos_arm64
build/build-manifest.json     sange.build-manifest/v1: commit, tree, version, each file's sha256 and size
```

## Archives

`--archives` adds what the PowerShell release's GoReleaser run made:

```
build/macos/tool_macos_universal      macOS only, with both darwin targets: lipo joins amd64 and arm64;
                                      it is in the build manifest, so impr sign signs it like the others
build/archives/tool_linux_amd64.tar.gz
build/archives/tool_windows_amd64.zip  a .zip for each Windows binary, a .tar.gz for every other
build/archives/checksums.txt           sha256 of each archive, by bare name
```

Each archive holds the binary under its own name, plus `LICENSE` and `README.md` when the repository
has them. Names carry no version, as the estate build layout requires, and entries carry a fixed
timestamp, so the same files make the same archive. `impr build --archives` packs the files as built
(unsigned); [`impr release --archives`](release.md) packs them after signing and verifying.

## Windows version information

Every Windows binary gets version information, an application manifest and, optionally, an icon. These
are what Explorer's Details tab shows, and what AppLocker and WDAC rules match on. impr writes these
resources itself, with no go-winres.

```bash
impr build --version v1.4.2 --product "Acme Tool" --company "Acme Ltd" --copyright "© 2026 Acme Ltd" \
  --description "Signs things" --icon assets/tool.ico
```

| Option | Default |
| --- | --- |
| `--product` | the binary name |
| `--company`, `--description`, `--copyright` | empty |
| `--icon FILE.ico` | none |
| `--no-winres` | embed nothing |

- **Versions.** `ProductVersion` is `--version` as given (`v1.4.2-rc.1`). `FileVersion` is its numeric
  part as `a.b.c.d` (`1.4.2.0`).
- **The manifest.** It runs the program as the invoking user (`asInvoker`), declares Windows 7 to 11,
  and allows long paths.
- **`winres/winres.json`.** When the main package has one (go-winres's file), its `RT_VERSION` strings
  and its first `RT_GROUP_ICON` (`.ico` only) are used. The build's version still sets the versions.
  Manifest settings in it are not applied, and impr says so. A PNG icon is refused: convert it to `.ico`.
- **The project's own `.syso`.** When the main package already carries one for the target (say
  `rsrc_windows_amd64.syso` from go-winres), impr adds nothing and says so, because two resource sections
  cannot be linked.
- **How.** For each Windows target impr writes `zz_impr_winres_windows_<arch>.syso` into the main package,
  runs `go build`, and removes it. The work tree is never left changed. amd64, 386 and arm64 are
  supported; 32-bit ARM gets no version information.

## Safety

- **How Go runs.** impr runs `go build -trimpath` itself, with CGO off, the user's go env file off
  (`GOENV=off`), no workspace (`GOWORK=off`), the local toolchain only, and `-mod=readonly`. It never
  runs a repository's GoReleaser config or its hooks, so nothing the repository controls runs on the
  signing host.
- **Allowed git commands.** impr runs `go build` only, and git only as `rev-parse HEAD`,
  `rev-parse HEAD^{tree}`, `remote get-url origin`, `describe --tags --abbrev=0 --match v[0-9]*` (the
  snapshot version; the estate's `src/v*` module tags never match), and `status` with fsmonitor off.
- **Version.** The version must be a semantic version, because it is stamped through `-ldflags`, and
  anything else could add linker flags. The Go linker ignores `-X` for a variable that does not exist,
  so impr checks every binary for the version's bytes: a version you gave that is not in the binary
  fails the build and names the variable; a snapshot version that is not stamped only warns.
- **Paths.** `--main` must be a path inside the module.
- **Uncommitted changes.** A work tree with uncommitted changes to tracked files is refused, because its
  binaries would not match the commit the manifest names. `--allow-dirty` builds anyway and records
  `dirty: true`; [`impr release`](release.md) never allows it.
- **`--clean`.** It removes only this binary's earlier files under `build/{os}/`, never anything else.
- **Never tags, pushes or publishes.**

---

[← Docs index](../../README.md#documentation)
