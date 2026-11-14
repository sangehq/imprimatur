# `impr build`

`impr build` cross-compiles a Go module into the estate's `build/` layout. It writes the build manifest
`impr sign` signs, bound to the git commit and tree.

## Usage

```bash
impr build                                   # targets from build/targets.txt, else this host
impr build --targets linux/amd64,windows/arm64,darwin/arm64
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

## What it writes

```
build/linux/tool_linux_amd64
build/windows/tool_windows_arm64.exe
build/macos/tool_macos_arm64
build/build-manifest.json     sange.build-manifest/v1: commit, tree, version, each file's sha256 and size
```

## Safety

- **How Go runs.** impr runs `go build -trimpath` itself, with CGO off, the user's go env file off
  (`GOENV=off`), no workspace (`GOWORK=off`), the local toolchain only, and `-mod=readonly`. It never
  runs a repository's GoReleaser config or its hooks, so nothing the repository controls runs on the
  signing host.
- **Allowed git commands.** impr runs `go build` only, and git only as `rev-parse HEAD`,
  `rev-parse HEAD^{tree}`, `remote get-url origin`, and `status` with fsmonitor off.
- **Version.** `--version` must be a semantic version, because it is stamped through `-ldflags`, and
  anything else could add linker flags.
- **Paths.** `--main` must be a path inside the module.
- **Uncommitted changes.** A work tree with uncommitted changes to tracked files is refused, because its
  binaries would not match the commit the manifest names. `--allow-dirty` builds anyway and records
  `dirty: true`; [`impr release`](release.md) never allows it.
- **`--clean`.** It removes only this binary's earlier files under `build/{os}/`, never anything else.
- **Never tags, pushes or publishes.**

Windows version resources (the PowerShell toolkit's go-winres step) are not built.

---

[← Docs index](../../README.md#documentation)
