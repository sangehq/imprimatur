# `impr init`

`impr init` sets a Go project up for [`impr build`](build.md): its release targets, and its build output
kept out of git, as the PowerShell line's `impr init` did for GoReleaser.

## Command

```bash
impr init                         # the only program under cmd/, from anywhere in the repository
impr init --main ./cmd/tool       # choose the program when the module has several
impr init --force                 # write build/targets.txt again (your edits to it are lost)
```

`--module DIR` and `--repo-root DIR` name the module and the repository as for `impr build`.

## What it writes

- **`build/targets.txt`**, with the targets the PowerShell line's GoReleaser template built: Windows amd64,
  386 and arm64; Linux amd64, arm64, 386 and armv7; macOS amd64 and arm64. `impr build` reads it when
  `--targets` is not given. A file already there is kept, and `impr init` stops, unless `--force`.
- **`.gitignore`** lines, under `# impr build output`, when the project has a `.gitignore` or is a git work
  tree: `build/*/` (the per-OS folders and archives), `build/build-manifest.json`, and
  `zz_impr_winres_windows_*.syso` (the Windows resource file a cut-short build can leave). Lines already
  there are not added again.
- **Nothing through a link.** A `build` folder, `build/targets.txt` or `.gitignore` that is a symbolic
  link is refused, with or without `--force`, and each file is written to a temporary file beside it and
  renamed into place, so a link that appears meanwhile is replaced rather than followed.
- **Not `.goreleaser.yaml`.** impr builds with `go build` itself (design ID-09), so a GoReleaser config would
  never be read, and impr does not run a repository's GoReleaser config (threat I-06).

## The program

With one program under `cmd/`, impr picks it. With several, `impr init` stops and lists the `--main` line for
each; the line it prints at the end, `impr build --main ./cmd/NAME`, is the build to run. With none, it says
so: a library has nothing to build.

When sange drives impr it sets the project up itself; `impr init` is for running impr on its own.

---

[← Docs index](../../README.md#documentation)
