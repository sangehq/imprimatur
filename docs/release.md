# Release

A release publishes impr's binaries on imprimatur's GitHub release and nowhere
else: there is no package-manager, image or `go install` path. No version has
been released yet.

## How a release runs

`.github/workflows/release.yml` calls `simtabi/.github`'s shared
`go-release.yml`, pinned to a commit, which runs GoReleaser with
`src/.goreleaser.yaml`. It starts in one of two ways:

```bash
# push the tag: this builds and publishes vX.Y.Z
git -C ~/Artisan/projects/opensource/sange/packages/imprimatur push origin vX.Y.Z

# or build a tag that is already on GitHub
gh workflow run release.yml --repo sangehq/imprimatur -f tag=vX.Y.Z
```

- Pushing a `vX.Y.Z` (or `vX.Y.Z-rc.N`) tag publishes. Push one only for code
  that is ready to ship; test builds use a pre-release tag.
- The run refuses a final version whose `CHANGELOG.md` has no `## [X.Y.Z]`
  section; that section becomes the release body.
- The release carries one bare binary per line of `build/targets.txt`, named
  `impr_{os}_{arch}[.exe]` (`macos`, never `darwin`; `armv7` for 32-bit ARM),
  and `checksums.txt` with bare file names:

  ```bash
  sha256sum -c --ignore-missing checksums.txt
  ```

- The shared workflow also pushes `src/vX.Y.Z` on the same commit, the tag Go
  resolves the module in `src/` through. It matches no release trigger.
- Build provenance is not attested: GitHub Free refuses attestations on a
  private repository, so the shared workflow skips that step here.

`src/internal/guardtest` fails if `release.yml` gains a branch or schedule
trigger, stops calling the pinned shared workflow, or stops passing the tag;
if `src/.goreleaser.yaml` gains a block that publishes anywhere else or writes
into `build/`; and if its targets drift from `build/targets.txt`.

Check the config locally, writing only to the ignored `.cache/goreleaser/`:

```bash
goreleaser check --config src/.goreleaser.yaml
goreleaser release --snapshot --clean --skip=sign,publish,sbom --config src/.goreleaser.yaml
```

## Versions and tags

The first tag after the move to `sangehq` is `v1.8.0`, matching the PowerShell
line's CHANGELOG (SD-070). Tags are final: never moved, deleted or reused, and
a bad version is retracted, not replaced.

---

[← Docs index](../README.md#documentation)
