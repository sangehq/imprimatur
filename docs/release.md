# Release

Binaries are not released yet: imprimatur is git only until the owner approves
a release, and users build from source.

## How a release runs, when one is approved

`.github/workflows/release.yml` has `workflow_dispatch` as its only trigger,
with a required `confirm` input. Its first step refuses to run unless `confirm`
is `release-go` and the run is on a `refs/tags/v[0-9]*` tag. The one command:

```bash
gh workflow run release.yml --repo sangehq/imprimatur --ref vX.Y.Z -f confirm=release-go
```

- Pushing a `vX.Y.Z` tag publishes nothing.
- `vX.Y.Z` must be a real tag already on GitHub.
- The command publishes for real: it cross-builds `build/targets.txt`, checks
  `build/checksums.txt`, and creates a GitHub release with the binaries, the
  checksums and that version's `CHANGELOG.md` section. Run it only for a
  version that was approved.

`src/internal/guardtest` fails if `release.yml` gains a `push`, `schedule`,
`pull_request` or `release` trigger, or loses the confirmation.

## Versions and tags

The first tag after the move to `sangehq` is `v1.8.0`, matching the PowerShell
line's CHANGELOG (SD-070). Tags are final: never moved, deleted or reused, and
a bad version is retracted, not replaced. The module lives in `src/`, so Go
resolves it only through a `src/vX.Y.Z` tag on the same commit; the release
workflow does not create that alias tag yet, so it is pushed alongside `vX.Y.Z`.

---

[← Docs index](../README.md#documentation)
