# `impr release`

`impr release` builds a Go module, signs the build with a profile, and verifies the result, all in one step.

## Usage

```bash
impr release --profile acme-release --purpose release
impr release --profile dev --purpose internal --platforms checksums --targets linux/amd64
impr release v1.4.0 --profile acme-release --purpose release      # VERSION, as in impr build
```

`impr release` runs, in order:

1. [`impr build`](build.md), with every build option available.
2. `impr sign --manifest build/build-manifest.json --commit … --tree … --profile … --purpose … --strict`.
   The repository comes from `git remote get-url origin` unless `--repo` names it.
3. `impr verify --signed build/impr-manifest.json --manifest build/build-manifest.json --strict`.

It stops at the first failure and uses that step's exit code. With `--archives`, it then packs the
signed files into `build/archives/` ([archives](build.md#archives)).

With `--json`, stdout holds exactly one document:

```json
{"contract": 1, "ok": true, "build": {…impr build --json…}, "sign": {…impr sign --json…}, "verify": {…impr verify --json…}}
```

On a failure `ok` is false, `step` names the step that failed (`sign` or `verify`), and the steps after
it are absent. A build failure prints the ordinary error document.

## What it never does

- It never builds from uncommitted changes; `--allow-dirty` is refused.
- It never tags, pushes, uploads or publishes. What to do with the signed files is yours: attach them
  to a GitHub release, or hand them to sange's release pipeline.
- It never weakens a profile. The purpose, `allowedRepos` and every pin are checked exactly as
  [`impr sign`](sign.md) checks them, so a test profile can never sign a release.

---

[← Docs index](../../README.md#documentation)
