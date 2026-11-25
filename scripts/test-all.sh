#!/usr/bin/env bash
# Every gate CI runs, in one command, stopping at the first that fails:
# gofmt, go vet, golangci-lint, the whole suite (unit, CLI, guards), and the
# end-to-end tests through the built impr binary, counted so a run that
# quietly skips them fails.
#
#   scripts/test-all.sh            from the repository root (or: make test-all)
set -euo pipefail
cd "$(dirname "$0")/.."

E2E_MIN=${E2E_MIN:-9}

echo "== vendored web assets"
# Every vendored file matches MANIFEST.sha256 (the web package's test checks
# the same, embedded; this one reads the files on disk).
(cd src/internal/web/assets/vendor && shasum -a 256 -c --quiet MANIFEST.sha256)
echo "vendored: $(grep -c . src/internal/web/assets/vendor/MANIFEST.sha256) files match MANIFEST.sha256"

echo "== web asset versions against sange and authama"
# The three sange projects vendor one Tabler set (owner, 2026-11-25). Each
# sibling is read from its origin/main, never its working tree. sange drift
# fails, except Bootstrap, which sange builds at 5.3.9 from source while
# tabler.min.js bundles 5.3.8; authama drift is a warning until its own
# follow-up pull request.
ours=$(grep -E '^[@a-z]' src/internal/web/assets/vendor/TABLER_VERSION | sed 's#^@tabler/icons-sprite #@tabler/icons #' | sort)
pins=$(printf '%s\n' "$ours" | grep -c .)
if [ "$pins" -lt 5 ]; then echo "read $pins pins from TABLER_VERSION, want at least 5"; exit 1; fi
sib=..
tmp=$(mktemp -d "${TMPDIR:-/tmp}/impr-sib.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
printf '%s\n' "$ours" >"$tmp/ours"
# compare FILE writes the lines that differ from ours to $tmp/diff; a diff
# that cannot run (status 2) fails the gate instead of reading as no drift.
compare() {
  local st=0
  diff "$tmp/ours" "$1" >"$tmp/diff" || st=$?
  if [ "$st" -gt 1 ]; then echo "diff failed on $1"; exit 1; fi
}
if git -C "$sib/sange" rev-parse --verify -q origin/main >/dev/null 2>&1; then
  theirs=$(git -C "$sib/sange" show origin/main:src/internal/web/vendor.md |
    sed -nE 's/^\| `([^`]+)` \| ([0-9][^ |]*) \|.*/\1 \2/p' | sort)
  n=$(printf '%s\n' "$theirs" | grep -c . || true)
  if [ "$n" -lt 5 ]; then echo "read $n pins from sange's vendor.md, want at least 5"; exit 1; fi
  printf '%s\n' "$theirs" >"$tmp/sange"
  compare "$tmp/sange"
  drift=$(grep '^[<>]' "$tmp/diff" | grep -v ' bootstrap ' || true)
  if [ -n "$drift" ]; then echo "sange vendors a different set (< imprimatur, > sange):"; echo "$drift"; exit 1; fi
  echo "sange: same set ($n pins; Bootstrap 5.3.8 here, 5.3.9 there, as documented)"
else
  echo "skipped: no sange checkout with origin/main at $sib/sange"
fi
if git -C "$sib/authama" rev-parse --verify -q origin/main >/dev/null 2>&1; then
  theirs=$(git -C "$sib/authama" show origin/main:src/internal/web/assets/vendor/TABLER_VERSION |
    grep -E '^[@a-z]' | sed 's#^@tabler/icons-sprite #@tabler/icons #' | sort)
  printf '%s\n' "$theirs" >"$tmp/authama"
  compare "$tmp/authama"
  drift=$(grep '^[<>]' "$tmp/diff" || true)
  if [ -n "$drift" ]; then
    echo "warning: authama vendors a different set until its follow-up pull request (< imprimatur, > authama):"
    echo "$drift"
  else
    echo "authama: same set"
  fi
else
  echo "skipped: no authama checkout with origin/main at $sib/authama"
fi

echo "== gofmt"
out=$(gofmt -l src/cmd src/internal)
if [ -n "$out" ]; then echo "not gofmt-clean:"; echo "$out"; exit 1; fi

echo "== go vet"
go -C src vet ./...

echo "== golangci-lint"
(cd src && golangci-lint run ./...)

echo "== go test (unit, CLI, guards)"
go -C src test -count=1 ./...

echo "== end-to-end (the built impr)"
e2e=$(go -C src test -count=1 -v ./internal/e2e/ 2>&1) || { echo "$e2e"; exit 1; }
passed=$(printf '%s\n' "$e2e" | grep -c '^--- PASS: TestE2E' || true)
skipped=$(printf '%s\n' "$e2e" | grep -c '^--- SKIP: TestE2E' || true)
echo "end-to-end: $passed passed, $skipped skipped"
if [ "$passed" -lt "$E2E_MIN" ]; then
  echo "end-to-end: $passed passed, want at least $E2E_MIN (a skip is not a pass)"
  exit 1
fi
echo "== all gates green"
