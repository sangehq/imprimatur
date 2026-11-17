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
