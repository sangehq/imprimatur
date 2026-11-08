## Summary

<!-- What this changes and why. Link the issue it closes. -->

Closes #

## Checks

- [ ] `make check` is green (gofmt, vet, lint, `go test -race`, guard tests).
- [ ] New behaviour has tests; a new guard was proven red once.
- [ ] External programs run only through `internal/execx`, by absolute path, never through a shell.
- [ ] Signing still fails closed: no fallback certificate, no first-match identity.
- [ ] No certificate, key, password or token is written into a test, fixture or doc; test values are
      generated at run time.
- [ ] The matching `docs/` page is updated, and `CHANGELOG.md` has an `[Unreleased]` entry where the change
      is user-visible.
