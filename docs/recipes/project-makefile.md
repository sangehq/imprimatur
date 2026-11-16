# Sign and verify from a project's Makefile

Give a project `make` targets for signing and verifying, without writing the impr command lines
yourself.

```make
include path/to/imprimatur/make/impr.mk

release: build
	$(MAKE) impr-sign PROFILE=acme-release PURPOSE=release MANIFEST=build/build-manifest.json
	$(MAKE) impr-verify PROFILE=acme-release SIGNED=build/impr-manifest.json STRICT=1
```

Pin the repository's own rules alongside it, so nobody signs it with another profile:

```json
{"schema": "imprimatur.project/v1", "profile": "acme-release", "strict": true, "requireRepo": true}
```

saved as `.imprimatur/project.json`.

Details: [`make/impr.mk`](../tools/make.md), [`.imprimatur/project.json`](../tools/project.md).

---

[← Docs index](../../README.md#documentation)
