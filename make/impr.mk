# impr Make targets (GNU make). Include this file in a project's Makefile:
#
#   include path/to/imprimatur/make/impr.mk
#   make impr-sign PROFILE=acme-release PURPOSE=release MANIFEST=build/build-manifest.json
#
# Every target is prefixed impr- so it never clashes with the project's own,
# and runs the impr command of the same name. Short aliases match the CLI's:
# impr-s (sign), impr-v (verify), impr-d (doctor), impr-b (build),
# impr-r (release).
#
# Variables (all optional unless a target says so):
#   IMPR       the impr binary (default: impr on PATH)
#   PROFILE    --profile: the signing profile (sign, verify)
#   PURPOSE    --purpose: release | test | internal (sign; required)
#   MANIFEST   --manifest: the build manifest (sign; required)
#   SIGNED     --signed: impr-manifest.json to verify (verify)
#   ROOT       --root: the signing root (default: the current folder)
#   COMMIT     --commit (default: git rev-parse HEAD)
#   TREE       --tree (default: git rev-parse HEAD^{tree})
#   REPO       --repo (default: git remote get-url origin)
#   PLATFORMS  --platforms, comma-separated (default: the profile's)
#   FILE       loose files to verify, space-separated (verify, instead of SIGNED)
#   REQUEST    --request: a rules request (rules)
#   VERSION    the version to build (build, release; default: the latest v* tag + -snapshot)
#   MAIN       --main: the main package (build, release)
#   TARGETS    --targets, comma-separated (build, release)
#   ARCHIVES=1 --archives (build, release)
#   KEY, VALUE the config key and value (config-get, config-set)
#   SHELLS     shells to install completion for, or all (completion; default: $SHELL)
#   DIR        --dir: the install folder (install, uninstall)
#   FORCE=1    --force (install)
#   STRICT=1   --strict        JSON=1  --json
#   ARGS       any other impr options

IMPR      ?= impr
PROFILE   ?=
PURPOSE   ?=
MANIFEST  ?=
SIGNED    ?=
ROOT      ?= $(CURDIR)
COMMIT    ?= $(shell git rev-parse HEAD 2>/dev/null)
TREE      ?= $(shell git rev-parse 'HEAD^{tree}' 2>/dev/null)
REPO      ?= $(shell git remote get-url origin 2>/dev/null)
PLATFORMS ?=
FILE      ?=
REQUEST   ?=
STRICT    ?=
JSON      ?=
ARGS      ?=
VERSION   ?=
MAIN      ?=
TARGETS   ?=
ARCHIVES  ?=
KEY       ?=
VALUE     ?=
SHELLS    ?=
DIR       ?=
FORCE     ?=

_impr_common = $(if $(STRICT),--strict) $(if $(JSON),--json) $(ARGS)
_impr_need   = $(if $($(1)),,$(error $(1) is required: make $@ $(1)=...))
_impr_build  = --repo-root "$(ROOT)" $(if $(MAIN),--main "$(MAIN)") $(if $(TARGETS),--targets "$(TARGETS)") $(if $(ARCHIVES),--archives)

.PHONY: impr-sign impr-s impr-verify impr-v impr-doctor impr-d impr-cert impr-profiles impr-rules impr-events impr-events-verify impr-companion impr-version impr-help \
	impr-build impr-b impr-release impr-r impr-config impr-config-get impr-config-set impr-completion \
	impr-completion-uninstall impr-install impr-uninstall impr-path

impr-sign:
	$(call _impr_need,PROFILE)$(call _impr_need,PURPOSE)$(call _impr_need,MANIFEST)
	$(IMPR) sign --manifest "$(MANIFEST)" --commit "$(COMMIT)" --tree "$(TREE)" --profile "$(PROFILE)" --purpose "$(PURPOSE)" \
	  --root "$(ROOT)" $(if $(REPO),--repo "$(REPO)") $(if $(PLATFORMS),--platforms "$(PLATFORMS)") $(_impr_common)
impr-s: impr-sign

impr-verify:
	$(call _impr_need,PROFILE)
	$(IMPR) verify --profile "$(PROFILE)" --root "$(ROOT)" $(if $(SIGNED),--signed "$(SIGNED)") $(if $(MANIFEST),--manifest "$(MANIFEST)") \
	  $(_impr_common) $(if $(FILE),-- $(FILE))
impr-v: impr-verify

impr-doctor:
	$(IMPR) doctor $(_impr_common)
impr-d: impr-doctor

impr-cert:
	$(IMPR) cert list $(_impr_common)

impr-profiles:
	$(IMPR) profile list $(_impr_common)

impr-rules:
	$(call _impr_need,REQUEST)
	$(IMPR) rules --request "$(REQUEST)" $(_impr_common)

impr-events:
	$(IMPR) events tail $(_impr_common)

impr-events-verify:
	$(IMPR) events verify $(_impr_common)

impr-companion:
	$(IMPR) companion info $(_impr_common)

impr-version:
	$(IMPR) version

impr-help:
	$(IMPR) help

impr-build:
	$(IMPR) build $(_impr_build) $(_impr_common) $(VERSION)
impr-b: impr-build

impr-release:
	$(call _impr_need,PROFILE)$(call _impr_need,PURPOSE)
	$(IMPR) release $(_impr_build) --profile "$(PROFILE)" --purpose "$(PURPOSE)" $(if $(REPO),--repo "$(REPO)") \
	  $(if $(PLATFORMS),--platforms "$(PLATFORMS)") $(_impr_common) $(VERSION)
impr-r: impr-release

impr-config:
	$(IMPR) config show $(_impr_common)

impr-config-get:
	$(call _impr_need,KEY)
	$(IMPR) config get "$(KEY)"

impr-config-set:
	$(call _impr_need,KEY)$(call _impr_need,VALUE)
	$(IMPR) config set "$(KEY)" '$(VALUE)'

impr-completion:
	$(IMPR) completion install $(SHELLS)

impr-completion-uninstall:
	$(IMPR) completion uninstall $(SHELLS)

impr-install:
	$(IMPR) install $(if $(DIR),--dir "$(DIR)") $(if $(FORCE),--force)

impr-uninstall:
	$(IMPR) uninstall $(if $(DIR),--dir "$(DIR)")

impr-path:
	$(IMPR) path $(_impr_common)
