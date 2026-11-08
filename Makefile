# imprimatur - dev front door. Run from the repository root:  make <target>
#
# The Go module is src/ (go.mod lives there), so every go command runs through
# `go -C src`. Build output lands in build/ at the root, one folder per OS and
# nothing else:
#
#   make build   build/{host-os}/impr
#   make cross   build/{os}/impr_{os}_{arch}[.exe] + build/checksums.txt
#
# The OS folder is macos, never darwin. Releases are on hold: nothing here
# publishes.
MODULE    := src
GO        := go -C $(MODULE)
HOST_GOOS := $(shell go env GOOS 2>/dev/null)
HOST_OS   := $(if $(filter darwin,$(HOST_GOOS)),macos,$(HOST_GOOS))
EXE       := $(if $(filter windows,$(HOST_GOOS)),.exe,)
BIN       := build/$(HOST_OS)/impr
PKG       := ./cmd/impr
OS_DIRS   := build/macos build/linux build/windows build/freebsd build/archives build/checksums.txt

export GOPRIVATE ?= github.com/sangehq/*
export GONOSUMDB ?= github.com/sangehq/*

VERSION := $(shell git describe --tags --match 'v[0-9]*' --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
CLI_PKG := github.com/sangehq/imprimatur/src/internal/cli
LDFLAGS := -s -w -X $(CLI_PKG).version=$(VERSION) -X $(CLI_PKG).commit=$(COMMIT) -X $(CLI_PKG).date=$(DATE)

GOFILES_DIRS := $(MODULE)/cmd $(MODULE)/internal

.PHONY: help build test vet fmt fmt-check lint check cross clean

help: ## list targets
	@grep -E '^[a-zA-Z_-]+:.*?##' $(MAKEFILE_LIST) | sed -E 's/:.*## /\t/' | sort

build: ## compile the host binary into build/{host-os}/impr
	@mkdir -p build/$(HOST_OS)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o ../$(BIN)$(EXE) $(PKG)
	@echo "built $(BIN)$(EXE)"

test: ## run the suite with the race detector
	$(GO) test -race ./...

vet: ## go vet
	$(GO) vet ./...

fmt: ## gofmt every file in place
	gofmt -w $(GOFILES_DIRS)

fmt-check: ## fail if any file is not gofmt-clean
	@out="$$(gofmt -l $(GOFILES_DIRS))"; if [ -n "$$out" ]; then echo "not gofmt-clean:"; echo "$$out"; exit 1; fi

lint: ## golangci-lint (config in src/.golangci.yml)
	cd $(MODULE) && golangci-lint run ./...

check: fmt-check vet lint test ## every local gate

cross: clean ## cross-build build/targets.txt into build/{os}/ with build/checksums.txt
	@grep -vE '^[[:space:]]*(#|$$)' build/targets.txt | while read -r os arch arm; do \
	  name=$$os; [ "$$os" = darwin ] && name=macos; \
	  suffix=$$arch; [ -n "$$arm" ] && suffix=armv$$arm; \
	  ext=; [ "$$os" = windows ] && ext=.exe; \
	  mkdir -p build/$$name; \
	  echo "build $$name/impr_$${name}_$$suffix$$ext"; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch GOARM=$$arm $(GO) build -trimpath -ldflags '$(LDFLAGS)' \
	    -o ../build/$$name/impr_$${name}_$$suffix$$ext $(PKG) || exit 1; \
	done
	@cd build && find . -mindepth 2 -type f -name 'impr_*' | sed 's|^\./||' | sort | xargs shasum -a 256 > checksums.txt
	@echo "wrote build/checksums.txt"

clean: ## remove generated build output, keeping build/targets.txt
	rm -rf $(OS_DIRS)
