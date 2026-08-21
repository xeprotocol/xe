# XE node build. One definition of "how the binary is built", used by CI, by
# the release workflow and by anyone reproducing a published checksum (#839).
#
# The previous build command was copy-pasted in five places with two different
# version schemes; this file is now the single source of truth.

BINARY      ?= xe
CMD         := ./cmd/xe
DIST        ?= dist

# VERSION is the release identity. A tagged build passes the tag; an untagged
# build derives a descriptive, non-release-looking string. Never defaults to a
# bare semver: a binary that claims to be v1.2.3 without a tag behind it is a
# supply-chain lie.
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)

# SOURCE_DATE_EPOCH pins any timestamp the toolchain might embed. Taken from
# the commit, so the same commit yields the same value on any machine.
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct 2>/dev/null || echo 0)

# Reproducibility flags. Each one removes a specific source of drift:
#   -trimpath      strips the absolute build path (/home/adam/... vs /home/runner/...)
#   -buildvcs=false stops the toolchain stamping VCS state into the binary
#   CGO_ENABLED=0  static, no host libc linkage
#   -s -w          drops symbol and DWARF tables (also smaller)
# The Go toolchain version itself is pinned by the `toolchain` line in go.mod;
# without it, two different 1.25.x patch releases produce different bytes.
GOFLAGS_REPRO := -trimpath -buildvcs=false
LDFLAGS       := -s -w -X main.version=$(VERSION)

# The exact Go toolchain a release is built with, pinned in .go-version.
# `go 1.25.0` in go.mod is a MINIMUM, not a pin: two builders on different
# 1.25.x patch releases produce different bytes for the same commit, which
# makes a published checksum unverifiable. `dist` and `verify-repro` force the
# pinned toolchain; plain `make build` uses whatever the developer has, because
# a day-to-day build does not need to match a published artifact byte for byte.
GO_VERSION       := $(shell cat .go-version)
PINNED_TOOLCHAIN := go$(GO_VERSION)

# Platforms published by the release workflow.
PLATFORMS ?= linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

export CGO_ENABLED := 0
export SOURCE_DATE_EPOCH

.PHONY: all build dist clean test race vet fmt lint checksums verify-repro tools-check print-version

all: build

## build: build the node binary for the host platform
build:
	go build $(GOFLAGS_REPRO) -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD)

## dist: cross-compile every published platform into $(DIST)/ plus SHA256SUMS
dist: export GOTOOLCHAIN = $(PINNED_TOOLCHAIN)
dist: clean
	@mkdir -p $(DIST)
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		out=$(DIST)/$(BINARY)_$(VERSION)_$${os}_$${arch}; \
		echo "==> $$out"; \
		GOOS=$$os GOARCH=$$arch go build $(GOFLAGS_REPRO) -ldflags "$(LDFLAGS)" -o $$out $(CMD) || exit 1; \
	done
	@$(MAKE) --no-print-directory checksums

## checksums: (re)generate SHA256SUMS over everything in $(DIST)
checksums:
	@cd $(DIST) && rm -f SHA256SUMS && sha256sum $(BINARY)_* | LC_ALL=C sort -k2 > SHA256SUMS
	@echo "==> $(DIST)/SHA256SUMS"
	@cat $(DIST)/SHA256SUMS

## verify-repro: build the same commit from two different paths with separate
## build caches and compare checksums. This is the check that turns
## "reproducible" into a tested claim rather than an asserted one.
verify-repro:
	@scripts/ci/verify-reproducible.sh $(VERSION)

## clean: remove build output
clean:
	rm -rf $(DIST) $(BINARY)

test:
	go test ./...

race:
	go test -race -shuffle=on -timeout=300s ./...

vet:
	go vet ./...

fmt:
	gofmt -l $$(git ls-files '*.go')

lint:
	golangci-lint run

print-version:
	@echo "version=$(VERSION)"
	@echo "go=$(GO_VERSION)"
	@echo "commit=$(COMMIT)"
	@echo "source_date_epoch=$(SOURCE_DATE_EPOCH)"
