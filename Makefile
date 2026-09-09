BINARY      ?= xe
CMD         := ./cmd/xe
DIST        ?= dist

VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)

SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct 2>/dev/null || echo 0)

GOFLAGS_REPRO := -trimpath -buildvcs=false
LDFLAGS       := -s -w -X main.version=$(VERSION)

GO_VERSION       := $(shell cat .go-version)
PINNED_TOOLCHAIN := go$(GO_VERSION)

PLATFORMS ?= linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

export CGO_ENABLED := 0
export SOURCE_DATE_EPOCH

.PHONY: all build dist clean test race vet fmt lint checksums verify-repro tools-check print-version

all: build

build:
	go build $(GOFLAGS_REPRO) -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD)

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

checksums:
	@cd $(DIST) && rm -f SHA256SUMS && sha256sum $(BINARY)_* | LC_ALL=C sort -k2 > SHA256SUMS
	@echo "==> $(DIST)/SHA256SUMS"
	@cat $(DIST)/SHA256SUMS

verify-repro:
	@scripts/ci/verify-reproducible.sh $(VERSION)

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
