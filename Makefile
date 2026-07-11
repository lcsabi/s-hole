BINARY   = s-hole
PKG      = ./cmd/s-hole
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

VERSION_PKG = github.com/lcsabi/s-hole/internal/version
LDFLAGS     = -ldflags="-s -w \
                -X '$(VERSION_PKG).Version=$(VERSION)' \
                -X '$(VERSION_PKG).Commit=$(COMMIT)' \
                -X '$(VERSION_PKG).BuildDate=$(DATE)'"

# On Windows use: $env:GOOS="linux"; $env:GOARCH="arm64"; go build ...
# or run these targets from WSL / Git Bash.

.PHONY: all pi pi32 linux clean test test-race bench fmt vet lint check install help version tools-install

## help: show this help text (default target)
help:
	@echo "s-hole — available targets:"
	@grep -E '^## [a-z]' Makefile | sed 's/^## /  /'

## all: build for the current OS/architecture
all:
	CGO_ENABLED=0 go build $(LDFLAGS) -o $(BINARY) $(PKG)

## pi: Raspberry Pi 4 / 5 and any 64-bit ARM board (arm64)
pi:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BINARY)-linux-arm64 $(PKG)

## pi32: Raspberry Pi 2 / 3 and older 32-bit ARM boards (armv7)
pi32:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build $(LDFLAGS) -o $(BINARY)-linux-armv7 $(PKG)

## linux: 64-bit x86 Linux (for VMs, cloud, NAS)
linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY)-linux-amd64 $(PKG)

## install: build and install into $GOPATH/bin (or $GOBIN)
install:
	go install $(LDFLAGS) $(PKG)

## test: run the full test suite
test:
	go test -count=1 ./...

## test-race: run tests under the race detector (requires CGO)
test-race:
	CGO_ENABLED=1 go test -race -count=1 ./...

## bench: run benchmarks (one iteration each — for regression smoke)
bench:
	go test -run=^$$ -bench=. -benchtime=1x ./...

## fmt: gofmt every Go file in place
fmt:
	gofmt -s -w .

## vet: go vet across all packages
vet:
	go vet ./...

## lint: run golangci-lint (install via `make tools-install` if missing)
lint:
	golangci-lint run ./...

## tools-install: install developer tools (golangci-lint) into $GOBIN
tools-install:
	# v2 module path — the un-versioned path installs golangci-lint v1,
	# which cannot parse the version:"2" schema in .golangci.yml.
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	@echo "tools installed; ensure \$$(go env GOBIN) (or \$$GOPATH/bin) is on \$$PATH"

## check: fmt + vet + lint + test — what CI does
check: fmt vet lint test

## version: print the version that would be embedded in a build
version:
	@echo "version: $(VERSION)"
	@echo "commit:  $(COMMIT)"
	@echo "date:    $(DATE)"

## clean: remove compiled binaries
clean:
	rm -f $(BINARY) $(BINARY)-linux-*
