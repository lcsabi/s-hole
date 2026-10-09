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

# The golangci-lint release that `make tools-install` installs and the CI lint
# job runs (CI reads this line). Move it on purpose: a new linter release can
# add findings.
GOLANGCI_LINT_VERSION ?= v2.14.0

# On Windows use: $env:GOOS="linux"; $env:GOARCH="arm64"; go build ...
# or run these targets from WSL / Git Bash.

.PHONY: all pi pi32 linux clean test test-race bench fmt vet lint lint-windows lint-sh vuln check install help version tools-install

## help: show this help text (default target)
help:
	@echo "s-hole available targets:"
	@grep -E '^## [a-z]' Makefile | sed 's/^## /  /'

## all: build for the current OS/architecture
all:
	CGO_ENABLED=0 go build -trimpath $(LDFLAGS) -o $(BINARY) $(PKG)

## pi: 64-bit ARM Linux (arm64): a Raspberry Pi 3, 4, or 5 on a 64-bit OS
pi:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath $(LDFLAGS) -o $(BINARY)-linux-arm64 $(PKG)

## pi32: 32-bit ARM Linux (armv7): a Raspberry Pi 2, or a Pi 3 or 4 on a 32-bit OS
pi32:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -trimpath $(LDFLAGS) -o $(BINARY)-linux-armv7 $(PKG)

## linux: 64-bit x86 Linux (for VMs, cloud, NAS)
linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath $(LDFLAGS) -o $(BINARY)-linux-amd64 $(PKG)

## install: build and install into $GOPATH/bin (or $GOBIN)
install:
	go install -trimpath $(LDFLAGS) $(PKG)

## test: run the full test suite
test:
	go test -count=1 ./...

## test-race: run tests under the race detector (requires CGO)
test-race:
	CGO_ENABLED=1 go test -race -count=1 ./...

## bench: run benchmarks (one iteration each, for regression smoke)
bench:
	go test -run=^$$ -bench=. -benchtime=1x ./...

## fmt: gofmt every Go file in place
fmt:
	gofmt -s -w .

## vet: go vet across all packages
vet:
	go vet ./...

## lint: run golangci-lint for this OS and for Windows (install via `make tools-install` if missing)
lint: lint-windows
	golangci-lint run ./...

## lint-windows: run golangci-lint for the Windows build (GOOS=windows); `make lint` runs it
# The Windows-only files build only with GOOS=windows, so a lint for another
# OS does not check them. CI runs both.
lint-windows: export GOOS=windows
lint-windows:
	golangci-lint run ./...

## lint-sh: shellcheck the deploy and CI scripts (CI runs the same check)
lint-sh:
	@command -v shellcheck >/dev/null 2>&1 || { \
		echo "shellcheck not found; install it (apt install shellcheck / brew install shellcheck)"; \
		exit 1; }
	shellcheck deploy/*.sh .github/*.sh

## vuln: scan dependencies + code for known CVEs (govulncheck)
vuln:
	# go run keeps govulncheck out of the module's require set; CI runs the
	# same tool through the golang/govulncheck-action job, and the weekly
	# vulncheck workflow also scans the latest release binaries. @latest is
	# deliberate: the advisories come from the live database, so the scanner
	# release does not change which findings appear.
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

## tools-install: install developer tools (golangci-lint) into $GOBIN
tools-install:
	# v2 module path: the un-versioned path installs golangci-lint v1,
	# which cannot parse the version:"2" schema in .golangci.yml.
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	@echo "tools installed; ensure \$$(go env GOBIN) (or \$$GOPATH/bin) is on \$$PATH"

## check: fmt + vet + lint + lint-sh + test (what CI does)
check: fmt vet lint lint-sh test

## version: print the version that would be embedded in a build
version:
	@echo "version: $(VERSION)"
	@echo "commit:  $(COMMIT)"
	@echo "date:    $(DATE)"

## clean: remove compiled binaries
clean:
	rm -f $(BINARY) $(BINARY)-linux-*
