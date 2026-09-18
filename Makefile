# zed-package-checker

SERVER_DIR := server
RUST_DIR   := server_rs
BINARY     := package-checker-lsp
DIST       := $(SERVER_DIR)/dist
VERSION    ?= dev

GO_LDFLAGS := -s -w -X main.version=$(VERSION)

# Prefer a golangci-lint installed by `make lint-tools`, which is built against
# this machine's Go. A package-manager build compiled with an older Go refuses
# to run against a newer `go` directive, and on a typical PATH it would shadow
# the working one.
# Pinned so a new release cannot turn CI red on a day nobody touched the code.
# Overridable: make lint-tools GOLANGCI_VERSION=v2.14.0
GOLANGCI_VERSION ?= v2.13.2

GOPATH_BIN := $(shell go env GOPATH)/bin
GOLANGCI   := $(if $(wildcard $(GOPATH_BIN)/golangci-lint),$(GOPATH_BIN)/golangci-lint,golangci-lint)

# Every platform a release ships. Stage 0 confirmed all six cross-compile with
# CGO_ENABLED=0, which is what makes building them on one runner possible.
RELEASE_TARGETS := darwin/arm64 darwin/amd64 linux/arm64 linux/amd64 windows/arm64 windows/amd64
RELEASE_DIR     := $(DIST)/release

.PHONY: all server server-rs harness dbcheck scanharness extension release-binaries test test-rs test-race test-differential lint lint-rs lint-tools fmt tidy clean help

all: server extension ## Build both halves

server: ## Build the language server for this machine
	cd $(SERVER_DIR) && CGO_ENABLED=0 go build -trimpath \
		-ldflags "$(GO_LDFLAGS)" -o dist/$(BINARY) ./cmd/$(BINARY)
	@echo "built $(DIST)/$(BINARY)"

server-rs: ## Build the Rust server (see server_rs/docs/RUST-VS-GO.md)
	cd $(RUST_DIR) && cargo build --release
	@echo "built $(RUST_DIR)/target/release/$(BINARY)"

harness: ## Build the extraction harness (development only)
	cd $(SERVER_DIR) && go build -o dist/extractharness ./cmd/extractharness
	@echo "built $(DIST)/extractharness"

dbcheck: ## Build the database checker (development only)
	cd $(SERVER_DIR) && go build -o dist/dbcheck ./cmd/dbcheck
	@echo "built $(DIST)/dbcheck"

scanharness: ## Build the phase-by-phase scan timer (development only)
	cd $(SERVER_DIR) && go build -o dist/scanharness ./cmd/scanharness
	@echo "built $(DIST)/scanharness"

extension: ## Build the Zed extension shim to wasm
	cargo build --release --target wasm32-wasip1

release-binaries: ## Cross-compile every release target, with checksums
	rm -rf $(RELEASE_DIR)
	mkdir -p $(RELEASE_DIR)
	@set -e; for target in $(RELEASE_TARGETS); do \
		os=$${target%/*}; arch=$${target#*/}; \
		name=$(BINARY)-$$os-$$arch; \
		if [ "$$os" = "windows" ]; then name=$$name.exe; fi; \
		echo "  $$name"; \
		(cd $(SERVER_DIR) && GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build -trimpath \
			-ldflags "$(GO_LDFLAGS)" -o dist/release/$$name ./cmd/$(BINARY)); \
	done
	@# Checksums cover the binaries as they will be run, not as they are shipped:
	@# the shim hashes what it has after decompressing, so this must match that.
	cd $(RELEASE_DIR) && shasum -a 256 $(BINARY)-* > SHA256SUMS
	cd $(RELEASE_DIR) && gzip -9 $(BINARY)-*
	@echo "release artifacts in $(RELEASE_DIR)"

test: ## Run Go tests with the race detector
	cd $(SERVER_DIR) && go test -race ./...

test-rs: ## Run the Rust server's tests
	cd $(RUST_DIR) && cargo test

test-race: ## Hammer the concurrency tests (the Stage 7 gate)
	cd $(SERVER_DIR) && go test -race -count=100 ./internal/engine/...

test-differential: dbcheck ## Check our matching against osv-scanner (needs the advisory cache)
	cd $(SERVER_DIR) && ./dist/dbcheck -runs 1 npm Go PyPI
	cd $(SERVER_DIR) && go test -tags differential -run TestMatchesOSVScanner -v ./internal/match/

lint: ## Vet the Go module and run golangci-lint
	cd $(SERVER_DIR) && go vet ./...
	@if command -v $(GOLANGCI) >/dev/null 2>&1; then \
		cd $(SERVER_DIR) && $(GOLANGCI) run; \
	else \
		echo "golangci-lint not installed; go vet ran, the rest did not."; \
		echo "install it with: make lint-tools"; \
	fi

lint-rs: ## Check formatting and lint the Rust server
	cd $(RUST_DIR) && cargo fmt --check
	cd $(RUST_DIR) && cargo clippy --all-targets -- -D warnings

lint-tools: ## Install golangci-lint, built against this machine's Go
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)
	@echo "installed to $$(go env GOPATH)/bin/golangci-lint"

fmt: ## Format every tree
	cd $(SERVER_DIR) && gofmt -w .
	cargo fmt
	cd $(RUST_DIR) && cargo fmt

tidy: ## Tidy Go module dependencies
	cd $(SERVER_DIR) && go mod tidy

clean: ## Remove build output
	rm -rf $(DIST) target $(RUST_DIR)/target

help: ## List targets
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  %-10s %s\n", $$1, $$2}'
