# zed-package-checker

SERVER_DIR := server
BINARY     := package-checker-lsp
DIST       := $(SERVER_DIR)/dist
VERSION    ?= dev

GO_LDFLAGS := -s -w -X main.version=$(VERSION)

# Prefer a golangci-lint installed by `make lint-tools`, which is built against
# this machine's Go. A package-manager build compiled with an older Go refuses
# to run against a newer `go` directive, and on a typical PATH it would shadow
# the working one.
GOPATH_BIN := $(shell go env GOPATH)/bin
GOLANGCI   := $(if $(wildcard $(GOPATH_BIN)/golangci-lint),$(GOPATH_BIN)/golangci-lint,golangci-lint)

.PHONY: all server harness dbcheck scanharness extension test test-race test-differential lint lint-tools fmt tidy clean help

all: server extension ## Build both halves

server: ## Build the language server for this machine
	cd $(SERVER_DIR) && CGO_ENABLED=0 go build -trimpath \
		-ldflags "$(GO_LDFLAGS)" -o dist/$(BINARY) ./cmd/$(BINARY)
	@echo "built $(DIST)/$(BINARY)"

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

test: ## Run Go tests with the race detector
	cd $(SERVER_DIR) && go test -race ./...

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

lint-tools: ## Install golangci-lint, built against this machine's Go
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	@echo "installed to $$(go env GOPATH)/bin/golangci-lint"

fmt: ## Format both languages
	cd $(SERVER_DIR) && gofmt -w .
	cargo fmt

tidy: ## Tidy Go module dependencies
	cd $(SERVER_DIR) && go mod tidy

clean: ## Remove build output
	rm -rf $(DIST) target

help: ## List targets
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  %-10s %s\n", $$1, $$2}'
