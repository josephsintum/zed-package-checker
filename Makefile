# zed-package-checker

SERVER_DIR := server
BINARY     := package-checker-lsp
DIST       := $(SERVER_DIR)/dist
VERSION    ?= dev

GO_LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all server harness dbcheck extension test test-differential lint fmt tidy clean help

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

extension: ## Build the Zed extension shim to wasm
	cargo build --release --target wasm32-wasip1

test: ## Run Go tests with the race detector
	cd $(SERVER_DIR) && go test -race ./...

test-differential: dbcheck ## Check our matching against osv-scanner (needs the advisory cache)
	cd $(SERVER_DIR) && ./dist/dbcheck -runs 1 npm Go PyPI
	cd $(SERVER_DIR) && go test -tags differential -run TestMatchesOSVScanner -v ./internal/match/

lint: ## Vet the Go module (golangci-lint if available)
	cd $(SERVER_DIR) && go vet ./...
	@command -v golangci-lint >/dev/null 2>&1 \
		&& (cd $(SERVER_DIR) && golangci-lint run) \
		|| echo "golangci-lint not installed, skipped"

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
