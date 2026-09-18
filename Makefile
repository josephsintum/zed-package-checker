# zed-package-checker

SERVER_DIR  := server
BINARY      := package-checker-lsp
RELEASE_DIR := $(SERVER_DIR)/target/release-assets

# The target `release-binary` builds; the release workflow passes each of the
# six it ships, and locally it defaults to this machine.
TARGET ?= $(shell rustc -vV | sed -n 's/^host: //p')

.PHONY: all server extension test lint fmt release-binary clean help

all: server extension ## Build both halves

server: ## Build the language server for this machine
	cd $(SERVER_DIR) && cargo build --release
	@echo "built $(SERVER_DIR)/target/release/$(BINARY)"

extension: ## Build the Zed extension shim to wasm
	cargo build --release --target wasm32-wasip1

test: ## Run the server's tests
	cd $(SERVER_DIR) && cargo test

lint: ## Check formatting and lint both crates
	cargo fmt --check
	cd $(SERVER_DIR) && cargo fmt --check
	cd $(SERVER_DIR) && cargo clippy --all-targets -- -D warnings

fmt: ## Format both crates
	cargo fmt
	cd $(SERVER_DIR) && cargo fmt

release-binary: ## Build one release asset for TARGET, named as the shim expects
	cd $(SERVER_DIR) && cargo build --release --target $(TARGET)
	mkdir -p $(RELEASE_DIR)
	@set -e; name=$(BINARY)-$(TARGET); src=$(BINARY); \
	case "$(TARGET)" in *windows*) src=$$src.exe; name=$$name.exe;; esac; \
	cp $(SERVER_DIR)/target/$(TARGET)/release/$$src $(RELEASE_DIR)/$$name; \
	echo "  $(RELEASE_DIR)/$$name"
	@# Checksums cover the binaries as they will be run, not as they are shipped:
	@# the shim hashes what it has after decompressing, so this must match that.
	cd $(RELEASE_DIR) && shasum -a 256 $(BINARY)-* > SHA256SUMS

clean: ## Remove build output
	rm -rf target $(SERVER_DIR)/target

help: ## List targets
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  %-16s %s\n", $$1, $$2}'
