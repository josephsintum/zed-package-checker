# zed-package-checker

# The server crate's package name, for `cargo -p`. Both crates share the
# workspace at the root, so build output lands in target/ here.
SERVER      := package-checker
BINARY      := package-checker-lsp
RELEASE_DIR := target/release-assets

# The target `release-binary` builds; the release workflow passes each of the
# six it ships, and locally it defaults to this machine.
TARGET ?= $(shell rustc -vV | sed -n 's/^host: //p')

.PHONY: all server extension test lint fmt release-binary clean help

all: server extension ## Build both halves

server: ## Build the language server for this machine
	cargo build --release -p $(SERVER)
	@echo "built target/release/$(BINARY)"

extension: ## Build the Zed extension shim to wasm
	cargo build --release --target wasm32-wasip1

test: ## Run every crate's tests
	cargo test --workspace

lint: ## Check formatting and lint both crates
	cargo fmt --check
	cargo clippy --workspace --all-targets -- -D warnings

fmt: ## Format both crates
	cargo fmt

release-binary: ## Build one release asset for TARGET, named as the shim expects
	cargo build --release -p $(SERVER) --target $(TARGET)
	mkdir -p $(RELEASE_DIR)
	@set -e; name=$(BINARY)-$(TARGET); src=$(BINARY); \
	case "$(TARGET)" in *windows*) src=$$src.exe; name=$$name.exe;; esac; \
	cp target/$(TARGET)/release/$$src $(RELEASE_DIR)/$$name; \
	echo "  $(RELEASE_DIR)/$$name"
	@# Checksums cover the binaries as they will be run, not as they are shipped:
	@# the shim hashes what it has after decompressing, so this must match that.
	cd $(RELEASE_DIR) && shasum -a 256 $(BINARY)-* > SHA256SUMS

clean: ## Remove build output
	rm -rf target

help: ## List targets
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  %-16s %s\n", $$1, $$2}'
