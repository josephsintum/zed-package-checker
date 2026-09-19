# server

The language server: it walks a project, extracts its dependencies with spans,
matches them against the OSV database, and publishes diagnostics over LSP. The
Zed extension at the repository root is a thin shim that downloads and launches
this binary.

## Layout

One crate, flat modules. Module privacy gives every dependency boundary the
server needs; `tests/boundaries.rs` checks the one it cannot.

| File | What it does |
|---|---|
| `model.rs` | Domain types — packages, positions, advisories, findings. `std` only |
| `version.rs`, `semver_like.rs`, `pypi.rs`, `digits.rs` | Per-ecosystem version ordering, ported from osv-scalibr |
| `db.rs` | The advisory cache: download, lock, verify, publish atomically, revalidate |
| `api.rs` | Per-package advisories from osv.dev, kept on disk |
| `osv.rs`, `load.rs`, `index.rs` | Archives to an in-memory index |
| `matcher.rs` | Which advisories apply to which dependency, and what fixes them |
| `extract.rs`, `manifest.rs` | Walking a project, and the six manifest parsers |
| `span.rs` | Byte offsets to editor positions |
| `scan.rs` | Extraction + database + matching, composed |
| `engine.rs` | Debounce, coalesce, supersede, publish |
| `lsp.rs`, `diagnostics.rs`, `action.rs`, `progress.rs` | The protocol, the wording users read, the quick fix, the download bar |
| `config.rs` | `initializationOptions` |

## Building and running

From the repository root, which owns the Cargo workspace:

```sh
cargo build --release -p package-checker   # target/release/package-checker-lsp
cargo test --workspace
cargo clippy --workspace --all-targets
```

Point Zed at `target/release/package-checker-lsp` through
`lsp.package-checker.binary.path`.

## Measuring

```sh
cargo run --release --bin dbcheck -- --fetch npm      # download and time the archive load
cargo run --release --bin scanbench -- --runs 5 DIR   # a scan, phase by phase
scripts/compare-sources.py                            # archive vs API: identical diagnostics?
```

`dbcheck` times the database; `scanbench` times everything the editor pays on
every debounce. The answer the latter gave is that the scan is not worth
optimising — 62 ms at the deliberate worst case of 100,200 files with nothing
prunable, against a 1,000 ms debounce.

Retained memory comes from the `count-alloc` feature, a counting allocator.
It is opt-in because its atomic counter is contended by every worker during a
parallel load and distorts the very timing it sits beside, so a timing build
and a memory build are two different binaries.

## Checking the version comparators

The riskiest part of the server is version ordering, because getting it subtly
wrong means silently missing advisories. `tests/differential.rs` checks the
comparators against **osv-scalibr's own answers** over 116,142 real comparisons,
recorded from the Go, PyPI and npm archives into `tests/corpus/ordering.tsv.gz`.
The corpus is a tracked fixture: the test fails, rather than skips, if it is
missing.

## What is not here

Hover with full advisory prose, the transitive npm graph, EPSS and KEV
enrichment, reachability analysis. See `docs/PLAN.md` for what is planned.
