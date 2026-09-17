# server_rs

A Rust rewrite of `server/`, built to answer one question: **would Rust have been
the better choice for this?**

It is a working language server, not a sketch. It walks a project, extracts its
dependencies with spans, matches them against a local copy of the OSV database,
and publishes diagnostics over LSP — and it produces byte-identical output to the
Go server across the fixtures they share.

The answer, with the measurements behind it, is in
[`docs/RUST-VS-GO.md`](docs/RUST-VS-GO.md). The part of it worth shipping — the
changes to make to the Go server, ranked and measured — is in
[`docs/CARRY-BACK.md`](docs/CARRY-BACK.md). The two largest are implemented and
committed on branch `db-parallel-load`; this branch deliberately leaves `server/`
untouched, so `scripts/bench.sh` here measures the Go server as it was.

## Layout

One crate, flat modules. The Go server splits the same work across nine packages
because Go's only mechanism for a dependency boundary is a separate package plus
a test that walks imports; module privacy gives that for free.

| File | What it does |
|---|---|
| `model.rs` | Domain types — packages, positions, advisories, findings. `std` only |
| `version.rs`, `semver_like.rs`, `pypi.rs`, `digits.rs` | Per-ecosystem version ordering, ported from osv-scalibr |
| `db.rs` | The advisory cache: download, lock, verify, publish atomically |
| `osv.rs`, `load.rs`, `index.rs` | Archives to an in-memory index |
| `matcher.rs` | Which advisories apply to which dependency |
| `extract.rs`, `manifest.rs` | Walking a project, and the four manifest parsers |
| `span.rs` | Byte offsets to editor positions |
| `scan.rs` | Extraction + database + matching, composed |
| `engine.rs` | Debounce, coalesce, supersede, publish |
| `lsp.rs`, `diagnostics.rs` | The protocol, and the wording users read |

## Building and running

```sh
cargo build --release              # target/release/package-checker-lsp
cargo test                         # 58 tests
cargo clippy --all-targets
```

Point Zed at `target/release/package-checker-lsp` through
`lsp.package-checker.binary.path`, exactly as for the Go binary.

## The measurements

```sh
scripts/bench.sh                   # load time, retained memory, peak RSS, both servers
scripts/compare-servers.py         # every published diagnostic, both servers, diffed
```

`bench.sh` builds the Go harness from this worktree if it is missing, so both
implementations are always measured at the same commit. It also builds two
copies of `dbcheck`: timings come from the plain build, retained memory from one
with a counting allocator, because that allocator's atomic counter is contended
by every worker during a parallel load and distorts the very timing it sits
beside.

## Checking the version comparators

The riskiest part of the port is version ordering, because getting it subtly
wrong means silently missing advisories. `tests/differential.rs` checks it
against **osv-scalibr's own answers** over 116,082 real comparisons. Regenerate
the corpus after changing anything in that area:

```sh
cd tools/semantic-oracle
go run . -root ~/Library/Caches/zed-package-checker/db \
  -out ../../tests/corpus/ordering.tsv Go PyPI npm
```

`tools/semantic-oracle` is a separate Go module on purpose: it exists to check
this server, and must never become something it depends on. So is
`tools/load-phases`, which attributes the load-time difference between the two
servers to inflating versus parsing:

```sh
cd tools/load-phases
go run . -archive ~/Library/Caches/zed-package-checker/db/osv-scalibr/npm/all.zip
go run . -archive ... -fast      # with klauspost/compress as the inflater
```

The Rust side reports the same split from `dbcheck --sequential <ecosystem>`.

## What is not here

Reachability analysis, the transitive npm graph, hover, code actions, `$/progress`
download reporting, and enrichment. See the last section of the verdict for the
full list and for the one behavioural gap deliberately carried over from the Go
server rather than fixed.
