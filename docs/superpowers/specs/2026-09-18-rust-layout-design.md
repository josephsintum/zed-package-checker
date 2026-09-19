# Restructure `server/` as an idiomatic Rust crate

Design for reshaping the language server's crate layout, layering, public API,
lints and tests to match Rust conventions and the Apollo Rust best-practices
handbook. Behaviour does not change; every step ends with the full test suite
green and `server/scripts/compare-sources.py` still agreeing.

## Why

The crate was built as a port and kept the port's shape: 10k lines in 20 flat
files, four of them over 700 lines; a dependency cycle between `diagnostics`
and `action`; `anyhow` on a library trait; no `[lints]` table; public re-exports
that exist only for two benchmark binaries. None of it is wrong, but none of it
is what a Rust reader expects, and the cycle is the kind that grows.

## Decisions

- **One crate, mostly flat.** Directories only where a module has real children.
- **Typed errors, keep the trait objects.** `anyhow` leaves the library; the
  `dyn Scanner`/`dyn Publisher`/`dyn Progress` seams stay — one implementation
  each at runtime, and they exist so tests inject fakes.
- **No workspace split, no generics, no behaviour change.**

## 1. Module tree

```
src/
  lib.rs            crate docs and the public surface
  main.rs           flags, wiring, shutdown
  bin/{dbcheck,scanbench}.rs
  model.rs          domain types, std only
  span.rs  read.rs
  version.rs        parent: Version, ParseError, compare; re-exports
  version/{semver_like,pypi,digits}.rs
  manifest.rs       parent: Parser type, sighting/first_per_name helpers, the conformance table
  manifest/{npm,go,cargo,python}.rs   one format each, with its own tests
  extract.rs
  osv.rs  load.rs  index.rs  db.rs  api.rs
  matcher.rs  scan.rs  engine.rs
  config.rs  lsp.rs  diagnostics.rs  action.rs  progress.rs
  testing.rs        #[cfg(test)] unit-test support (fake archive server, fake editor)
tests/
  common/mod.rs     fixture-path helper for integration tests
  {boundaries,differential,extraction,model,ordering}.rs
```

`manifest.rs` splits by format; the parent keeps what every parser shares and
the conformance table that runs all six. `db.rs` stays one file: one lifecycle,
long because of its tests. `version/` holds the three modules that exist only
to serve `version.rs`.

Moves are pure `git mv` plus `mod` declarations, committed before any content
change, so later diffs are readable.

## 2. Layering

Dependency direction, top to bottom:

```
model → span, read → version → manifest → extract → osv, index → load, db, api
      → matcher → scan → engine → config → diagnostics, action, progress → lsp
```

One cycle exists today and is removed by two moves:

- `action::version_span(sightings, finding)` → `extract::version_span`. It
  answers "which sighting does this finding come from, and where is its version
  written" — a question about sightings. `diagnostics` and `action` both call it
  from above.
- `diagnostics::NAME` → `config::NAME`. The server's identity, used as the
  diagnostic `source` and in `serverInfo`; `config` sits below both users.

The `Scanner` trait moves next to `ScanError` in `scan.rs` (so `engine` depends
downward on both) and `scan` returns `Result<Report, ScanError>`. No new variants
are expected: the engine only displays errors and treats `NotReady` specially,
and it matches on that variant rather than on the message. `anyhow` is removed from
`[dependencies]` (the bins may keep it as a bin-only dependency if they want).

`tests/boundaries.rs` continues to hold `model` to `std`. The rest of the order
is held by review; a reference from a lower module to a higher one is a defect.

## 3. Public API (`lib.rs`)

Two documented tiers; everything else `pub(crate)`:

- **The server:** `Backend`, `Config`, `Database`, `DbError`, `Progress`,
  `ClientProgress`, `Engine`, `Requester`, `Scanner`, `Publisher`, `Reason`,
  `DEFAULT_DEBOUNCE`, `WorkspaceScanner`, `ScanError`, `Extractor`,
  `ExtractError`, `default_root`, and the `model` and `version` modules.
- **For the measurement binaries** (a labelled group): `Index`, `Matcher`,
  `load`, `Strategy`, `ArchiveStats`, `LoadError`, `SKIP_DIRS`,
  `is_manifest_name`, `alloc`.

`span::{Encoding, LineIndex, column}` stop being public unless a bin needs them.

## 4. Lints, panics, unsafe

`server/Cargo.toml`:

```toml
[lints.rust]
missing_docs = "warn"
unsafe_op_in_unsafe_fn = "deny"
rust_2018_idioms = { level = "warn", priority = -1 }

[lints.clippy]
unwrap_used = "warn"
expect_used = "warn"
dbg_macro = "warn"
todo = "warn"
unimplemented = "warn"
large_enum_variant = "warn"
needless_pass_by_value = "warn"
redundant_clone = "warn"
doc_markdown = "warn"
missing_errors_doc = "warn"
missing_panics_doc = "warn"
```

`server/clippy.toml`: `allow-unwrap-in-tests = true`, `allow-expect-in-tests = true`.
CI already runs clippy with `-D warnings`, so these are enforced.

The five production `expect`s:

| Site | Disposition |
|---|---|
| `pypi.rs` three regex constants | `#[expect(clippy::expect_used, reason = "constant pattern, checked at first use")]` |
| `db.rs:500` `serde_json::to_vec(meta)` | `#[expect]` with reason: `Meta` is plain data and serialisation cannot fail |
| `index.rs:56` "every affected package was counted" | keep with `#[expect]`; the two-pass build is the invariant and restructuring it would cost the contiguous layout |
| `model.rs:524` "a finding always carries at least one advisory" | restructure: `Finding::worst` cannot fail if the type guarantees a first advisory. Option chosen in the plan: keep `Vec<Arc<Advisory>>` and make `worst` return `Option`, with the one caller that needs a value handling `None` — smaller than a non-empty vector type |

The two `unsafe` sites (`alloc.rs` counting allocator, `load.rs` mmap) get
`// SAFETY:` comments in the handbook's form.

## 5. Tests and docs

- Test names stay as sentences. Files whose test module has more than ~15 tests
  (`db`, `matcher`, `diagnostics`, `manifest/*`, `scan`) group them into
  `mod <unit>` submodules (`db::tests::heal::…`), so one unit can be run alone.
- `tests/common/mod.rs` holds the fixture-path helper; `src/testing.rs` stays
  for unit-test support (fake archive server, fake editor).
- `missing_docs` drives a `///` onto every public item. The crate doc in
  `lib.rs` gains a short layering map pointing at the modules.
- No `insta`, no `rstest`.

## 6. Sequencing

Each step is one commit and ends green (`make lint`, `make test`,
`compare-sources.py`):

1. Pure moves: `version/`, `manifest/`, `tests/common`. No content edits beyond
   `mod`/`use` lines.
2. Layering: `version_span` and `NAME` moves; typed `Scanner::scan`; `anyhow`
   out of the library.
3. Public API: tighten `lib.rs`.
4. Lints: add the tables, fix the fallout, dispose of the five `expect`s, add
   the `SAFETY` comments.
5. Tests and docs: submodule grouping, `missing_docs` fallout, crate doc.

## Out of scope

Workspace split; generics over the trait objects; behaviour changes of any kind;
new dependencies beyond none (no `insta`/`rstest`).
