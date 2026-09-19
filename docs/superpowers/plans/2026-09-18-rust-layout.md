# Rust Layout Restructure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reshape `server/` into a conventionally laid-out Rust crate — nested `version/` and `manifest/`, one-directional layering, typed errors, a `[lints]` table, a documented public API — with no behaviour change.

**Architecture:** One library crate plus three binaries. Directories only where a module has children (`version/`, `manifest/`). Dependency order `model → span, read → version → manifest → extract → osv, index → load, db, api → matcher → scan → engine → config → diagnostics, action, progress → lsp`; the `Scanner` trait and `ScanError` live in `scan.rs` so the engine depends downward on them. Trait objects stay as test seams; `anyhow` leaves the library.

**Tech Stack:** Rust 2024, tower-lsp-server, tokio, thiserror, clippy with a `[lints]` table.

**Spec:** `docs/superpowers/specs/2026-09-18-rust-layout-design.md`

## Global Constraints

- Behaviour does not change. After every task: `make lint` and `make test` green from the repository root; after the last task also `python3 server/scripts/compare-sources.py` prints `AGREE`.
- Commit messages are one line, no trailers (project convention).
- No new runtime dependencies. `anyhow` is removed from `[dependencies]`.
- Moves are `git mv` so history follows the files.
- All paths below are relative to `server/` unless they start with `docs/` or `Makefile`.
- The `make` targets run from the repository root: `cd /Users/josephsintum/code/zed-package-checker && make lint && make test`.

---

### Task 1: Nest the version comparators under `version/`

**Files:**
- Move: `src/semver_like.rs` → `src/version/semver_like.rs`, `src/pypi.rs` → `src/version/pypi.rs`, `src/digits.rs` → `src/version/digits.rs`
- Modify: `src/version.rs` (module declarations, imports), `src/lib.rs` (drop three `mod` lines), `src/version/pypi.rs` and `src/version/semver_like.rs` (`crate::digits` → `super::digits`)

**Interfaces:**
- Produces: `crate::version::{Version, ParseError}` unchanged; `version::pypi::PyPiVersion` and `version::semver_like::SemverLike` are `pub(crate)` children, nothing outside `version` uses them (only `version.rs` did).

- [ ] **Step 1: Move the files**

```bash
cd /Users/josephsintum/code/zed-package-checker/server
mkdir -p src/version
git mv src/semver_like.rs src/version/semver_like.rs
git mv src/pypi.rs src/version/pypi.rs
git mv src/digits.rs src/version/digits.rs
```

- [ ] **Step 2: Declare the children in `src/version.rs`**

Replace the two `use crate::…` lines with module declarations plus local imports:

```rust
use crate::model::Ecosystem;
use std::cmp::Ordering;
use std::fmt;

mod digits;
mod pypi;
mod semver_like;

use pypi::PyPiVersion;
use semver_like::SemverLike;
```

In `src/lib.rs` delete the lines `mod digits;`, `mod pypi;`, `mod semver_like;`.

In `src/version/pypi.rs` and `src/version/semver_like.rs`, change `use crate::digits` to `use super::digits`. Any `pub fn`/`pub struct` inside the three children that only `version.rs` uses may stay `pub`; module privacy already hides them (the parent declares `mod`, not `pub mod`).

- [ ] **Step 3: Build and test**

Run: `cargo test 2>&1 | grep -E "^error|FAILED|test result"`
Expected: every `test result: ok`, including `tests/ordering.rs` and `tests/differential.rs` (116,142 comparisons).

- [ ] **Step 4: Commit**

```bash
git add -A src/version.rs src/version src/lib.rs
git commit -m "Nest the version comparators under version/"
```

---

### Task 2: Split `manifest.rs` by format

**Files:**
- Create: `src/manifest/npm.rs`, `src/manifest/go.rs`, `src/manifest/cargo.rs`, `src/manifest/python.rs`
- Modify: `src/manifest.rs` (becomes the parent: shared helpers, `Parser`, conformance tests, re-exports)

**Interfaces:**
- Produces: `crate::manifest::{package_json, package_lock, go_mod, cargo_toml, cargo_lock, cargo_self, requirements, requirement_includes, Parser}` — same names, same signatures, now re-exported from the children. Nothing outside `manifest` changes.

Item-to-file mapping (line numbers as of this plan; move each item with its doc comment):

| Destination | Items (from `src/manifest.rs`) |
|---|---|
| `manifest.rs` (parent) | module doc; `Parser` (24); `sighting` (26); `first_per_name` (49); `offset_in` (61); `lowest_satisfying` (131 — used by npm and cargo); `mod conformance` (867–1143) |
| `manifest/npm.rs` | `NPM_SECTIONS` (16); `package_json` (68); `package_lock` (155); `lock_packages` (182); `lock_tree` (222); `lock_groups` (247); `property` (843); `prop_name` (852); behaviour tests `package_json_*` (1235, 1250) |
| `manifest/go.rs` | `Replace` (261); `replace_line` (270); `go_mod` (297); `require_line` (408); `strip_comment` (446); behaviour tests `go_mod_*` (1160–1225) |
| `manifest/cargo.rs` | `CARGO_SECTIONS` (461); `cargo_toml` (472); `cargo_self` (527); `cargo_lock` (549); `cargo_section` (603); `cargo_dependency` (617); `quoted_after` (653); `first_quoted` (670); `trim_toml_comment` (678); behaviour tests `cargo_toml_*` (1286, 1293) |
| `manifest/python.rs` | `requirements` (699); `requirement` (737); `unsupported_constraint` (798); `requirement_includes` (811); `specifier` (825); behaviour tests `requirements_*`, `requirement_includes_are_listed` (1256–1276) |

- [ ] **Step 1: Create the children with the moved items**

Each child starts with a one-line module doc and imports what it uses from the parent via `super::`. Skeletons:

```rust
// src/manifest/npm.rs
//! `package.json` and `package-lock.json`.

use super::{first_per_name, lowest_satisfying, sighting};
use crate::model::{DEV_GROUP, Ecosystem, ExtractedPackage};
use crate::span::LineIndex;
use jsonc_parser::ast::{Object, ObjectPropName, Value};
use jsonc_parser::{CollectOptions, ParseOptions, parse_to_ast};
use std::path::Path;

// NPM_SECTIONS, package_json, package_lock, lock_packages, lock_tree,
// lock_groups, property, prop_name — moved verbatim.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::test_support::{at, names_and_versions};
    // package_json_production_wins_over_dev, package_json_non_dependency_sections_are_ignored
}
```

```rust
// src/manifest/go.rs
//! `go.mod`: `require`, `replace` and the `go`/`toolchain` directives.

use super::{offset_in, sighting};
use crate::model::{Ecosystem, ExtractedPackage};
use crate::span::LineIndex;
use std::path::Path;
// Replace, replace_line, go_mod, require_line, strip_comment — moved verbatim.
```

```rust
// src/manifest/cargo.rs
//! `Cargo.toml` and `Cargo.lock`.

use super::{first_per_name, lowest_satisfying, offset_in, sighting};
use crate::model::{DEV_GROUP, Ecosystem, ExtractedPackage};
use crate::span::LineIndex;
use std::path::Path;
// CARGO_SECTIONS … trim_toml_comment — moved verbatim.
```

```rust
// src/manifest/python.rs
//! `requirements.txt`: PEP 508 lines, continuations, `-r` includes.

use super::{offset_in, sighting};
use crate::model::{Ecosystem, ExtractedPackage};
use crate::span::LineIndex;
use std::path::Path;
// requirements, requirement, unsupported_constraint, requirement_includes, specifier — moved verbatim.
```

Trim each `use` list to what the compiler asks for (unused-import warnings fail `make lint`).

- [ ] **Step 2: Rewrite the parent `src/manifest.rs`**

```rust
//! The six manifest parsers, across five formats, each with its spans.
//!
//! Each function is pure: source text and a path in, sightings out, no
//! filesystem. A file that will not parse yields nothing rather than an error —
//! a manifest caught mid-save is a normal event in an editor, not a scan
//! failure.

use crate::model::{Ecosystem, ExtractedPackage, Package, Range, Site};
use std::path::Path;

mod cargo;
mod go;
mod npm;
mod python;

pub use cargo::{cargo_lock, cargo_self, cargo_toml};
pub use go::go_mod;
pub use npm::{package_json, package_lock};
pub use python::{requirement_includes, requirements};

/// What every manifest parser is: source text and a path in, sightings out.
pub type Parser = fn(&str, &Path) -> Vec<ExtractedPackage>;

// sighting, first_per_name, offset_in, lowest_satisfying — unchanged, private;
// children reach them through `super::`.

/// Helpers the per-format tests share.
#[cfg(test)]
pub(crate) mod test_support {
    use crate::model::ExtractedPackage;
    use std::path::PathBuf;

    pub(crate) fn at(name: &str) -> PathBuf {
        PathBuf::from("/p").join(name)
    }

    pub(crate) fn names_and_versions(found: &[ExtractedPackage]) -> Vec<(String, String)> {
        found
            .iter()
            .map(|f| (f.package.name().to_owned(), f.package.version.to_string()))
            .collect()
    }
}

#[cfg(test)]
mod conformance {
    // moved verbatim; it already reaches every parser through `super::*`
}
```

Delete the old `mod behaviour` after its tests have been distributed to the children.

- [ ] **Step 3: Build and test**

Run: `cargo test 2>&1 | grep -E "^error|FAILED|test result"`
Expected: same test count as before the split (the 13 `behaviour` tests now report as `manifest::npm::tests::…`, `manifest::go::tests::…`, etc.).

Run: `cargo clippy --all-targets -- -D warnings 2>&1 | grep -E "^(warning|error)"`
Expected: no output.

- [ ] **Step 4: Commit**

```bash
git add -A src/manifest.rs src/manifest
git commit -m "Split the manifest parsers into one file per format"
```

---

### Task 3: Share the fixture helper between integration tests

**Files:**
- Create: `tests/common/mod.rs`
- Modify: `tests/extraction.rs:11-15`

- [ ] **Step 1: Create `tests/common/mod.rs`**

```rust
//! Shared by the integration tests; `cargo test` compiles it once per test binary.

use std::path::{Path, PathBuf};

/// A project under `testdata/fixtures/`.
pub fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/fixtures")
        .join(name)
}
```

- [ ] **Step 2: Use it from `tests/extraction.rs`**

Delete the local `fn fixture` and add at the top:

```rust
mod common;
use common::fixture;
```

- [ ] **Step 3: Test and commit**

Run: `cargo test --test extraction 2>&1 | grep "test result"`
Expected: `ok`, same count as before.

```bash
git add tests/common/mod.rs tests/extraction.rs
git commit -m "Share the fixture helper between integration tests"
```

---

### Task 4: Break the diagnostics/action cycle

**Files:**
- Modify: `src/action.rs:107-125` (`version_span` moves out), `src/extract.rs` (receives it), `src/diagnostics.rs:42`, `src/config.rs` (receives `NAME`), `src/diagnostics.rs:17` (`NAME` moves out), `src/action.rs:86,241`, `src/lsp.rs:272`

**Interfaces:**
- Produces: `crate::extract::version_span(sightings: &[ExtractedPackage], finding: &Finding) -> Option<Range>` (`pub(crate)`); `crate::config::NAME: &str`.

- [ ] **Step 1: Move `version_span` to `extract.rs`**

Cut the function and its doc comment (`/// Where this finding's version is written in the text just parsed.` through the closing brace) from `src/action.rs` and paste it into `src/extract.rs` after `is_manifest_name`, keeping `pub(crate)`. Add `use crate::model::{Finding, Range};` to `extract.rs` (extend the existing `use crate::model::{…}` line).

In `src/action.rs` replace every call `version_span(` with `crate::extract::version_span(` and in `src/diagnostics.rs:42` replace `crate::action::version_span(` with `crate::extract::version_span(`.

- [ ] **Step 2: Move `NAME` to `config.rs`**

In `src/config.rs` add near the top:

```rust
/// The server's name: the `source` on every diagnostic, and what `serverInfo`
/// reports.
pub const NAME: &str = "package-checker";
```

Delete the `pub const NAME` (and its doc) from `src/diagnostics.rs`; replace its two internal uses with `crate::config::NAME`. In `src/action.rs` replace `diagnostics::NAME` (2 sites) with `crate::config::NAME` and drop `use crate::diagnostics;` if nothing else uses it. In `src/lsp.rs:272` replace `diagnostics::NAME` with `crate::config::NAME`.

- [ ] **Step 3: Verify the cycle is gone**

Run: `grep -n "crate::action\|crate::lsp" src/diagnostics.rs; grep -n "crate::diagnostics\|use crate::diagnostics" src/action.rs`
Expected: only the module-doc mention in `diagnostics.rs:3` (prose), no code references.

Run: `cargo test 2>&1 | grep -E "^error|FAILED|test result"` — all `ok`.

- [ ] **Step 4: Commit**

```bash
git add src/action.rs src/extract.rs src/diagnostics.rs src/config.rs src/lsp.rs
git commit -m "Move version_span and NAME below diagnostics and action"
```

---

### Task 5: Typed errors on the scanner trait; `anyhow` out of the library

**Files:**
- Modify: `src/engine.rs:42-48` (trait moves out), `src/scan.rs` (receives the trait), `src/engine.rs:186,258` (in-flight type), `src/lib.rs` (re-export), `src/lsp.rs:74,142,611,655`, `src/progress.rs:192-195`, `src/scan.rs:407-412` (test helper), `src/engine.rs` tests `FakeScanner`, `Cargo.toml`

**Interfaces:**
- Produces: `crate::scan::Scanner` with `fn scan(&self, root: &Path) -> Result<Report, ScanError>` and `fn shutdown(&self) {}`; `crate::engine` imports it. `lib.rs` exports `Scanner` from `scan`.

- [ ] **Step 1: Write the failing test**

In `src/engine.rs` tests, change the fake to fail with a typed error, and assert the engine's notice for `NotReady` is driven by the variant:

```rust
    impl Scanner for Arc<FakeScanner> {
        fn scan(&self, root: &Path) -> Result<Report, ScanError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(gate) = self.block.lock().unwrap().take() {
                let _ = gate.recv();
            }
            if self.failing.load(Ordering::SeqCst) {
                return Err(ScanError::NotReady);
            }
            Ok(Report::new(root, self.findings.lock().unwrap().clone()))
        }
    }
```

Run: `cargo test --lib engine:: 2>&1 | grep -E "^error" | head -3`
Expected: compile error — `Scanner::scan` still returns `anyhow::Result`.

- [ ] **Step 2: Move the trait and type the error**

Cut from `src/engine.rs`:

```rust
/// Produces a report for a workspace. Implemented by `crate::scan`.
pub trait Scanner: Send + Sync + 'static {
    fn scan(&self, root: &Path) -> anyhow::Result<Report>;

    /// Stops background work. Called once, when the engine shuts down.
    fn shutdown(&self) {}
}
```

Paste into `src/scan.rs` directly after the `ScanError` enum, as:

```rust
/// Produces a report for a workspace.
///
/// A trait rather than the concrete [`WorkspaceScanner`] so the engine can be
/// tested against a fake; there is one real implementation.
pub trait Scanner: Send + Sync + 'static {
    /// Scans `root` and reports every vulnerable dependency under it.
    ///
    /// # Errors
    ///
    /// [`ScanError::NotReady`] while the advisory database is still
    /// downloading; the other variants wrap extraction, loading, cache and
    /// API failures.
    fn scan(&self, root: &Path) -> Result<Report, ScanError>;

    /// Stops background work. Called once, when the engine shuts down.
    fn shutdown(&self) {}
}
```

In `src/scan.rs` delete `use crate::engine::Scanner;`. In `src/engine.rs` add `use crate::scan::{ScanError, Scanner};`, change `in_flight: Option<JoinHandle<anyhow::Result<Report>>>` to `Option<JoinHandle<Result<Report, ScanError>>>`, and in the tests replace `anyhow::bail!` as in Step 1. In `impl Scanner for WorkspaceScanner` change the signature to `-> Result<Report, ScanError>` and the final `Err(ScanError::NotReady.into())` to `Err(ScanError::NotReady)`.

Update the other implementors: `src/lsp.rs:611` (`OneFinding`) and `src/progress.rs:193` (`Idle`) return `Result<Report, ScanError>` (import `crate::scan::ScanError`); `src/lsp.rs:74,142,655` and `src/main.rs` refer to `crate::scan::Scanner` / `package_checker::Scanner`. In `src/scan.rs` tests replace `is_not_ready`'s body with `matches!(result, Err(ScanError::NotReady))` and its parameter type with `&Result<Report, ScanError>`.

In `src/lib.rs`: `pub use engine::{DEFAULT_DEBOUNCE, Engine, Publisher, Reason, Requester};` and `pub use scan::{ScanError, Scanner, WorkspaceScanner};`.

- [ ] **Step 3: Remove `anyhow`**

Delete `anyhow = "1"` from `[dependencies]` in `Cargo.toml`. Run `grep -rn anyhow src tests` — expected: no matches.

- [ ] **Step 4: Test and commit**

Run: `cargo test 2>&1 | grep -E "^error|FAILED|test result"` — all `ok`. Run: `cargo clippy --all-targets -- -D warnings` — clean.

```bash
git add Cargo.toml Cargo.lock src/engine.rs src/scan.rs src/lsp.rs src/progress.rs src/lib.rs src/main.rs
git commit -m "Type the scanner's error and drop anyhow from the library"
```

---

### Task 6: Tighten the public API

**Files:**
- Modify: `src/lib.rs` (the `pub use` block), `src/span.rs` (visibility if needed)

- [ ] **Step 1: Rewrite the export block in `src/lib.rs`**

```rust
pub mod model;
pub mod version;

// What the language server binary composes.
pub use config::{Config, NAME};
pub use db::{Database, DbError, Progress, default_root};
pub use engine::{DEFAULT_DEBOUNCE, Engine, Publisher, Reason, Requester};
pub use extract::{ExtractError, Extractor};
pub use lsp::Backend;
pub use progress::ClientProgress;
pub use scan::{ScanError, Scanner, WorkspaceScanner};

// What the measurement binaries (`dbcheck`, `scanbench`) need beyond that.
// Not a stable API: they live in this repository and move with the code.
pub use extract::{SKIP_DIRS, is_manifest_name};
pub use index::Index;
pub use load::{ArchiveStats, LoadError, Strategy, load};
pub use matcher::Matcher;
pub mod alloc;
```

Remove `pub use span::{Encoding, LineIndex, column};` (no binary uses them; `lsp`, `action` and `diagnostics` reach `crate::span` directly).

- [ ] **Step 2: Build every target**

Run: `cargo build --all-targets 2>&1 | grep -E "^error" | head`
Expected: none. If a bin needs something removed, restore that one item under the second heading rather than reopening the block.

- [ ] **Step 3: Commit**

```bash
git add src/lib.rs
git commit -m "Document the public API as two tiers and drop the unused span exports"
```

---

### Task 7: Lints, the five `expect`s, and the two `unsafe` sites

**Files:**
- Modify: `Cargo.toml` (`[lints]`), create `clippy.toml`, `src/version/pypi.rs:8-19`, `src/db.rs:~500`, `src/index.rs:~30`, `src/model.rs:~515`, `src/diagnostics.rs` (`finding_diagnostic`, `for_file`, `count_and_severity`), `src/action.rs:~94`, `src/alloc.rs`, `src/load.rs:~165`

- [ ] **Step 1: Add the lint tables**

Append to `Cargo.toml`:

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

Create `clippy.toml`:

```toml
allow-unwrap-in-tests = true
allow-expect-in-tests = true
```

- [ ] **Step 2: See what fails**

Run: `cargo clippy --all-targets -- -D warnings 2>&1 | grep -E "^(warning|error)" | sort | uniq -c | sort -rn`
Expected: a list dominated by `missing_docs` and `missing_errors_doc`. Fix the non-doc ones in this task; docs are Task 8. To get a green build meanwhile, temporarily set `missing_docs`, `missing_errors_doc` and `missing_panics_doc` to `"allow"` and turn them to `"warn"` at the start of Task 8.

- [ ] **Step 3: The three regex constants**

In `src/version/pypi.rs`, put `#[expect(clippy::expect_used, reason = "the pattern is a constant; a typo fails the first test that touches it")]` above each of the three `static … LazyLock<Regex>` items.

- [ ] **Step 4: `write_meta` and `Index::build`**

Above `fn write_meta` in `src/db.rs`:

```rust
    #[expect(clippy::expect_used, reason = "Meta is plain data with no map keys; serialisation cannot fail")]
```

Above `pub(crate) fn build` in `src/index.rs`:

```rust
    #[expect(clippy::expect_used, reason = "the counting pass inserts every key the placing pass looks up; keeping two passes is what makes the posting lists contiguous")]
```

- [ ] **Step 5: `Finding::worst` returns `Option`**

In `src/model.rs` change `worst` to end with the `reduce(...)` (delete the `.expect(...)`) and its signature to `pub fn worst(&self) -> Option<&Advisory>`; document: `/// The highest-severity advisory, or None for a finding built with no advisories — which the matcher never produces.`

Callers:
- `src/action.rs:~94`: `let worst = finding.worst()?;` (the enclosing function already returns `Option`).
- `src/diagnostics.rs` `finding_diagnostic` → returns `Option<Diagnostic>`; first line `let worst = finding.worst()?;`; the last expression becomes `Some(diagnostic)`. In `for_file`, replace `out.extend(findings.iter().map(|finding| { … finding_diagnostic(finding, fixable) }))` with `filter_map` over the same closure. In `count_and_severity`, replace `let worst = finding.worst();` with `let Some(worst) = finding.worst() else { return format!("{} advisories", finding.advisories.len()) };`.
- Tests calling `finding_diagnostic(&f, …)` append `.expect("a finding with advisories renders")`; `matcher.rs:387` becomes `findings[0].worst().unwrap().id`.

Run: `cargo test --lib diagnostics:: action:: 2>&1 | grep "test result"` — all `ok`.

- [ ] **Step 6: `SAFETY` comments**

`src/alloc.rs`, above `unsafe impl GlobalAlloc for Counting`:

```rust
// SAFETY: every method forwards to `System` with the same layout it was given
// and only adds a relaxed counter around it, so the allocator's contract —
// unique, correctly aligned blocks that are freed with the layout they were
// allocated with — is exactly `System`'s.
```

`src/load.rs`, replace the existing comment above `unsafe { Mmap::map(&file) }` with one starting `// SAFETY:` and the same text (the archive is published by an atomic rename and never written in place, so the mapping cannot be truncated underneath us; a concurrent refresh renames a new file over the name and this mapping keeps the old inode).

- [ ] **Step 7: Everything else clippy names**

Fix each remaining non-doc warning at its site (`needless_pass_by_value`: take `&` or `impl AsRef`; `redundant_clone`: drop the clone; `doc_markdown`: backtick the identifier). Use `#[expect(clippy::…, reason = "…")]` only where the code is right and the lint is wrong.

Run: `cargo clippy --all-targets -- -D warnings` — clean (with the three doc lints still on `allow`). Run: `cargo test` — all `ok`.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml clippy.toml src
git commit -m "Enforce the lint table; justify or remove every production expect"
```

---

### Task 8: Docs and test grouping

**Files:**
- Modify: `Cargo.toml` (turn the three doc lints to `"warn"`), `src/lib.rs` (crate doc), every `pub` item clippy names, `src/db.rs`, `src/matcher.rs`, `src/diagnostics.rs`, `src/scan.rs` (test submodules)

- [ ] **Step 1: Turn the doc lints on and list the gaps**

Set `missing_docs`, `missing_errors_doc`, `missing_panics_doc` to `"warn"`. Run: `cargo clippy --all-targets -- -D warnings 2>&1 | grep -E "^(warning|error)" -A2 | grep -- "-->" | sort | uniq -c`
Expected: a per-file count of undocumented public items.

- [ ] **Step 2: Document them**

For every item listed: a `///` line saying what it is; for `Result`-returning functions an `# Errors` section naming the variants; for anything that can panic a `# Panics` section (there should be none left after Task 7). Keep to one or two lines — these are internal-facing docs for a private crate, and the module docs already carry the rationale.

- [ ] **Step 3: Crate doc**

Extend the `//!` block in `src/lib.rs` with a layering map:

```rust
//! # Layout
//!
//! Modules depend downward through this list and never upward:
//!
//! - `model` — domain types, `std` only
//! - `span`, `read` — positions and bounded file reads
//! - `version` — per-ecosystem ordering
//! - `manifest`, `extract` — parsers with spans, and the walk that runs them
//! - `osv`, `index`, `load`, `db`, `api` — advisories: decoding, indexing, the cache, the network
//! - `matcher`, `scan` — which advisories apply, composed into one scan
//! - `engine` — when to scan, what to publish
//! - `config`, `diagnostics`, `action`, `progress`, `lsp` — the protocol surface
```

- [ ] **Step 4: Group the large test modules**

In `src/db.rs`, `src/matcher.rs`, `src/diagnostics.rs` and `src/scan.rs`, wrap the tests in `mod <unit>` submodules named for the function or behaviour under test, e.g. in `db.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    // shared helpers stay here

    mod ensure {
        use super::*;
        // ensure_downloads_then_reuses_cache, ensure_revalidates_when_stale, …
    }

    mod heal {
        use super::*;
        // heal_recovers_from_truncated_archive, heal_does_not_reread_an_unchanged_archive, …
    }

    mod verify {
        use super::*;
        // ensure_rejects_corrupt_download, ensure_rejects_checksum_mismatch, crc32c_is_read_from_the_header
    }

    mod progress { … }
}
```

Test names are unchanged; only the module path grows (`db::tests::heal::heal_recovers_from_truncated_archive`). Do the same for `matcher` (`ranges`, `fixes`, `findings`), `diagnostics` (`severity`, `message`, `summary`, `data`) and `scan` (`database`, `revalidation`, `shutdown`).

- [ ] **Step 5: Final verification**

From the repository root:

```bash
make lint && make test && make server
python3 server/scripts/compare-sources.py | tail -1
```

Expected: lint clean, every suite `ok`, and `AGREE — both sources produce identical diagnostics`.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml src
git commit -m "Document every public item and group the large test modules by unit"
```
