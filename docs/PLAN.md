# Zed Package Checker

## Context

JetBrains ships [Package Checker](https://plugins.jetbrains.com/plugin/18337-package-checker) for IntelliJ IDEs: it flags vulnerable and malicious dependencies inline in build files across npm, PyPI, Go modules, Maven and more. Zed has no equivalent — the closest, [`zed-npm-update-checker`](https://github.com/e-simpson/zed-npm-update-checker), is npm-only and checks *staleness*, not security.

This builds that missing piece for Zed, across multiple languages. It is a multi-session project: every stage below is sized to be read and validated on its own before the next begins. On approval this file is copied to `docs/PLAN.md` in the repo and committed; each session starts by reading it, and each stage's completion is a commit against it.

### What the research established

I decompiled the real `packageChecker.jar` (v252.27397.114, from the local GoLand install) rather than guessing:

- **Data sources are Mend.io and OSV.dev** — stated verbatim in `plugin.xml`. OSV.dev is open and free, so half of Package Checker's data is directly available.
- **Architecture is three extension points**: `BuildFileProvider` → `ProjectDependenciesModel` → `ForwardDependenciesBuilderResolver`, with four inspections on top: declared, transitive, API-usage, malicious.
- **The data model is effectively a purl**: `PackageDto(type, namespace, name, version)` and `VulnerabilityDto(id, title, description, cvssScore, cvssVector, cve, cwe, reference)`, with `CallToAction → SingleVersion(newVersion)` driving the "upgrade to a safe version" quick-fix.
- **A portable lesson from a sibling JetBrains plugin**: carry *two* positions per dependency (declaration and version), each a `(file, range)` pair. Their shipped bug assumes both live in the same file. Same trap here: declared in `package.json`, resolved in `package-lock.json`.


### History: how the design was arrived at

The first plan embedded `osv-scanner` as a Go library and let it do everything. The
Stage 0 probe found that it reparses the entire ecosystem database on **every** scan —
4.5 s and 3.1 GB allocated for a one-dependency project, with peak RSS growing across
scans in a process that lives as long as the editor. So the design split: extraction
(what does this project depend on, and where does it say so) from matching (which
advisories apply), with matching owned here and the database loaded once per process.

That split was first built in Go, on osv-scalibr's extractors, and reached a working
end-to-end server. A Rust port was then built to test the language choice against
measurements rather than argument, over the same archives and the same fixtures, and
the two were made to agree diagnostic for diagnostic. The port won on every runtime
number that matters for a long-lived editor process — npm's archive loads in 390 ms
against 1,022 ms, the index retains 85 MiB against 110, the binary is 4.9 MB against
43.8 MB, and its 113 transitive dependencies are all reachable where the Go build
carried 152 of which most were a container scanner it never ran. The one cost is
cross-compilation: Rust needs `cross` for the Linux targets where `CGO_ENABLED=0` needed
nothing. The Go implementation was retired on 2026-09-18 once its remaining behaviour
and tests had been carried across; the sections below describe the Rust server.

Two findings from that comparison shaped the code and are worth keeping:

- **Version ordering has no crate.** osv-scalibr's `semantic` comparator accepts every
  version string in the real archives; the `semver` crate rejects `1.2`, a leading `v`
  and `1.2.3.4`, and `pep440_rs` rejects 3,185 PyPI versions that are in the archive
  right now. Reaching for either would have produced a server that silently missed
  advisories with every test passing. Both comparators are hand-written and checked
  against 116,142 of scalibr's recorded answers (`server/tests/differential.rs`).
- **The default representation is the wrong one.** `String` and `Vec` carry capacity
  words that `Box<str>` and `Box<[T]>` do not; across 228,368 advisories those words
  were 60% of the retained index, invisible in every test, found only by measuring.

There is deliberately **no published index and no CI job producing one**. An earlier
draft had a scheduled workflow publishing a compact index as a release asset; that was
dropped because the same result comes from loading the database properly at runtime,
and a published artifact would mean users trusting ours instead of the upstream bucket
— a poor trade in a supply-chain tool. See "Loading the database" below.

---

## Zed platform constraints

1. **Extensions cannot publish diagnostics.** The `zed:extension` WIT world exports `language-server-command` and little else. The only way to get a squiggle is to *be a language server*; the extension is a Rust→WASM shim that downloads and launches a native binary.
2. **Diagnostics for closed buffers work** — verified in Stage 1: files that were never opened still appear in the diagnostics panel when the server pushes them. Transitive findings are still **anchored to the manifest line of the top-level dependency that pulls them in** — `express` gets the squiggle, not a lockfile nobody opens — but for usability rather than necessity: the manifest is where the user can actually act. Re-publishing on `didOpen` is retained as cheap insurance.
3. **Language attachment is an explicit enumeration.** [`zed-typos`](https://github.com/BaptisteRoseau/zed-typos) lists ~80 language names, most not built-in, and works — so listing languages from other extensions is safe and idiomatic. One server runs per worktree regardless of list length.
4. **`zed_extension_api` 0.8.0 is unpublished** (`publish = false` in-tree). Build against **`0.7`** — confirmed as crates.io's max version.

### Verified against Zed's source

Everything below was read directly, not inferred:

| Claim | Evidence |
|---|---|
| **One server instance per worktree, not per language** — listing 12 languages gives 1 process | `LanguageServerSeed{worktree_id, name, toolchain, settings}` (`lsp_store.rs:284`). `language_name` is passed to `get_or_insert_language_server` but is **not** in the key |
| **Multiple servers coexist on one language; diagnostics merge** — ours won't clobber `json-language-server` on `package.json` | `diagnostics: HashMap<WorktreeId, HashMap<RelPath, Vec<(LanguageServerId, Vec<DiagnosticEntry>)>>>` (`lsp_store.rs:335`); `Buffer::update_diagnostics(server_id, …)` replaces only that server's set |
| `codeDescription` and `Diagnostic.data` survive round-trip | `lsp_store.rs:13328`, `:13339`, `:13354`, `:13374` |
| Dynamic `didChangeWatchedFiles` registration is supported, with unregister | `on_lsp_did_change_watched_files` (`:4200`), `on_lsp_unregister_did_change_watched_files` (`:4238`) |
| Exact language display names for `extension.toml` | `crates/grammars/src/*/config.toml`: `"Go Mod"`, `"JSON"`, `"Python"`, `"Go"`. `"Plain Text"` is defined in `language.rs:175` with `path_suffixes: ["txt"]` |

One caveat surfaced by the first row: `toolchain` *is* part of the server key, so a Python project with several virtualenvs could spawn extra instances. We declare no toolchain, so this should not apply — confirm at Stage 13.

Because `Rust` and `Plain Text` are in the language list, the server starts for nearly every project. It must **idle cheaply** when there is nothing to do: when extraction finds nothing, no database download, no refresh timer, no watchers beyond the manifest globs.

---

---

## Decisions

| Decision | Choice |
|---|---|
| Language server | **Rust**, edition 2024, one crate under `server/` |
| LSP library | `tower-lsp-server`, confined to `lsp.rs`, `progress.rs` and `action.rs` |
| Vulnerability data | **OSV**, two sources the matcher cannot tell apart: per-package answers from osv.dev kept on disk, or the full ecosystem archives. See "Where the advisories come from" |
| Ecosystems | **npm, Go, Python, Cargo** |
| Manifests without lockfiles | Ranges scan at their lowest satisfying version and the finding says it was inferred. Installed-package scanning (`site-packages`, `node_modules`) for exact versions is a post-v1 follow-up |
| npm workspaces | A root lockfile governs the manifests below it (done); transitive attribution to the member that pulls a package in is Stage 11 |
| Reachability | Not built; see "Not in scope" |
| Extension shim | Rust → WASM, resolves binary by release tag, **verifies SHA-256** before executing |
| Debounce | **1000 ms** (matches JetBrains) |
| Distribution | Six targets: macOS and Windows built natively, Linux as static musl via `cross` |

---

## Architecture

### Governing rules

These apply to every stage and are what the code is held to during review:

- **`model.rs` depends on nothing outside `std`.** It is the vocabulary every other
  module speaks, and a domain type that drags in the protocol or the network is one the
  tests cannot construct. `tests/boundaries.rs` checks it, because module privacy cannot.
- **Consumers define traits.** `engine` declares the `Scanner` and `Publisher` it needs;
  `db` declares `Progress`. `scan` and `lsp` implement them. Tests hand the engine a
  fake scanner and the database a recording progress sink without touching either.
- **Parsers are pure.** Source text and a path in, sightings out, no filesystem. A file
  that will not parse yields nothing rather than an error — a manifest caught mid-save is
  a normal event in an editor, not a scan failure.
- **Errors are typed** (`thiserror`) at every boundary that has a caller who can act on
  them, and `anyhow` only where the answer is "log it and keep serving". "Still
  downloading" and "nothing is vulnerable" are different types, never the same empty
  vector.
- **No globals.** Configuration is an `Arc<ArcSwap<Config>>` shared between the LSP
  layer and the scanner, swapped whole on `didChangeConfiguration`.
- **Every read of a project file is bounded** (`read.rs`), and the walk is capped. The
  server reads attacker-chosen bytes from any folder the user opens, and it aborts on
  panic, so a parser panic is the whole language server.
- `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` clean.

### Layout

```
zed-package-checker/
  extension.toml            # Zed manifest (root, required)
  Cargo.toml                # the shim: cdylib, zed_extension_api
  src/lib.rs                # the shim: resolve, download, verify, launch
  Makefile                  # build / test / lint / fmt / release-binary
  docs/PLAN.md              # this document
  server/
    Cargo.toml
    src/
      model.rs              # domain types; std only
      version.rs, semver_like.rs, pypi.rs, digits.rs   # per-ecosystem ordering
      db.rs                 # the archive cache: download, lock, verify, publish, revalidate
      api.rs                # per-package advisories from osv.dev, kept on disk
      osv.rs, load.rs, index.rs   # archives -> in-memory index
      matcher.rs            # which advisories apply, and what fixes them
      extract.rs, manifest.rs     # the walk, and the six parsers with spans
      span.rs, read.rs      # byte offsets -> positions; bounded file reads
      scan.rs               # extract + database + match, composed
      engine.rs             # debounce, coalesce, supersede, publish
      lsp.rs, diagnostics.rs, action.rs, progress.rs, config.rs
      bin/dbcheck.rs, bin/scanbench.rs   # measurement, not shipped behaviour
    tests/                  # integration tests; corpus/ holds the ordering oracle
    testdata/fixtures/{npm-direct,npm-nolock,npm-range-vs-lock,go-mod,py-requirements,rust-cargo}/
  .github/workflows/{ci.yml,release.yml}
```

`server/` is a member of the Cargo workspace at the root, which owns the lockfile, the
release profile and `clippy.toml`. Only the shim is a default member, so a bare
`cargo build --target wasm32-wasip1` never tries to build the server for wasm.

### Core types (`model.rs`)

```rust
/// A half-open span. Lines are one-based; columns are byte offsets, converted
/// to the negotiated encoding (utf-8 preferred, utf-16 fallback) at publish.
pub struct Range { pub start: Position, pub end: Position }

/// Where something was seen: a file and a range within it.
pub struct Site { pub path: PathBuf, pub range: Range }

/// Where a dependency is declared. The version may live in a DIFFERENT file
/// than the declaration (the bug JetBrains shipped), so evidence and
/// declaration are separate sites.
pub struct Anchor { pub declaration: Site }

pub struct Finding {
    pub package: Package,
    pub advisories: Vec<Arc<Advisory>>,   // shared, never copied
    pub evidence: Site,                   // where it was actually found (lockfile line)
    pub declared: Option<Anchor>,         // where the user can act; None if undeclared
    pub paths: Vec<Vec<PackageKey>>,      // root -> ... -> package; empty means direct
    pub reachable: Option<bool>,          // None = not analysed
    pub from_range: bool,                 // version inferred from a range, not pinned
    pub dep_groups: Vec<String>,          // "dev" demotes; malicious never demoted
    pub fix: Fix,                         // Clears(version) | Partial | None
}
```

Advisories carry no `details` field on purpose: the prose is read back from the
archive on demand for the two or three advisories a project matches. Sightings are
deduplicated by `(directory, package, version)` before matching — a lockfile
legitimately holds several versions of one package, and all of them are kept.

### Concurrency design (`engine.rs`)

One tokio task owns every piece of mutable state — the cached report, the published-URI
set, the debounce deadline, the in-flight scan — and everything else talks to it over a
channel. Race-free by construction rather than by discipline.

- **Debounce**: a request sets a deadline **1000 ms** out rather than scanning
  immediately; setting a new deadline *is* the reset, so there is no timer to drain. A
  `git checkout` touching forty files causes one scan.
- **Coalescing**: the channel is bounded and sends use `try_send`. A pending request
  already means "rescan", so extra ones are dropped, not queued — the channel can never
  back up.
- **Supersession**: the scan runs on the blocking pool and a new request aborts it. A
  stale scan's results are never published, and nothing in the scan path polls for
  cancellation.
- **Failure keeps the previous diagnostics.** Clearing on a failed scan would tell the
  user the project became clean, which is not what a failed scan means.
- **Reads** (`findings` for `didOpen`) go through the same channel with a reply slot,
  so the LSP layer never touches engine state directly.
- **Shutdown** is deterministic: the LSP `shutdown` request stops the scanner's
  background download, and dropping the engine ends the task.

Worked example — `npm install lodash`. Manifests and lockfiles are watched, not
`node_modules`, so this is two events:

```
t=0ms      package.json written       -> request -> deadline reset
t=12ms     package-lock.json written  -> request -> deadline reset
t=1012ms   deadline reached           -> ONE scan, no network
           publishDiagnostics
```

### What triggers a scan

| Trigger | Action |
|---|---|
| `initialized` | Immediate scan |
| `didChangeWatchedFiles` — created/changed manifest or lockfile | Debounced scan — **primary path** |
| `didChangeWatchedFiles` — **deleted or renamed** manifest | Publish an **empty array** for that URI immediately, then debounced scan |
| `didSave` on a manifest | Debounced scan (belt-and-braces; watchers can be flaky over SSH) |
| `didOpen` on any manifest | **Re-publish cached diagnostics — no scan.** Ten lines, and it's what defuses Zed's closed-buffer limitation |
| `didChange` (typing) | Nothing — never scan dirty buffers |
| DB becomes ready (first download, or another process finished refreshing) | Scan |
| DB refresh completes | Re-publish if the report changed |


### Database storage

One directory per ecosystem, each holding that ecosystem's `all.zip` — every advisory
as OSV-schema JSON, from `https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip`
— beside a small sidecar recording the ETag and when it was last confirmed current:

```
<root>/osv-scalibr/{npm,PyPI,Go,crates.io}/all.zip
```

The vendor directory keeps osv-scanner's layout so the same cache can be pointed at it
when differential-testing. The root is the platform cache directory — cache, not
config, since it is derived data the user should be able to reclaim by deleting it:

| OS | Path |
|---|---|
| macOS | `~/Library/Caches/zed-package-checker/db/` |
| Linux | `~/.cache/zed-package-checker/db/` |
| Windows | `%LocalAppData%\zed-package-checker\db\` |

**Measured sizes** (via `Content-Length`): npm **205 MB**, PyPI 32.7 MB, Go 11.1 MB,
crates.io 3.3 MB. Only the ecosystems present in the worktree are downloaded, smallest
first and concurrently, each published as it lands so a Rust project is not waiting on
npm's archive to see its own findings. npm is large because 97% of it is `MAL-`
malicious-package reports — which is the malicious-dependency feature itself, so it
cannot simply be dropped.

### Loading the database

Archives are memory-mapped and decoded across every core (`load.rs`) into a compact
index (`index.rs`): advisories in one `Vec`, per-package posting lists as index ranges
into another, keyed by `PackageKey`. Built once per process, rebuilt only when an
archive changes, never per scan. Scans are then hash lookups plus range arithmetic.

| Ecosystem | Advisories | Load | Retained |
|---|---:|---:|---:|
| Go | 9,082 | 17 ms | 7.9 MiB |
| PyPI | 25,029 | 46 ms | 44.6 MiB |
| npm | 228,368 | 390 ms | 85.5 MiB |

Three things account for the numbers, in descending order of value: only the
ecosystems present are loaded; the immutable advisory fields are `Box<str>` and
`Box<[T]>` rather than `String` and `Vec` (60% of the retained index was spare capacity
words before that change); and `details` is not indexed at all — it averages 662 bytes,
was more than half of an early index, and is read back from the archive on demand.

Parallel decoding costs peak memory during the load (the mapping faults the whole
archive in) but nothing afterwards; the sequential strategy exists for measurement and
for the `dbcheck` breakdown of inflate time versus parse time.

### Cross-process safety on the shared cache

The cache is one shared directory, but there is **one process per worktree** — three
open projects means three processes on the same 205 MB file. `db.rs` owns every write:

- **Atomic publish.** Download to a temp file in the same directory, `sync_all`, verify,
  then rename onto `all.zip`. Rename within a filesystem is atomic on POSIX, so a
  concurrent reader sees either the whole old file or the whole new one — never a
  partial. Windows can refuse a rename over an open file; it is retried with backoff.
- **Validate before publish.** CRC32C against the bucket's `x-goog-hash` header,
  streamed rather than read whole, and the zip's central directory opened — *before*
  renaming. Bytes that have not been verified are never published, which closes the
  permanent-corruption case that a plain `write` leaves open.
- **Advisory lock per ecosystem**, through `std`'s file locking. `try_lock` on the scan
  path, never a blocking lock: if another process is already refreshing, this one waits
  for it (bounded) and then uses what it left, rather than sitting at "not ready" until
  the next file event.
- **Re-check staleness after acquiring the lock** — the other process may have just
  finished.
- **Self-heal.** An archive that no longer opens as a zip is deleted and re-fetched. The
  check is memoised on the archive's modification time, because it reads the central
  directory of a 205 MB file and now runs on every revalidation, not once.
- **Revalidation is periodic, not once.** `ready` reports only that an archive exists;
  before this, a server whose archive was already on disk never consulted its freshness
  window again, and an editor left open for a week matched against week-old advisories.
  The scanner now offers the database a chance to revalidate once an hour, and the
  database answers with one conditional request per ecosystem — usually a
  few-hundred-byte `304`. Nothing is reloaded and no rescan is requested unless an
  archive actually changed.

**Three clocks**, which is the precise answer to "how often does this make requests":

| Clock | Frequency | Network |
|---|---|---|
| Archive revalidation | First run, then checked hourly against a 24 h freshness window | One conditional request per ecosystem when due; a download only when the bytes changed |
| Per-package cache (the online path) | Refreshed on a 12 h TTL | A batched query naming the packages, and the few advisory records that matched |
| Scans | Event-driven, 1 s debounce | **No — zero network, ever** |

**First-run honesty.** With the online path disabled, a JavaScript developer's first run
downloads the 205 MB npm archive and sees nothing until it lands, so `$/progress`
reports the download per ecosystem rather than leaving the wait silent. With it enabled
— the default — the first scan answers in about a second from osv.dev while the archive
downloads behind it.

### Settings

Delivered through `initializationOptions`, which the shim forwards from Zed's
`lsp.package-checker.initialization_options`, and re-read on `didChangeConfiguration`
without a restart. Everything has a working default:

```jsonc
{
  "online": {
    "enabled": true,                 // ask osv.dev about this project's packages first
    "exclude": ["@mycompany/"],      // names never sent; matched as a prefix
    "ttlHours": 12                   // how long a cached answer is trusted
  },
  "offline": false                   // never touch the network at all
}
```

`online.exclude` exists because an internal package name can say more than the
dependency does, and osv.dev has no advisories for private packages anyway. Excluded
packages are matched against the archive or not at all — never reported clean without
being checked.

Planned and not yet read: a user `exclude` list of directories, which will **add to**
the built-in skip list (`node_modules`, `.git`, `vendor`, `target`, `dist`, `.venv`)
rather than replace it — replacing is a footgun, and nobody wants to re-specify
`node_modules` to exclude one fixture directory. The built-in list stays in code rather
than in visible defaults: it is a correctness property (a `node_modules` manifest
describes someone else's package), not a preference.

### Testability

Each module is testable in isolation because of the trait seams and the pure parsers:

- `engine` is tested against a **fake `Scanner`** that returns canned reports, fails on
  demand, or blocks — with tokio's clock paused, so the debounce is exercised without
  sleeping and without racing the machine.
- `manifest` is pure: text in, sightings out. A conformance table runs every parser
  over hostile input, CRLF, empty files, and asserts every version span covers exactly
  the version it reported.
- `db`, `scan` and `load` run against a **local server that behaves like the bucket** —
  checksum header, ETag, `304`, injectable delay — and genuine zips built in memory.
  Hermetic, fast, no 205 MB fixture.
- `lsp` and `progress` run over a **fake editor** that drives the real JSON-RPC router
  and answers the server's requests, so the lifecycle state is what a real client would
  produce.
- Version ordering is checked against 116,142 of osv-scalibr's recorded answers.

---

## Stages

Each stage is a reviewable unit: it ends with code you read, a command you run, and a
gate that must pass before the next begins. Stages 0–9 and 12 are done; the numbering
is kept so the history reads in order.

### Stage 0 — Feasibility probe — **DONE**

Cleared the Zed-side unknowns (constraints above) and found the per-scan reparse that
split the design. Findings in the History section; the probe code is gone.

### Stage 1 — Walking skeleton — **DONE**

`extension.toml`, the shim, and a server that implemented only `initialize`/
`initialized` and published one hardcoded diagnostic. `positionEncoding` negotiated here
(prefer `utf-8`) so the encoding decision was settled before any real ranges existed.
Settled constraint 2 empirically: a diagnostic published for a closed file appears.

### Stage 2 — Domain model and contracts — **DONE**

`model.rs`, and the traits each consumer needs. No I/O, no dependencies.
`tests/boundaries.rs` holds it to that.

### Stage 3 — Extraction — **DONE**

`extract.rs` walks the tree (bounded, skip list applied by whole name so `dist` does not
exclude `district`), `manifest.rs` parses what it finds with spans, and `reconcile`
resolves a package seen in both a manifest and a lockfile — scoped to one project, with
a workspace lockfile at the root governing the members below it. `go.mod` `replace` and
`toolchain` directives are applied; `-r` includes in requirements files are followed;
constraints that name no single lowest version (`<`, `!=`, `*`, lists) are skipped
rather than guessed. An unreadable directory is logged and skipped, not a scan failure.

**Gate:** `tests/extraction.rs` asserts the exact `(file, line, column)` of every
dependency in every fixture; `manifest.rs`'s conformance table holds every parser to
the same hostile-input and span invariants.

### Stage 4 — The advisory cache — **DONE**

`db.rs`, per "Cross-process safety" above.

**Gate:** `src/db.rs` tests — download then reuse, revalidate when stale (fake clock,
`304`), corrupt and checksum-mismatched bodies never published, temp files cleaned up,
five concurrent processes make one request, a reader hammering the archive while a
writer republishes never sees a partial file, a truncated archive is healed, an
unchanged one is not re-read.

### Stage 5 — Loading and the index — **DONE**

`osv.rs`, `load.rs`, `index.rs`, per "Loading the database" above.

**Gate:** decode tests (withdrawn and id-less advisories dropped, only the requested
ecosystem kept, range events paired along the timeline, CVSS v3 preferred over v4, GIT
ranges dropped); load tests (a missing archive is an error not an empty index, an
archive nothing decodes from is rejected, one unreadable entry does not lose the rest,
sequential and parallel strategies build the same index). Measurements in the README.

### Stage 6 — Matching — **DONE**

`matcher.rs` for the range arithmetic; `version.rs` and friends for ordering, per the
History section. Handles `introduced`/`fixed` half-open ranges, `last_affected`,
explicit `versions` lists, the `"0"` sentinel, and computes a fix as the lowest
published version that clears *every* advisory on the package — never a downgrade, and
withheld where the index cannot be shown complete.

**Gate:** table-driven boundary tests; `tests/differential.rs` against the ordering
corpus.

### Stage 7 — The engine — **DONE**

`engine.rs`, per "Concurrency design" above.

**Gate:** forty requests inside the window cause one scan; a superseded scan never
publishes; a file that becomes clean is published empty; a deleted manifest is cleared
without waiting; a failed scan keeps the previous diagnostics; shutdown returns with a
scan in flight. Run with the clock paused.

### Stage 8 — First real end-to-end — **DONE**

`scan.rs` composes the three, `lsp.rs` and `diagnostics.rs` publish: severity mapping,
`source`/`code`/`codeDescription`, file watchers, `didOpen` re-publish, `$/progress`
per ecosystem, and a per-manifest summary anchored on a line every file of its kind must
contain (`module` in go.mod, `"name"` in package.json) so it survives reformatting.

**Gate:** `scripts/lsp-smoke.py` over every fixture; the diagnostics land in Zed on the
right lines with the summary matching the per-package findings.

### Stage 9 — Precise spans — **DONE**

Folded into Stage 3: the parser that finds a dependency is the one that knows where it
is, so spans cover the dependency's name (and, separately, the digits of its version)
from the start. Nothing re-reads a manifest to narrow an anchor.

### Stage 10 — Distribution

Release workflow: six targets (`aarch64`/`x86_64` × macOS, Windows, and static-musl
Linux via `cross`), each named `package-checker-lsp-<target-triple>`, published gzipped
with a `SHA256SUMS` over the uncompressed binaries. The shim resolves a binary from the
user's settings, then `PATH`, then downloads the pinned release and **verifies its
SHA-256** before marking it executable — and never from the worktree (see below).

**Gate:** install from a clean machine and have it work; tamper one byte of the binary
and confirm the shim refuses it and deletes it. Cut `v0.0.2`, the first release of this
server.

### Stage 11 — `graph`: npm transitive attribution, incl. workspaces

The largest piece of original work. A lockfile entry carries no parent links, so npm
resolution must be reconstructed: for a node at path *P* depending on *N*, walk *P*'s
ancestors for `<ancestor>/node_modules/N`; BFS from each root recording the first hop.
Falls back to the v1 nested tree.

**Workspaces are in scope.** `package-lock.json` v2/v3 encodes them: `"packages/api":
{...}` entries hold each sub-package's own dependencies, and `"node_modules/api":
{"link": true, "resolved": "packages/api"}` maps the symlink. The BFS starts from
*every* workspace root, and a finding is attributed to the sub-package manifest whose
dependency reaches it — not the root `package.json`. Today a transitive package is
reported on its lockfile line; a direct one on the manifest.

**Explicitly deferred:** `pnpm-lock.yaml`, `yarn.lock`, `bun.lock` have different
structures and each needs its own graph builder.

**Known defect to fix on the way in:** `reconcile` keys the declaration map by exact
directory while the lockfile lookup walks upward, so a workspace member's finding can
lose its manifest anchor.

**Gate:** an `npm-transitive` fixture anchors a 3-deep chain on the correct
`package.json` line with `relatedInformation` pointing at the lockfile; an
`npm-workspaces` fixture anchors on `packages/api/package.json`, not root.
Table-driven tests for hoisting, nested duplicates, cycles, and links.

### Stage 12 — Go ecosystem — **DONE**

A hand-written `go.mod` reader: `require` blocks and singles, `replace` (versioned
replacements substitute name and version; a local path drops the module), the
`toolchain` directive outranking `go` for the `stdlib` finding. Since Go 1.17 every
module is its own line in `go.mod`, so attribution is **identity** — no graph.

### Stage 13 — Python ecosystem

`requirements.txt` is done (free lines, `Plain Text` language; `-r` includes followed;
the lowest-version heuristic marks findings as inferred). Still open: a `pyproject.toml`
parser, and `poetry.lock`/`uv.lock` for pinned versions. Confirm the `toolchain` caveat
in the constraints does not spawn extra server instances.

**Gate:** a `pyproject.toml` fixture and a `uv.lock` fixture produce correct anchors.

### Stage 14 — The upgrade quick fix

*Done. Rewritten 2026-09-18 to record what was built.*

A quick fix on every finding whose `Fix` is `Clears`: it rewrites the version in the
manifest, preserving whatever surrounds it.

The plan as written assumed the version span would have to be carried from the parsers
through `reconcile` into the `Finding`. It does not, and doing so would have been lossy —
`reconcile` keeps only the name span, and drops the manifest sighting outright once a
lockfile supersedes it. Instead `action.rs` re-parses the one file the action is offered
on. Parsers are pure and cost microseconds, so the span only has to exist at the moment
the edit is built, and nothing upstream changed.

- **The span covers the digits alone**, never the operator, so `>=1.0.0 <2.0.0` becomes
  `>=1.4.0 <2.0.0` rather than losing its upper bound, and `v1.6.0` in a `go.mod` keeps
  its `v`. No operator is ever reconstructed, which is what the original plan would have
  required.
- **Lockfiles are never rewritten** — that would mean rewriting integrity hashes and
  resolved URLs — so `package_lock` and `cargo_lock` record no span. Where a lockfile
  pinned the version the action still edits the manifest, and says so in its title:
  *"Update lodash to 4.18.0 in package.json (lockfile not updated)"*.
- **Open manifests are now tracked** (`textDocumentSync.change` went from `NONE` to
  `FULL`) so the span is computed from the buffer rather than from disk. A stale
  diagnostic is a squiggle in the wrong place; a stale *edit* rewrites the wrong bytes in
  a file the user is editing. The edit also carries the document version, so a client
  that has moved on rejects it.
- **Findings are correlated by advisory id**, not by position, wherever the client sends
  `context.diagnostics` — which is what that field is for, and the only correlation that
  survives an edited buffer.
- **The message names the key**, because a quick fix nobody knows about is one nobody
  uses. Only where the fix exists *and* has somewhere to be written: `diagnostics` runs
  the same span lookup the action does, so a transitive dependency anchored in a lockfile
  is never told to press a key that would do nothing.

**Split out of this stage and still open:**

- **Hover** with full advisory prose. Worth doing now that the per-package API cache
  holds `details`; the old objection — reading it meant touching the 205 MB archive —
  no longer applies.
- **Upgrade all** on the summary diagnostic, gopls-style. Same machinery, one extra
  branch.
- **Suppression.** The `osv-scanner.toml` premise here is dead: no `osv-scanner`
  dependency remains, so none of that schema is free any more. It needs a project config
  mechanism that does not exist, and a harder problem behind it — suppressing one
  advisory of several would need `Fix` recomputed, and by then the index the matcher
  borrowed has been dropped. A restructure, not a feature.

**Gate:** met. The suite includes a round trip that applies the produced edit and
re-parses the result; and all six fixtures driven over real stdio LSP, each producing a
valid manifest at the fixed version with everything around it untouched.


### Stage 15 — Enrichment

**EPSS** (FIRST, daily CSV) and **CISA KEV** (1,711 actively-exploited CVEs). KEV promotes to Error; high EPSS promotes; unreachable or dev-only demotes. Both are small, cached, refreshed with the OSV DB, and preserve the offline property.

Both feeds are **CVE-keyed while OSV is GHSA-keyed**, so lookup goes through each advisory's `aliases`; `MAL-` entries have none and are unaffected (they're already Error). Best-effort by nature — say so in the hover.

This is the differentiator: Package Checker shows CVSS alone. A CVSS 9.8 at EPSS 0.02% and a CVSS 6.5 at EPSS 70% should not look identical in your editor.

**Gate:** a KEV-listed CVE renders as Error; the same CVE with KEV disabled renders per CVSS.


### Stage 16 — Hardening and publish

Wire up the full settings schema above end to end — shim forwards
`initialization_options`, server validates and applies them, `didChangeConfiguration`
re-reads without a restart — plus README with **CC-BY 4.0 attribution for OSV/GHSA data**, choose a final extension name (`"Package Checker"` is JetBrains' product name — a distinct one avoids registry friction), then submit to `zed-industries/extensions`.

---


---

## Verification that applies to every stage

- `make test` → `cargo test` in `server/`, which includes the ordering corpus;
  `make lint` → `cargo fmt --check` and `clippy -D warnings` over both crates.
- Real-Zed check via `dev: install dev extension` for any stage that changes observable
  behaviour. Unit tests cannot prove the Zed integration.
- Fixtures under `server/testdata/fixtures/` with pinned known-vulnerable dependencies;
  `tests/extraction.rs` asserts the exact `(file, line, column)` of every dependency.
- `scripts/lsp-smoke.py` drives the binary over stdio; `server/scripts/compare-sources.py`
  asserts the archive and the API produce identical diagnostics over every fixture.
- `tests/boundaries.rs` holds `model.rs` to `std` only.

## Open risks

| Risk | Resolved by |
|---|---|
| ~~Per-scan reparse of the database~~ | **Resolved**: the extract/match split, and an index built once per process |
| ~~Zed's handling of diagnostics for closed buffers~~ | **Resolved Stage 1**: Zed *does* show diagnostics for never-opened files. `didOpen` re-publish is defensive, not load-bearing |
| ~~Version ordering owned here~~ | **Resolved**: hand-written to osv-scalibr's comparator, checked against 116,142 of its recorded answers |
| Range heuristic false positives when the installed version is newer | Accepted for v1; installed-package scanning is the follow-up |
| npm's 205 MB download remains, since there is no published index | The online path answers first; the archive lands in the background with progress; only JavaScript projects pay it |
| Cross-compilation needs `cross` for the Linux targets | One tool in the release workflow; macOS and Windows build natively |
| `ring` (behind `ureq`'s TLS) on `aarch64-pc-windows-msvc` | Unverified until the first release run; `aws-lc-rs` or the platform TLS is the fallback |
| Monorepo scan cost | The walk is capped at 100,000 files and says so; a user-facing `exclude` is planned |
| Python `toolchain` in the server key may spawn extra instances | Stage 13 |

## Where the advisories come from, and why that changed

*Added 2026-09-18.* The plan above assumes one source: download every advisory for
every ecosystem a project uses, then match locally. That is still how `offline: true`
works, and it is why the first run took about five seconds on a mixed repository while a
competing extension answered in under one.

The competitor is fast because it keeps no local database at all — it posts the
dependency list to `api.osv.dev/v1/querybatch` on every session and persists nothing.
That is a different trade, not a faster version of this one: it is useless offline and
re-sends everything on each editor restart.

What this server does now sits between the two. On a cold cache it asks osv.dev about
the dependencies it actually found, **then keeps the answers on disk** and refreshes them
on a twelve-hour TTL. First run is about a second; every run after it is local. The cache
for a real project is a few hundred kilobytes rather than 253 MB.

Three facts made it cheap, all verified rather than assumed:

- The advisory bucket serves one JSON file per advisory (`/{ecosystem}/{id}.json`) in a
  format **byte-identical to an archive entry**, so `osv.rs` decodes it unchanged.
- An **unversioned** query returns a package's complete advisory set — for `lodash`, ten
  rather than the six matching the installed version.
- `Index::build` is pure and in-memory, so `Matcher` and everything downstream is
  untouched; the two sources are indistinguishable to it.

**The correctness trap, stated because it is subtle and silent.** Building the index from
only the advisories that match the installed version omits exactly those whose window
starts *above* it. `Matcher::fix_for` verifies a candidate upgrade by asking the index
what else affects that package, so a filtered index would confidently recommend upgrading
to a version already known to be vulnerable. The second, unversioned query is what
prevents that; where even it comes back truncated, the package is marked partial and no
fix is claimed at all.

**The invariant:** for every package that produces a finding, the index holds that
package's complete advisory set. `server/scripts/compare-sources.py` is the gate —
the same binary over the same fixtures, once against the archive and once against an
empty cache, asserting every published diagnostic is identical.

The privacy position changed with it, deliberately. Names, ecosystems and versions of
dependencies are sent on a cold cache; manifests and source are not, ever. `online.exclude`
keeps named packages off the wire, because an internal package name can say more than the
dependency does and osv.dev has no advisories for private packages anyway. A one-time
`window/showMessage` names what was sent, which is the consent step this class of tool
usually omits.


## Never resolve an executable from the open worktree

Briefly, the shim looked for `server/target/release/package-checker-lsp`
inside the worktree and ran it, so that working on this project needed no
settings. That is arbitrary code execution: a language server runs against
whatever folder the user opens, so any cloned repository shipping a file at that
path would have been executed the moment the folder was opened — no build step,
no prompt, nothing beyond opening it.

It is the same hostile-clone threat model the server already takes seriously
elsewhere (bounded manifest reads, validated advisory ids used as filenames),
and the extension is a worse place to get it wrong, because the extension runs
before any of the server's own guards do.

**A binary path may come from the user's settings or their `PATH`, never from
the project being inspected.** Both of those are things the user controls; the
worktree is not.


## Task: a setting for how much of a package's history to show

*Raised 2026-09-18, from seeing this server and deps-lsp side by side in one panel.*

Today one dependency produces **one** diagnostic, aggregating its advisories:
`gin@1.6.0 — 5 advisories, worst High (CVSS 7.1). Fixed in 1.7.7`. deps-lsp
produces one diagnostic **per advisory**, so the same dependency fills the panel
with `GHSA-h395-qcrw-5vmq`, `GO-2021-0052`, `GO-2023-1737` as separate rows.

Two things could be meant by "show all vulnerabilities", and they are different
features — settle which before building:

1. **Advisories that do not affect the installed version.** Newly possible: the
   per-package cache fetches a package's *complete* set, so for `lodash` we hold
   ten advisories and report the six that match. A setting could surface the
   other four as informational — "clear at this version" — which is useful when
   deciding whether to pin or move.
2. **One diagnostic per advisory instead of one per package.** Purely a
   rendering choice over data already in hand, matching deps-lsp's shape. The
   aggregate exists because a package with seventy-six advisories makes the line
   unreadable, so this would want a cap.

Reading 1 is the one the new data makes possible and the one that says something
the user cannot already get by hovering. Default stays as it is either way:
only what affects the version you have.

Shape, if it is reading 1:

```jsonc
{ "diagnostics": { "scope": "affecting" } }   // default, today's behaviour
{ "diagnostics": { "scope": "all" } }         // plus advisories cleared by this version
```

Both need `Finding` to carry the non-matching advisories, which `Matcher` drops
today — so it is a change to matching, not only to wording.


## What a fifth ecosystem actually costs

Measured against `server/`, which has the same four ecosystems in one flat
crate. Traced rather than estimated: fifteen sites, of which **eleven are
compiler-enforced or need no change at all.**

`db.rs` and `osv.rs` need **zero** changes, because both route through
`Ecosystem::as_str()` and `FromStr`, which route through `Ecosystem::ALL`. The
closed enum and the fixed-length `ALL` array turn most of the work into compile
errors: adding a variant breaks the array length, `as_str`, and `Version::parse`
until each is answered.

| Addition | Edited lines | New code |
|---|---:|---|
| RubyGems (`Gemfile.lock`) | ~10 across 6 files | ~110 parser, no new comparator, no new dependency |
| Composer (`composer.lock`) | ~10 | ~120 parser, reuses `jsonc-parser` |
| Maven (`pom.xml`) | ~10 | ~250 parser + ~180 comparator + an XML dependency |

The ranking is the finding. Maven is expensive not because of the enum but
because `pom.xml` needs `<parent>` inheritance, `${property}` substitution and
`<dependencyManagement>` BOM imports — a line-based reader does not survive
`${spring.version}` — and Maven's version ordering is its own grammar. Composer
and RubyGems are an afternoon each.

**Four sites are not compiler-enforced, and they are the same mistake four
times:** a string-keyed dispatch that should be a table keyed by the closed enum
— `from_purl_type`, the extractor's `parser_for`, the LSP layer's `MANIFESTS`,
and the summary anchor's filename match. They have already drifted: `MANIFESTS`
watches seven files nothing parses (`yarn.lock`, `pnpm-lock.yaml`, `bun.lock`,
`go.sum`, `pyproject.toml`, `poetry.lock`, `uv.lock`), and the summary anchor
names `pyproject.toml`, which no parser reads. The consequence today is only a
spurious rescan, but it is the seam a fifth ecosystem will be added through.

The fix is about twenty lines — one `const FORMATS: [(Ecosystem, &str, Parser)]`
with the other four derived from it — and it is a simplification, not
architecture. **Do it when a fifth ecosystem is actually being added.** With four
and no concrete plan it is a refactor with no forcing function, and the design
otherwise holds: the per-ecosystem job here is parsing alone, with no registry
client, no completion provider and no network client behind it, so the trait and
per-ecosystem crate layout that a version-checking tool needs would be pure
overhead.


## Not in scope for v1

Vulnerable-API-usage for npm and Python (needs Mend-style symbol data no open source
provides); installed-package scanning for exact versions; pnpm/yarn/bun transitive
graphs; Maven/Gradle/Composer/Ruby; commit blocking; a dedicated tool-window UI — Zed's
diagnostics panel is the UI.

Reachability analysis is deferred rather than planned: for Go it would mean shelling
out to `govulncheck` (the server already hands its child the user's shell environment),
it is slow enough to be default-off, and no other ecosystem has an equivalent. EPSS and
KEV enrichment (Stage 15) is the better use of the same effort.
