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

### The decisive find

`osv-scanner/v2` works as a library and `ScannerActions` already exposes what we need: `CompareOffline`, `LocalDBPath`, `DownloadDatabases`, `PluginNetworkDisabled`, `CallAnalysisStates`, `PluginsEnabled`, `ConfigOverridePath`. It depends on `golang.org/x/vuln v1.6.0`, and `osv-scalibr` ships `enricher/reachability/{go,java,rust}` — **govulncheck-style call analysis is a config flag, not a subsystem we write**.

Better still, `models.PackageInfo.Inventory.Location.Descriptor.File` carries `{Path, LineNumber}`, populated by `packagelockjson`, `gomod`, `requirements`, `poetrylock`, `uvlock`, `packagejson`, `yarnlock`, `pnpmlock`. **Line numbers come free for most manifests.**

Two things it does *not* do by default, both verified in source and both handled below: its `lockfile` preset (`internal/scalibrplugin/presets.go`) **excludes the `packagejson` and `pyprojecttoml` extractors** — a project with a manifest but no lockfile yields nothing unless we enable them — and its local-DB cache handling is not safe across processes.

### Stage 0 changed the shape of this (2026-09-16)

The feasibility probe cleared the Zed-side and build-side unknowns, but found that
osv-scanner re-parses the entire ecosystem database on **every** scan. Driving
`osv-scalibr` directly for **extraction only** costs 500 µs and 12 MB.

Measured against the real npm database, one dependency:

| | Wall time | Peak RSS | Total allocated |
|---|---|---|---|
| One scan | 4.45 s | 600 MB | 3.4 GB |
| Two scans, same process | 8.72 s | 922 MB | 6.5 GB |

Peak RSS is the kernel's figure; "total allocated" is Go's `TotalAlloc`, which is
cumulative throughput and not a memory reading. The problem is not transient spikes —
it is a sustained several-hundred-megabyte footprint in a process that lives as long as
the editor, whose high-water mark grows across scans.

So the design splits in two, and several sections below are written against the original
single-`DoScan` shape — where they conflict, this section wins:

- **`extract`** (was `scan`) drives `osv-scalibr` extractors directly. It is the only
  package importing scalibr. Gets manifest/lockfile parsing for 21 ecosystems with line
  numbers, which is the genuinely hard part to replicate.
- **`match`** is ours: look each package up and evaluate version ranges.
  `deps.dev/util/semver` (already a scalibr dependency) handles per-ecosystem version
  semantics.

Owning the matcher costs us per-ecosystem range semantics, which is why `match` is
differential-tested against osv-scanner's own results.

There is deliberately **no index package and no CI job**. An earlier draft had a
scheduled workflow publishing a compact index as a release asset; that was dropped
because the same result comes from loading the database properly at runtime, and a
published artifact would mean users trusting ours instead of the upstream bucket — a
poor trade in a supply-chain tool. See "Loading the database" below.

### Why Go, not Rust

Server language and analyzable ecosystems are orthogonal. `osv-scalibr` covers 21 ecosystems (including `rust`), and its reachability enricher covers Rust too. Adding Cargo later is a `locate/cargo.go`, not a rewrite. There is no Rust equivalent of osv-scanner — `cargo-audit`/`rustsec` is Rust-only — so Rust would mean reimplementing 21 extractors, per-ecosystem version-range matching, the offline DB, and reachability. Go also brings `golang.org/x/mod/modfile` and a `CGO_ENABLED=0` policy that makes cross-compilation trivial.

The lock-in is osv-scanner itself, which is why `internal/scan` is the only package allowed to import it.

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
| npm extractor populates line numbers | `packagelockjson.go:347` → `LocationFromPathAndLine(input.Path, pkg.Line)` |
| `ParentIDs` is **not** populated for npm — the transitive graph is ours to build | `packagelockjson.go:337-348` sets no `ID`/`ParentIDs` |
| `packagejson`/`pyprojecttoml` extractors are **off by default** | `presets.go` `lockfile` preset: 0 references to either |

One caveat surfaced by the first row: `toolchain` *is* part of the server key, so a Python project with several virtualenvs could spawn extra instances. We declare no toolchain, so this should not apply — confirm at Stage 12.

Because `Rust` and `Plain Text` are in the language list, the server starts for nearly every project. It must **idle cheaply** when there is nothing to do: on `ErrNoPackagesFound`, no DB download, no refresh timer, no watchers beyond the manifest globs.

---

## Decisions

| Decision | Choice |
|---|---|
| Language server | **Go 1.23+**, embedding `osv-scanner/v2` |
| LSP library | `go.lsp.dev/protocol` v1.0.1 + `go.lsp.dev/jsonrpc2`, confined to `internal/lsp` (see risks — this is a single tag after years dormant, not an established maintenance record) |
| Vulnerability data | **Local OSV database**, refreshed in background. No per-scan network. |
| MVP ecosystems | **npm, Go, Python** (Cargo as stretch) |
| Manifests without lockfiles | **Enable `packagejson` + `pyprojecttoml` extractors**; ranges scan at their lowest satisfying version (the heuristic `requirements` already uses); message says "range may include vulnerable versions". Installed-package scanning (`site-packages`, `node_modules`) for exact versions is a post-v1 follow-up |
| npm workspaces | **In scope for Stage 10** — one root lockfile, many manifests, attribution to the correct sub-package |
| Reachability | **Go only**, `reachability/go/source` plugin, default off |
| Extension shim | Rust → WASM, resolves binary by release tag, **verifies SHA-256** before executing |
| Debounce | **1000 ms** (matches JetBrains) |
| First-run download | Full ecosystem zips as published (npm 205 MB) — compact-index optimization deferred until there is evidence it's needed |

---

## Go architecture

### Governing rules

These apply to every stage and are what I'll hold the code to during review:

- **Dependencies point inward.** `internal/model` has zero external imports. `internal/lsp` is the only package importing `go.lsp.dev`; `internal/scan` is the only one importing `osv-scanner`. **`scan.Scan` returns fully-converted `model` types — never `models.PackageSource` or any osv-scanner type.** Both third-party lock-ins are therefore one-file replacements. Enforced with a test that walks `go list -deps`.
- **Consumers define interfaces.** `engine` declares the `Scanner`, `Locator`, `DB` interfaces it needs; `scan`, `locate`, `db` return concrete structs that happen to satisfy them. Accept interfaces, return structs.
- **`context.Context` first parameter on every blocking call**, propagated to `DoScan` and every HTTP request. No `context.Background()` below `main`.
- **Errors wrapped with `%w`**; sentinel errors (`ErrDatabaseNotReady`, `ErrNoManifests`) declared in the package that owns the condition. No naked `_ =`.
- **Functional options** for construction: `scan.New(scan.WithLocalDB(path), scan.WithGoReachability(false))`. No config structs with 12 fields, no globals.
- **Table-driven tests with subtests** throughout; `-race` in CI; golden files for `locate` output.
- Every exported type and function documented; `gofmt` + `golangci-lint` clean.

### Layout

```
zed-package-checker/
  extension.toml            # Zed manifest (root, required)
  Cargo.toml                # cdylib, zed_extension_api = "0.7"
  src/lib.rs                # the shim, ~200 lines
  Makefile                  # build / test / lint / fmt
  docs/PLAN.md              # this document, committed
  server/
    go.mod
    cmd/package-checker-lsp/main.go   # flag parsing, wiring, signal handling only
    internal/
      model/    # domain types; ZERO external deps
      extract/  # ONLY package importing osv-scalibr
      locate/   # manifest -> precise ranges
      graph/    # transitive -> top-level attribution
      db/       # offline OSV DB lifecycle
      fix/      # safe-version computation
      enrich/   # EPSS + CISA KEV
      engine/   # orchestration + concurrency
      lsp/      # ONLY package importing go.lsp.dev
    testdata/
      osvdb/    # tiny hand-built all.zip per ecosystem, 2-3 synthetic advisories each
      fixtures/{npm-direct,npm-nolock,npm-transitive,npm-workspaces,go-mod,py-poetry,py-uv,py-requirements}/
  .github/workflows/{ci.yml,release.yml}
```

A Go module is directory-scoped, so `server/` coexists with the root `Cargo.toml`/`extension.toml` without conflict.

### Core types (`internal/model`)

```go
// Range is a half-open span in a file. Column units follow the negotiated
// positionEncoding (utf-8 preferred, utf-16 fallback).
type Range struct{ StartLine, StartCol, EndLine, EndCol int }

// Anchor is where a dependency is declared. Version may live in a DIFFERENT
// file than the declaration (the bug JetBrains shipped), so it carries its own path.
type Anchor struct {
    Path        string
    Decl        Range
    VersionSpan *Range // nil when the version isn't textually present
    VersionPath string // "" means same file as Decl
}

type Finding struct {
    Pkg        Pkg
    Advisories []Advisory
    Declared   *Anchor          // where the user can act; nil if undeclared
    Evidence   Anchor           // where it was actually found (lockfile line)
    Paths      [][]PackageKey   // root -> ... -> Pkg; empty means direct
    Reachable  *bool            // nil = not analyzed
    FromRange  bool             // version came from a range heuristic, not a pin
}
```

Findings are **deduplicated by `(package, version, advisory)`** before publish — a project with both `package-lock.json` and `yarn.lock` would otherwise report everything twice.

### Concurrency design (`internal/engine`)

The engine uses a **single goroutine owning all mutable state** (actor pattern) rather than mutexes. Scan state, the debounce timer, and the published-URI set are only ever touched inside `run()`, so the design is race-free by construction rather than by discipline.

```go
type Engine struct {
    requests chan request      // buffered(1), coalescing
    queries  chan query        // synchronous reads from LSP handlers
    done     chan struct{}
    wg       sync.WaitGroup
}

func (e *Engine) Start(ctx context.Context) // spawns run(); returns immediately
func (e *Engine) Close() error              // closes done, waits on wg — deterministic shutdown
```

`run()` is a `select` loop over `requests`, `queries`, `timer.C`, `ctx.Done()` and `done`. Key behaviours:

- **Debounce**: a request resets a **1000 ms** timer rather than scanning immediately, so a `git checkout` touching 40 files causes one scan.
- **Coalescing**: `requests` is buffered with capacity 1 and sends are non-blocking (`select { case ch <- r: default: }`). A pending request already means "rescan", so extra ones are dropped, not queued — the channel can never back up.
- **Cancellation**: an in-flight scan holds a `context.CancelFunc`. A new request cancels it — a stale scan's results are never published.
- **Reads** go through `queries` (a channel carrying a reply channel), so LSP handlers never touch engine state directly.

Every goroutine in the program has exactly one owner and a `Close`. `main` wires `signal.NotifyContext` to the root context.

Worked example — `npm install lodash`. We watch manifests and lockfiles only, not `node_modules`, so this is two events:

```
t=0ms      package.json written       -> request -> timer reset
t=12ms     package-lock.json written  -> request -> timer reset
t=1012ms   timer fires                -> ONE scan, no network
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

### Database storage and request cadence

Layout is fixed by osv-scanner; we pass `LocalDBPath` and it manages the tree:

```
<LocalDBPath>/osv-scalibr/{npm,PyPI,Go}/all.zip   # NOTE: osv-scalibr, not osv-scanner
```

Each `all.zip` holds every advisory for that ecosystem as OSV-schema JSON. Source: `https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip`; the 46-ecosystem list is at `ecosystems.txt` in the same bucket. We choose the path explicitly (`os.UserCacheDir()` + our name) rather than relying on osv-scanner's env-var fallback — cache, not config, since it's derived data users should be able to reclaim:

| OS | Path |
|---|---|
| macOS | `~/Library/Caches/zed-package-checker/db/` |
| Linux | `~/.cache/zed-package-checker/db/` |
| Windows | `%LocalAppData%\zed-package-checker\db\` |

**Measured sizes** (via `Content-Length`, not estimated): npm **205.2 MB**, PyPI 32.7 MB, Go 11.1 MB, Packagist 10.1 MB, Maven 9.7 MB, RubyGems 4.1 MB, crates.io 3.3 MB. We download only the ecosystems present in the worktree. npm is large because it is dominated by `MAL-` malicious-package reports — which is the malicious-dependency feature itself, so it can't simply be dropped.

**The load cost.** osv-scanner's `zipDB.load()` (`osvlocal/zip.go:210-234`) reads the whole zip into memory and **decompresses and `protojson.Unmarshal`s every advisory in the ecosystem**, keeping only those touching packages present. Retained memory is small; peak memory is ~205 MB for npm and the CPU cost is on the order of 100k JSON parses. Whether this happens **per scan or once per process** decides whether the 1 s debounce is meaningful — it is a Stage 0 question, and Stage 3 measures duration *and* peak RSS. If it's per scan and slow, the first remedy is a compact derived index (see Stage 4), not a daemon.

### Loading the database

The 600 MB comes from *how* osv-scanner reads the archive, not from the work itself:

```go
cache, err := os.ReadFile(db.StoredAt)   // all 205 MB, held for the whole walk
zipReader, _ := zip.NewReader(bytes.NewReader(cache), int64(len(cache)))
```

Three changes remove almost all of it, in descending order of value. None needs a new
file format, a build step or anything to invalidate.

**Load only the ecosystems present.** Do this first: roughly twenty lines, and the
largest effect for most users. A Go project reads 11 MB rather than npm's 205 MB, a
Python one 33 MB. Only JavaScript projects pay full price, so for most projects the
problem simply does not arise. The ecosystem set comes from extraction, which has
already run.

**Stream the archive from disk.** `zip.OpenReader(path)` instead of `os.ReadFile` plus
`bytes.NewReader`, so the 205 MB is never resident. Roughly ten lines.

**Parse once per process into a compact in-memory index.** Build
`map[PackageKey][]Advisory` at startup, keeping only the fields matching needs — id,
aliases, affected ranges, severity, summary, url — and discarding each advisory after
extracting them. Rebuilt when the database refreshes, never per scan. Roughly 150 lines.

Scans then become map lookups, and the startup cost is paid once in the background. A
persistent on-disk index would additionally avoid that one-off startup parse, but it
buys only a few seconds nobody is waiting on, and costs a versioned format, a builder, a
reader, invalidation, and cross-process coordination so two editor windows do not
rebuild at once — machinery that can be *wrong*, in a tool whose value depends on being
right. Reconsider only if Stage 4's measurements are bad.

**Unmeasured, and worth measuring at Stage 4 rather than reasoning about:** peak RSS once
streaming, the retained size of the compact index, and whether the 600 → 922 MB growth
continues or plateaus. Two data points are not a trend.

### Cross-process safety on the shared cache

The cache is one shared directory, but there is **one process per worktree** — three open projects means three processes on the same 205 MB file. osv-scanner's own cache handling is not safe for this, verified in `enricher/vulnmatch/osvlocal/zip.go`:

```go
_ = os.WriteFile(db.StoredAt, body, 0644)   // :151 — non-atomic, error discarded
...
if db.Offline { return cache, nil }         // :97-103 — no checksum validation
```

Three failure modes follow: a multi-second window where the file is truncated mid-write; no locking, so N processes can each download 205 MB and interleave writes; and — worst — a crash mid-write leaves a corrupt zip that **never self-heals**, because the CRC32C check that online mode performs is skipped in offline mode, which is our mode.

So `internal/db` owns all fetching and osv-scanner is only ever allowed to **read**:

- **`DownloadDatabases: false`, always.** Paired with `CompareOffline: true`, osv-scanner never writes to the cache.
- **Atomic publish.** Download to `all.zip.tmp.<pid>.<rand>` in the same directory, `fsync`, then `os.Rename` onto `all.zip`. Rename within a filesystem is atomic on POSIX, so a concurrent reader sees either the whole old file or the whole new one — never a partial.
- **Validate before publish.** Open the temp file as a zip and check CRC32C against the bucket's `x-goog-hash` header *before* renaming. We never publish bytes we haven't verified — this closes the permanent-corruption case.
- **Advisory lock per ecosystem**, via `github.com/gofrs/flock` (`flock` on POSIX, `LockFileEx` on Windows). **`TryLock` on the scan path, never a blocking `Lock`**: if another process is already refreshing, the scan path skips and uses what's on disk.
- **A background waiter for the skipped case.** If `TryLock` fails *and* there is no usable DB yet, a separate goroutine blocks on `Lock` (with context) and, when the other process finishes, releases and fires a scan request. Without this, the second process would sit at `ErrDatabaseNotReady` until the next file event — which could be never.
- **Re-check staleness after acquiring the lock** — the other process may have just finished, so don't re-download.
- **Self-heal on startup.** Validate each `all.zip` opens as a zip; if not, delete and re-fetch. Recovers from any pre-existing corruption.
- **Windows caveat**: `os.Rename` over a file another process has open can fail with `ERROR_ACCESS_DENIED`. The read window is short (osv-scanner uses `os.ReadFile`), so retry the rename with backoff.

The cache stays shared rather than per-worktree — 205 MB × N projects is not acceptable, and sharing is safe once the above holds.

**Three independent clocks**, which is the precise answer to "how often do we make requests":

| Clock | Frequency | Network |
|---|---|---|
| OSV DB refresh | First run, then every 24 h in background | **Yes** — the only significant traffic |
| EPSS + KEV refresh | Every 24 h, alongside the DB | Yes — 4.1 MB combined (EPSS 2.5 MB gz, KEV 1.6 MB / 1,711 entries; both measured) |
| Scans | Event-driven, 1 s debounce | **No — zero network, ever** |

A scan makes no network requests at all: `CompareOffline: true`, `PluginNetworkDisabled: true`, `TransitiveScanning.Disabled: true`. Steady state for a full day's work is **one conditional request per ecosystem per 24 h**, usually a few-hundred-byte `304 Not Modified`.

**First-run honesty.** A JS developer's first run downloads the binary (size TBD at Stage 0) plus the 205 MB npm database, and sees nothing until that completes. `$/progress` reporting ships with the first end-to-end stage, not at hardening — otherwise the first real users conclude it's broken.

### Settings

Delivered through `initializationOptions`, which the Rust shim forwards from
Zed's `lsp.package-checker.initialization_options`. Everything below has a
working default; the schema exists so users are never forced to patch source.

```jsonc
{
  "exclude": ["fixtures/**", "third_party"],   // ADDED to the built-in skip list
  "ecosystems": ["npm", "Go", "PyPI"],         // omit to scan every supported one
  "severityThreshold": "low",                  // low | medium | high | critical
  "includeDevDependencies": true,
  "goReachability": false,                     // slow, shells out to the Go toolchain
  "debounceMs": 1000,
  "maxScanSeconds": 60,
  "database": {
    "path": null,                              // defaults to the OS cache dir
    "refreshHours": 24
  }
}
```

Two decisions worth stating. `exclude` **adds to** the built-in skip list
(`node_modules`, `.git`, `vendor`, `target`, `dist`, `.venv`, dotfiles) rather
than replacing it — replacing is a footgun, and nobody wants to re-specify
`node_modules` to exclude one fixture directory. And the built-in list stays in
code rather than in defaults the user can see: it is a correctness property (a
`node_modules` manifest describes someone else's package), not a preference. A
`replaceExclude` escape hatch can follow if anyone needs it.

Every package that consumes settings takes them as a struct through its
functional options, so nothing reaches for a global.

### Testability

Each stage is testable in isolation because of the interface seams:

- `engine` is tested against a **fake `Scanner`** that returns canned reports and blocks on demand — so the concurrency stage can be fully validated before `scan` works at all.
- `locate` is pure: `([]byte, PackageKey) → Anchor`. Golden-file tests, zero I/O.
- `graph` is pure: lockfile bytes → adjacency. Table-driven.
- `scan` is tested against committed fixture projects and **`testdata/osvdb/` — tiny hand-built `all.zip` files with 2-3 synthetic advisories per ecosystem**. Hermetic, fast, and no 205 MB fixture.
- Only the LSP layer needs an integration harness.

---

## Stages

Each stage is a reviewable unit: it ends with code you read, a command you run, and a gate that must pass before the next begins. Each lands as its own commit. `locate` (Stage 8) deliberately comes *after* the first end-to-end (Stage 7): `Inventory` already supplies line numbers, so real diagnostics appear in Zed one stage sooner, and `locate` then only adds precise spans for the code action.

### Stage 0 — Feasibility probe — **DONE** (see README for results; code in `probe/`)

Everything that could invalidate the architecture and that a source read cannot settle. The Zed-side assumptions are already verified above; these need a running Go program.

1. Does `pkg/osvscanner` cross-compile `CGO_ENABLED=0` for darwin/linux/windows × arm64/amd64? (Their goreleaser mandates it, but that proves *their* binary builds, not our import path.)
2. How big is the stripped binary? >80 MB means importing individual scalibr extractors rather than `pkg/osvscanner`.
3. **Is `models.PackageInfo.Inventory` non-nil at the `pkg/osvscanner` result level?** The extractor sets `Location` (verified), but the field is tagged `json:"-"` and I have not confirmed it survives to the public API. **The "free line numbers" design depends entirely on this.**
4. Do `CompareOffline` + `LocalDBPath` work programmatically without the env var? Is `GroupInfo.MaxSeverity` a number or a label?
5. **Is `zipDB.load()` invoked per `DoScan` call, or cached across calls within a process?** Determines whether every debounced scan re-parses the ecosystem.
6. Does `PluginsEnabled: ["javascript/packagejson", "python/pyprojecttoml"]` add those extractors on top of the default preset, and do their `Location`s carry line numbers?

**Gate:** all six targets build, size is acceptable, `Inventory` is non-nil with real line numbers, #5 and #6 answered. Findings recorded in the README. If #3 fails, `locate` grows substantially and we re-plan before building anything on top.

### Stage 1 — Walking skeleton — **DONE**

Repo scaffolding, `extension.toml`, the Rust shim pointing at a **local** binary path, and a Go server that implements only `initialize`/`initialized` and publishes one **hardcoded** diagnostic on line 1 of `package.json`. Negotiate `positionEncoding` here (prefer `utf-8`) so the encoding decision is settled before any real ranges exist.

**Review:** `extension.toml`, `src/lib.rs`, `main.go`, `internal/lsp/server.go`.
**Gate:** a squiggle appears in Zed. Then publish it while `package.json` is *closed* and open it afterwards — this settles constraint 2 empirically, at the cheapest possible moment.

### Stage 2 — Domain model and contracts — **DONE**

All of `internal/model`, plus the interface declarations each consumer needs. No I/O, no dependencies. This is a pure reading stage — the whole vocabulary of the system in one sitting, which is the cheapest point to change names and shapes.

**Review:** every type in `internal/model`, every interface.
**Gate:** `go build ./...`, `go vet`, doc comments on all exported items. Review is the gate.

### Stage 3 — `extract` package

The osv-scalibr driver behind `Extractor`, returning `[]ExtractedPackage`. Functional options; `ErrVulnerabilitiesFound` treated as the success path; `TransitiveScanning.Disabled: true` (the network-backed resolver — would break the offline guarantee); `ExcludePatterns` for `node_modules`/`.venv`/`vendor`; **`PluginsEnabled` adds `packagejson` and `pyprojecttoml`** with `FromRange` set on their findings; dedup by `(package, version, advisory)`. `osvschema.Vulnerability` is a protobuf — getters only, never `encoding/json`.

Exercised by a **throwaway CLI harness** (`cmd/scanharness`), not the LSP, so scanning is validated independently of the editor.

The skip list moves here from `internal/lsp` and becomes config-driven from the
start: `SkipDirRegex` built from the built-in names plus any `exclude` patterns.
Retrofitting configurability onto a hardcoded list after three call sites depend
on it is the expensive order to do this in.

**Review:** `internal/extract/*.go`.
**Gate:** `scanharness testdata/fixtures/npm-direct` prints real GHSA IDs with line numbers; `npm-nolock` prints findings with `FromRange`. **Measure and record: wall time and peak RSS for a scan** against the real npm DB on a mid-size project. `go test -race ./internal/scan/...` against `testdata/osvdb/`.

### Stage 4 — `db` package

Offline OSV database lifecycle, per the layout, paths and cross-process rules above. Download only ecosystems present in the worktree. Background refresh past 24 h with `If-Modified-Since`. Explicit `ErrDatabaseNotReady` rather than silently-empty results.

Also owns **loading**, per "Loading the database" above: ecosystem filtering first, then
streaming from disk, then the compact in-memory index rebuilt only on refresh. The
download stays simple — full ecosystem zips as published, npm's 205 MB included, in the
background so the editor stays usable, with other ecosystems scannable meanwhile.

**Review:** `internal/db/*.go`, especially goroutine lifecycle, context handling, and the cross-process safety rules.
**Gate:**
- Cold start downloads; second start doesn't.
- **Measure and record peak RSS** for: a Go-only project, a Python-only project, and an
  npm project, each at startup and after five scans. These are the numbers that decide
  whether anything further is needed; record them in the README next to Stage 0's.
- An npm project's steady-state RSS after the index is built is well under the 600 MB
  baseline, and does not grow across five scans.
- **Offline assertion**: with the DB cached, run the harness under `tcpdump -i any -n 'not port 53'` and confirm zero egress. This is the privacy claim — tested, not assumed.
- **Concurrency**: launch 3 harness processes simultaneously against one empty cache. Exactly one downloads; the other two skip, wait, and **scan successfully once it finishes**.
- **Corruption recovery**: truncate `all.zip` to half its size, start the server, confirm it detects, re-fetches and scans successfully.
- **Torn-read**: while one process rewrites the zip in a loop, another scans in a loop; no scan ever fails.

### Stage 5 — `match` package

Ours, because we no longer use osv-scanner's matcher. Looks each extracted package up in
the in-memory index from Stage 4 and decides whether it falls inside an advisory's
affected ranges.

The hard part is version semantics: npm semver, PEP 440, Go's scheme and Cargo all order
versions differently, and `1.0.0-beta` sorting before `1.0.0` is the sort of detail that
silently produces wrong answers. `deps.dev/util/semver` (already a scalibr dependency)
handles this, so the work is wiring rather than invention. Handles `Introduced`/`Fixed`
half-open ranges, `LastAffected`, explicit `Versions` lists, and the "0" sentinel.

**Review:** `internal/match/*.go`.
**Gate:**
- Table-driven tests per ecosystem covering boundaries: exactly `Introduced`, exactly
  `Fixed`, prereleases either side of a boundary, disjoint backported ranges, and an
  advisory with no fix.
- **Differential test against osv-scanner.** Run both over the same fixtures and assert
  identical findings. This is the safety net for having taken matching in-house, and it
  is worth the awkwardness of keeping osv-scanner as a test-only dependency.

### Stage 6 — `engine` package *(the concurrency stage)*

The actor loop, debounce, coalescing, cancellation, publish-state tracking including **empty arrays to clear stale diagnostics**, deletion handling, and the idle-cheaply path. Tested entirely against a fake `Scanner` — no osv-scanner, no LSP.

**Review:** `internal/engine/*.go`. This is the stage most likely to harbour subtle bugs and deserves the closest reading.
**Gate:** `go test -race -count=100 ./internal/engine/...` clean. Explicit tests for: 40 rapid requests inside the 1 s window → exactly 1 scan; a new request cancels an in-flight scan and its results are never published; a deleted manifest gets an empty publish; `Close()` terminates every goroutine (`goleak`). Debounce tests use an injected clock, not `time.Sleep`.

### Stage 7 — First real end-to-end

Wire stages 3–5 into the LSP layer. Severity mapping, `source`/`code`/`codeDescription`, file watchers, `didOpen` re-publish, **`$/progress` for DB download**. Ranges are full lines from `Inventory`. npm only.

**Review:** `internal/lsp/diagnostics.go`, the wiring in `main.go`.
**Gate:** open a real vulnerable npm project in Zed and see correct, correctly-positioned diagnostics; open one with no lockfile and see `FromRange` findings; first run shows download progress. First genuinely useful build.

### Stage 8 — `locate` package (npm)

`package.json` → precise `(file, range)` pairs for declaration and version span, across `dependencies`/`devDependencies`/`optionalDependencies`/`peerDependencies`. Includes the byte-offset ↔ column helper for both encodings. Pure functions, golden-file tests.

**Review:** `internal/locate/*.go` + golden files.
**Gate:** golden tests pass including edge cases — nested scopes (`@scope/pkg`), duplicate names across sections, CRLF files, non-ASCII content. Diagnostics in Zed now underline the dependency name, not the whole line.

### Stage 9 — Distribution

Release workflow (six targets, `CGO_ENABLED=0`), asset naming contract, **`SHA256SUMS` published with every release**, shim switched to `github_release_by_tag_name` + `download_file` + **verify SHA-256** + `make_file_executable`, with `LanguageServerInstallationStatus::Failed` and a clear message when GitHub is unreachable. Cut `v0.0.1`.

**Gate:** install from a clean machine with no Go toolchain and have it work; tamper one byte of the binary and confirm the shim refuses it. Doing this early means a broken distribution path surfaces now, not after six more stages of content.

### Stage 10 — `graph` package (npm transitive, incl. workspaces)

The largest piece of original work. `extractor.Package.ParentIDs` exists but is **not populated** by `packagelockjson` (confirmed), so npm resolution must be reconstructed: for a node at path *P* depending on *N*, walk *P*'s ancestors for `<ancestor>/node_modules/N`; BFS from each root recording the first hop. Falls back to the v1 nested tree.

**Workspaces are in scope.** `package-lock.json` v2/v3 encodes them: `"packages/api": {...}` entries hold each sub-package's own dependencies, and `"node_modules/api": {"link": true, "resolved": "packages/api"}` maps the symlink. The BFS starts from *every* workspace root, and a finding is attributed to the sub-package manifest whose dependency reaches it — not the root `package.json`.

**Explicitly deferred:** `pnpm-lock.yaml`, `yarn.lock`, `bun.lock` have different structures and each needs its own graph builder. Their direct-dependency diagnostics already work via `Inventory`; only transitive attribution falls back to the lockfile line until their builders land.

**Review:** `internal/graph/npmlock.go`.
**Gate:** `npm-transitive` anchors a 3-deep chain on the correct `package.json` line with `relatedInformation` pointing at the lockfile; `npm-workspaces` anchors on `packages/api/package.json`, not root. Table-driven tests for hoisting, nested duplicates, cycles, and links.

### Stage 11 — Go ecosystem

Near-free: `x/mod/modfile` gives exact positions, and since Go 1.17 every module is its own line in `go.mod`, so attribution is **identity** — no graph, no `go mod graph`.

**Gate:** a Go fixture with a known-vulnerable indirect dependency shows a diagnostic on the right `go.mod` line.

### Stage 12 — Python ecosystem

`requirements.txt` (free lines, `Plain Text` language; the extractor's lowest-version heuristic sets `FromRange`) → `pyproject.toml` locator → `poetry.lock`/`uv.lock` graphs. Confirm the `toolchain` caveat doesn't spawn extra server instances.

**Gate:** all three Python fixtures produce correct anchors.

### Stage 13 — Hover, code actions, suppression

Full advisory markdown on hover. Two code actions:
- **Upgrade**: minimum-safe = max of `fixed` events across advisories hitting the package, compared with `osv-scalibr/semantic` (public; handles npm semver, PEP 440, Go, Cargo), rewritten preserving the operator (`^4.17.15` → `^4.17.21`). Direct deps with a same-file version span only.
- **Ignore this advisory**: appends to `osv-scanner.toml` at the worktree root and rescans. The mechanism is free — osv-scanner honours it via `ConfigOverridePath`, and the schema (verified in `internal/config/config.go:16-49`) is richer than just an ID list:

```go
type IgnoreEntry struct {
    ID          string    `toml:"id"`
    IgnoreUntil time.Time `toml:"ignoreUntil"`   // snooze, not just suppress
    Reason      string    `toml:"reason"`
}
type PackageOverrideEntry struct {
    Name        string `toml:"name"`
    NameIsRegex bool   `toml:"nameIsRegex"`
    Ignore      bool   `toml:"ignore"`
    // + Version, Ecosystem, Group, EffectiveUntil, Reason
}
```

So three actions fall out almost for free, mirroring JetBrains' `IgnoreReason`/`excludeList`: **ignore this advisory**, **snooze it for 30 days** (`ignoreUntil`), and **ignore this package entirely** (`PackageOverrides`, which also supports regex and dev-group scoping). `Config.UnusedIgnoredVulns()` additionally lets us surface ignore entries that no longer match anything — worth a diagnostic on the toml itself so suppressions don't rot silently.

**Gate:** applying the upgrade in Zed produces a valid manifest and the diagnostic clears on rescan; applying ignore clears it and the toml is well-formed; an expired `ignoreUntil` brings the diagnostic back.

### Stage 14 — Enrichment

**EPSS** (FIRST, daily CSV) and **CISA KEV** (1,711 actively-exploited CVEs). KEV promotes to Error; high EPSS promotes; unreachable or dev-only demotes. Both are small, cached, refreshed with the OSV DB, and preserve the offline property.

Both feeds are **CVE-keyed while OSV is GHSA-keyed**, so lookup goes through each advisory's `aliases`; `MAL-` entries have none and are unaffected (they're already Error). Best-effort by nature — say so in the hover.

This is the differentiator: Package Checker shows CVSS alone. A CVSS 9.8 at EPSS 0.02% and a CVSS 6.5 at EPSS 70% should not look identical in your editor.

**Gate:** a KEV-listed CVE renders as Error; the same CVE with KEV disabled renders per CVSS.

### Stage 15 — Go reachability

Enable `reachability/go/source`; consume `GroupInfo.ExperimentalAnalysis[id].Called`; demote unreachable findings. Default **off** — it shells out to the Go toolchain and is slow. Requires `worktree.shell_env()` in the shim so `go` is on `PATH` under a GUI-launched Zed.

**Gate:** a fixture importing a vulnerable module without calling the affected symbol produces a demoted diagnostic. Timed on a real repo before enabling by default anywhere.

### Stage 16 — Hardening and publish

Wire up the full settings schema above end to end — shim forwards
`initialization_options`, server validates and applies them, `didChangeConfiguration`
re-reads without a restart — plus README with **CC-BY 4.0 attribution for OSV/GHSA data**, choose a final extension name (`"Package Checker"` is JetBrains' product name — a distinct one avoids registry friction), then submit to `zed-industries/extensions`.

---

## Verification that applies to every stage

- `make test` → `go test -race ./...`; `make lint` → `golangci-lint run`.
- Real-Zed check via `dev: install dev extension` for any stage that changes observable behaviour. Unit tests cannot prove the Zed integration.
- Fixtures under `server/testdata/fixtures/` with pinned known-vulnerable dependencies, matched against `server/testdata/osvdb/`; assert exact `(file, line, col)`. `locate` and `graph` are where bugs will live, and their output is precisely assertable.
- An import-boundary test asserting only `internal/scan` reaches osv-scanner and only `internal/lsp` reaches `go.lsp.dev`.

## Open risks

| Risk | Resolved by |
|---|---|
| ~~`PackageInfo.Inventory` may be nil~~ | **Resolved Stage 0**: non-nil, real line numbers |
| ~~`load()` may run per scan~~ | **Confirmed Stage 0** — it does. Resolved by the extract/match split above |
| ~~Binary size~~ | **Resolved Stage 0**: ~41 MB, well under threshold |
| ~~`CGO_ENABLED=0` cross-compile~~ | **Resolved Stage 0**: all 6 targets build |
| ~~`packagejson` line numbers~~ | **Resolved Stage 0**: works with `IncludeDependencies` config |
| ~~Offline flags / `MaxSeverity` format~~ | **Resolved Stage 0**: flags work; `MaxSeverity` is a numeric string |
| ~~Zed's handling of diagnostics for closed buffers~~ | **Resolved Stage 1**: Zed *does* show diagnostics for never-opened files. `didOpen` re-publish is now defensive, not load-bearing |
| Range heuristic false positives when the installed version is newer | Accepted for v1; installed-package scanning is the follow-up |
| **We now own version-range matching** — per-ecosystem semantics are subtle | `deps.dev/util/semver`; differential-test `match` against osv-scanner's own results |
| Database load footprint — 600 MB peak, growing across scans | Stage 4: ecosystem filter, streaming read, parse-once index; measured at the gate |
| npm's 205 MB download remains, since there is no published index | Background with progress; only JavaScript projects pay it |
| `go.lsp.dev/protocol` is one tag after years dormant | Confined to `internal/lsp`; hand-written structs over `sourcegraph/jsonrpc2` is a one-package fallback |
| Reachability cost on large repos | Stage 15, timed before defaulting on |
| Monorepo scan cost | User-facing `exclude` and `maxScanSeconds` settings; skip list is config-driven from Stage 3 |
| Python `toolchain` in the server key may spawn extra instances | Stage 12 |

## Not in scope for v1

Vulnerable-API-usage for npm and Python (needs Mend-style symbol data no open source provides); installed-package scanning for exact versions; pnpm/yarn/bun transitive graphs; Maven/Gradle/Composer/Ruby; commit blocking; a dedicated tool-window UI — Zed's diagnostics panel is the UI.
