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

One caveat surfaced by the first row: `toolchain` *is* part of the server key, so a Python project with several virtualenvs could spawn extra instances. We declare no toolchain, so this should not apply — confirm at Stage 13.

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
| npm workspaces | **In scope for Stage 11** — one root lockfile, many manifests, attribution to the correct sub-package |
| Reachability | **Go only**, `reachability/go/source` plugin, default off |
| Extension shim | Rust → WASM, resolves binary by release tag, **verifies SHA-256** before executing |
| Debounce | **1000 ms** (matches JetBrains) |
| First-run download | Full ecosystem zips as published (npm 205 MB) — compact-index optimization deferred until there is evidence it's needed |

---

## Go architecture

### Governing rules

These apply to every stage and are what I'll hold the code to during review:

- **Dependencies point inward.** `internal/model` has zero external imports. `internal/lsp` is the only package importing `go.lsp.dev`. `internal/extract` owns `osv-scalibr`, with one deliberate exception: `internal/match` imports `osv-scalibr/semantic`, a pure version-ordering primitive with no extraction machinery behind it, which Stage 14's upgrade action needs too. `osv-scanner` survives only in the build-tagged differential test in `internal/match` — matching is ours. **`scan.Scan` returns fully-converted `model` types — never `models.PackageSource` or any osv-scanner type.** The third-party lock-ins are therefore contained to one package each. Enforced by `internal/arch`, which walks every package's direct imports, including behind build tags.

  *Corrected 2026-09-16.* Three of the four rules as originally written were false, and the enforcement test they claimed did not exist. The `osv-scanner` rule named `internal/scan`, which never imported it; the `osv-scalibr` rule did not admit `semantic`; and `cmd/package-checker-lsp` reached `go.lsp.dev` directly. The last was fixed rather than excused — the connection wiring moved into `lsp.Serve`, which also removed the window in which a client could be handed to an already-dispatching server.
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

**The load cost.** osv-scanner's `zipDB.load()` (`osvlocal/zip.go:210-234`) reads the whole zip into memory and **decompresses and `protojson.Unmarshal`s every advisory in the ecosystem**, keeping only those touching packages present. Retained memory is small; peak memory is ~205 MB for npm and the CPU cost is on the order of 100k JSON parses. Stage 0 confirmed this happens **per scan**, not once per process. The remedy is loading the database properly at runtime (Stage 5), not a persistent index or a daemon.

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
right. Reconsider only if Stage 5's measurements are bad.

**Unmeasured, and worth measuring at Stage 5 rather than reasoning about:** peak RSS once
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

Each stage is a reviewable unit: it ends with code you read, a command you run, and a gate that must pass before the next begins. Each lands as its own commit. `locate` (Stage 9) deliberately comes *after* the first end-to-end (Stage 8): `Inventory` already supplies line numbers, so real diagnostics appear in Zed one stage sooner, and `locate` then only adds precise spans for the code action.

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

### Stage 3 — `extract` package — **DONE**

The osv-scalibr driver behind `Extractor`, returning `[]ExtractedPackage`. Extraction
only: it reports what a project depends on, with no advisory data involved — matching is
Stage 6.

Extractors are constructed directly (`packagejson.New(cfg)` and friends) rather than
resolved through scalibr's plugin registry, because `packagejson` only reads dependencies
when `IncludeDependencies` is set, and that comes from a plugin-specific config proto
that `PluginsEnabled` cannot express.

Details the Stage 0 probe settled:

- `StoreAbsolutePath: true`, or paths come back relative to `/` with no leading slash.
- `SkipDirRegex`, not `DirsToSkip` — the latter wants paths relative to the scan roots,
  so bare names like `node_modules` fail. Built from the built-in list (moved here from
  `internal/lsp`) plus any `exclude` setting, config-driven from the start.
- A package found by two extractors is returned twice, once from the manifest and once
  from the lockfile, so results are deduplicated.
- The project's own `name@version` is extracted alongside its dependencies and must be
  dropped; it is not a dependency of itself.
- `PURLType` is a purl type ("golang"), not an OSV ecosystem name ("Go"); unsupported
  types are skipped rather than erroring.
- Line numbers are one-based and become `model.Site` through `WholeLine`.

Exercised by a **throwaway CLI harness** (`cmd/extractharness`), not the LSP, so
extraction is validated independently of the editor.

**Review:** `internal/extract/*.go`.
**Gate:**
- `extractharness testdata/fixtures/npm-direct` prints `npm:lodash@4.17.15` twice —
  `package.json:5` and `package-lock.json:14` — collapsed to one by dedup, with the
  fixture's own package absent.
- `npm-nolock` prints the same package with `FromRange` set, resolved from `^4.17.15`.
- `go test -race ./internal/extract/...` against committed fixtures. No network, no
  advisory database: this stage touches neither.

### Stage 4 — `db` package: fetching and cross-process safety — **DONE**

Owns the local copy of the OSV database as a set of files on disk. Nothing in this stage
parses an advisory — that is Stage 5.

Downloads only the ecosystems present in the worktree, so a Go project fetches 11 MB and
a Python one 33 MB rather than npm's 205 MB. Refreshes in the background past 24 h using
`If-Modified-Since`. Reports `ErrDatabaseNotReady` explicitly rather than returning
silently-empty results, since "still downloading" and "nothing is vulnerable" must not
look alike.

The cross-process rules above are the substance of this stage: osv-scanner's own cache
handling is unsafe for concurrent processes, and Zed runs one server per worktree.
Atomic temp-then-rename, validate before publishing, `TryLock` on the scan path with a
background waiter for the process that skipped, startup self-heal, and a rename retry
for Windows.

**Review:** `internal/db/*.go`, especially goroutine lifecycle, context handling and the
locking rules.
**Gate:**
- Cold start downloads; second start doesn't; a Go-only project never fetches npm.
- **Offline assertion**: with the database cached, run under `tcpdump -i any -n 'not port 53'`
  and confirm zero egress. This is the privacy claim — tested, not assumed.
- **Concurrency**: three processes against one empty cache. Exactly one downloads; the
  other two skip, wait, and become ready once it finishes.
- **Corruption recovery**: truncate `all.zip` to half its length, start the server, confirm
  it detects, re-fetches and works.
- **Torn-read**: one process rewriting the archive in a loop while another reads it in a
  loop; no read ever fails.

### Stage 5 — `db` package: loading and the in-memory index — **DONE** (see README for measurements)

Turns those files into something matchable, per "Loading the database" above: stream the
archive from disk rather than reading 205 MB into memory, parse once per process into a
compact `map[PackageKey][]Advisory` keeping only the fields matching needs, and rebuild
only when the database refreshes — never per scan.

This is where the Stage 0 memory finding gets resolved, and where we learn whether the
remedy was necessary or merely tidy.

**Review:** the loader and index types.
**Gate:**
- **Measure and record peak RSS** for a Go-only, a Python-only and an npm project, each at
  startup and after five scans. Record them in the README beside Stage 0's figures.
- An npm project's steady state is well under the 600 MB baseline and does not grow
  across five scans.
- Loading is not repeated between scans, asserted rather than assumed.

### Stage 6 — `match` package — **DONE**

Only the range arithmetic is ours; version ordering comes from `osv-scalibr/semantic`,
the same package osv-scanner uses.

osv-scanner's own matcher is not reused because its database cache is filtered to the
package names present when it first loaded, and later calls get that stale set regardless
of what the project now depends on. Correct for a CLI that runs once; for a server that
rescans after every `npm install` it would silently miss advisories for newly added
dependencies. Caching it ourselves, keyed on the dependency-name set, was considered and
rejected: it trades ~240 lines of ours for an invalidation rule whose correctness depends
on an unexported implementation detail, and whose failure mode is a silent false
negative.

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

### Stage 7 — `engine` package *(the concurrency stage)* — **DONE**

The actor loop, debounce, coalescing, cancellation, publish-state tracking including **empty arrays to clear stale diagnostics**, deletion handling, and the idle-cheaply path. Tested entirely against a fake `Scanner` — no osv-scanner, no LSP.

**Review:** `internal/engine/*.go`. This is the stage most likely to harbour subtle bugs and deserves the closest reading.
**Gate:** `go test -race -count=100 ./internal/engine/...` clean. Explicit tests for: 40 rapid requests inside the 1 s window → exactly 1 scan; a new request cancels an in-flight scan and its results are never published; a deleted manifest gets an empty publish; `Close()` terminates every goroutine (`goleak`). Debounce tests use an injected clock, not `time.Sleep`.

### Stage 8 — First real end-to-end

Assemble `extract`, `db` and `match` into the single `Scanner` the engine expects, and
wire that to the LSP layer: severity mapping, `source`/`code`/`codeDescription`, file
watchers, `didOpen` re-publish, **`$/progress` for the database download**. Ranges are
full lines from `Inventory`; precise spans arrive with `locate`.

All three MVP ecosystems at once — extraction and matching already cover npm, Go and
Python, so restricting this to npm would mean writing code to hold the others back.

**Review:** `internal/lsp/diagnostics.go`, the wiring in `main.go`.
**Gate:** open a real vulnerable project in Zed and see correct, correctly-positioned
diagnostics; a lockfile-free project shows `FromRange` findings; the first run shows
download progress; the summary matches the per-package findings. This repository is a
usable test case. First genuinely useful build.

*Checked 2026-09-16.* This gate originally cited "17 vulnerabilities" in our own
tree, a Stage 0 measurement that is long stale — the dependencies have moved on.
`govulncheck v1.8.0` now reports exactly one vulnerability in the modules we
require, `GO-2026-5932` in `golang.org/x/crypto@v0.57.0`, with nothing called.
We report the same advisory on the same module at the same version, so this
clause is met. The number to match is whatever govulncheck currently says.

**Also: a per-manifest summary diagnostic.** gopls does this for govulncheck and it is
visibly better than squiggles alone: one diagnostic anchored on a line that always exists
— the `module` directive in go.mod, the `name` field in package.json — reading
"3 vulnerable dependencies (1 critical, 2 high)".

Per-package diagnostics scatter across files the user may not have open, so nothing says
"this project has a problem" in one place. The summary is that place, and it costs little
while the publishing path is being wired anyway.

Anchor it on a line the manifest is guaranteed to have, not line 1, so it survives
reformatting.


### Stage 9 — `locate` package (npm)

`package.json` → precise `(file, range)` pairs for declaration and version span, across `dependencies`/`devDependencies`/`optionalDependencies`/`peerDependencies`. Includes the byte-offset ↔ column helper for both encodings. Pure functions, golden-file tests.

**Review:** `internal/locate/*.go` + golden files.
**Gate:** golden tests pass including edge cases — nested scopes (`@scope/pkg`), duplicate names across sections, CRLF files, non-ASCII content. Diagnostics in Zed now underline the dependency name, not the whole line.

### Stage 10 — Distribution

Release workflow (six targets, `CGO_ENABLED=0`), asset naming contract, **`SHA256SUMS` published with every release**, shim switched to `github_release_by_tag_name` + `download_file` + **verify SHA-256** + `make_file_executable`, with `LanguageServerInstallationStatus::Failed` and a clear message when GitHub is unreachable. Cut `v0.0.1`.

**Gate:** install from a clean machine with no Go toolchain and have it work; tamper one byte of the binary and confirm the shim refuses it. Doing this early means a broken distribution path surfaces now, not after six more stages of content.

### Stage 11 — `graph` package (npm transitive, incl. workspaces)

The largest piece of original work. `extractor.Package.ParentIDs` exists but is **not populated** by `packagelockjson` (confirmed), so npm resolution must be reconstructed: for a node at path *P* depending on *N*, walk *P*'s ancestors for `<ancestor>/node_modules/N`; BFS from each root recording the first hop. Falls back to the v1 nested tree.

**Workspaces are in scope.** `package-lock.json` v2/v3 encodes them: `"packages/api": {...}` entries hold each sub-package's own dependencies, and `"node_modules/api": {"link": true, "resolved": "packages/api"}` maps the symlink. The BFS starts from *every* workspace root, and a finding is attributed to the sub-package manifest whose dependency reaches it — not the root `package.json`.

**Explicitly deferred:** `pnpm-lock.yaml`, `yarn.lock`, `bun.lock` have different structures and each needs its own graph builder. Their direct-dependency diagnostics already work via `Inventory`; only transitive attribution falls back to the lockfile line until their builders land.

**Review:** `internal/graph/npmlock.go`.
**Gate:** `npm-transitive` anchors a 3-deep chain on the correct `package.json` line with `relatedInformation` pointing at the lockfile; `npm-workspaces` anchors on `packages/api/package.json`, not root. Table-driven tests for hoisting, nested duplicates, cycles, and links.

### Stage 12 — Go ecosystem

Near-free: `x/mod/modfile` gives exact positions, and since Go 1.17 every module is its own line in `go.mod`, so attribution is **identity** — no graph, no `go mod graph`.

**Gate:** a Go fixture with a known-vulnerable indirect dependency shows a diagnostic on the right `go.mod` line.

### Stage 13 — Python ecosystem

`requirements.txt` (free lines, `Plain Text` language; the extractor's lowest-version heuristic sets `FromRange`) → `pyproject.toml` locator → `poetry.lock`/`uv.lock` graphs. Confirm the `toolchain` caveat doesn't spawn extra server instances.

**Gate:** all three Python fixtures produce correct anchors.

### Stage 14 — Hover, code actions, suppression

Full advisory markdown on hover. Two code actions:
- **Upgrade**: minimum-safe = max of `fixed` events across advisories hitting the package, compared with `osv-scalibr/semantic` (public; handles npm semver, PEP 440, Go, Cargo), rewritten preserving the operator (`^4.17.15` → `^4.17.21`). Direct deps with a same-file version span only.
- **Upgrade all**: applies every available version bump in one manifest, the equivalent
  of gopls's "Upgrade All". With seventeen findings, one action per finding is where the
  leverage is lost. Offered on the summary diagnostic rather than on individual findings,
  and only for those with a same-file version span.
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

### Stage 15 — Enrichment

**EPSS** (FIRST, daily CSV) and **CISA KEV** (1,711 actively-exploited CVEs). KEV promotes to Error; high EPSS promotes; unreachable or dev-only demotes. Both are small, cached, refreshed with the OSV DB, and preserve the offline property.

Both feeds are **CVE-keyed while OSV is GHSA-keyed**, so lookup goes through each advisory's `aliases`; `MAL-` entries have none and are unaffected (they're already Error). Best-effort by nature — say so in the hover.

This is the differentiator: Package Checker shows CVSS alone. A CVSS 9.8 at EPSS 0.02% and a CVSS 6.5 at EPSS 70% should not look identical in your editor.

**Gate:** a KEV-listed CVE renders as Error; the same CVE with KEV disabled renders per CVSS.

### Stage 16 — Go reachability

Enable `reachability/go/source`; consume `GroupInfo.ExperimentalAnalysis[id].Called`; demote unreachable findings. Default **off** — it shells out to the Go toolchain and is slow. Requires `worktree.shell_env()` in the shim so `go` is on `PATH` under a GUI-launched Zed.

**Gate:** a fixture importing a vulnerable module without calling the affected symbol produces a demoted diagnostic. Timed on a real repo before enabling by default anywhere.

### Stage 17 — Hardening and publish

Wire up the full settings schema above end to end — shim forwards
`initialization_options`, server validates and applies them, `didChangeConfiguration`
re-reads without a restart — plus README with **CC-BY 4.0 attribution for OSV/GHSA data**, choose a final extension name (`"Package Checker"` is JetBrains' product name — a distinct one avoids registry friction), then submit to `zed-industries/extensions`.

---

## Verification that applies to every stage

- `make test` → `go test -race ./...`; `make lint` → `golangci-lint run`.
- Real-Zed check via `dev: install dev extension` for any stage that changes observable behaviour. Unit tests cannot prove the Zed integration.
- Fixtures under `server/testdata/fixtures/` with pinned known-vulnerable dependencies, matched against `server/testdata/osvdb/`; assert exact `(file, line, col)`. `locate` and `graph` are where bugs will live, and their output is precisely assertable.
- The import-boundary test in `internal/arch`, which walks every package's direct imports — including behind build tags — and holds the dependency rules stated above. (This line previously repeated the stale rules corrected in "Governing rules"; both places are now the same.)

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
| Database load footprint — 600 MB peak, growing across scans | Stage 4 fetches only the ecosystems present; Stage 5 streams and parses once, and measures the result |
| npm's 205 MB download remains, since there is no published index | Background with progress; only JavaScript projects pay it |
| `go.lsp.dev/protocol` is one tag after years dormant | Confined to `internal/lsp`; hand-written structs over `sourcegraph/jsonrpc2` is a one-package fallback |
| Reachability cost on large repos | Stage 16, timed before defaulting on |
| Monorepo scan cost | User-facing `exclude` and `maxScanSeconds` settings; skip list is config-driven from Stage 3 |
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
package's complete advisory set. `server_rs/scripts/compare-sources.py` is the gate —
the same binary over the same fixtures, once against the archive and once against an
empty cache, asserting every published diagnostic is identical.

The privacy position changed with it, deliberately. Names, ecosystems and versions of
dependencies are sent on a cold cache; manifests and source are not, ever. `online.exclude`
keeps named packages off the wire, because an internal package name can say more than the
dependency does and osv.dev has no advisories for private packages anyway. A one-time
`window/showMessage` names what was sent, which is the consent step this class of tool
usually omits.

## Release blocker: remove the comparison language server

`extension.toml` declares a second language server, `package-checker-go`, so both
implementations can run side by side in one editor and be told apart — each
passes `--label`, and the diagnostics panel distinguishes them by the `source`
field rather than by the server's name.

Zed starts every declared language server, so with no `binary.path` configured
it reports a failure. That is acceptable scaffolding and unacceptable in a
published extension: nobody installing this should see a server fail to start
because of a comparison they never asked for.

**Before publishing, delete the `[language_servers.package-checker-go]` block**
and the `COMPARISON_SERVER_ID` branch in `src/lib.rs`. The `--label` flag on
both servers can stay — it costs nothing and makes the comparison reproducible
from the command line.

Deliberately *not* resolved from `$PATH`: an older copy installed there produces
differences that look like a real disagreement between the two servers and are
not. Explicit configuration or nothing.

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

Measured against `server_rs/`, which has the same four ecosystems in one flat
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

Vulnerable-API-usage for npm and Python (needs Mend-style symbol data no open source provides); installed-package scanning for exact versions; pnpm/yarn/bun transitive graphs; Maven/Gradle/Composer/Ruby; commit blocking; a dedicated tool-window UI — Zed's diagnostics panel is the UI.
