# zed-package-checker

A [Zed](https://zed.dev) extension that flags **vulnerable and malicious dependencies**
as editor diagnostics, across npm, Go modules and Python — the capability JetBrains
IDEs get from their Package Checker plugin, which Zed has no equivalent for.

Vulnerability data comes from [OSV.dev](https://osv.dev), matched **entirely on your
machine**. Your dependency list never leaves the box.

> **Status: early development.** It works, but there is no release to install yet —
> you build it yourself. See [`docs/PLAN.md`](docs/PLAN.md) for the design and what
> is still to come.

## How it works

Zed extensions cannot publish diagnostics — only a language server can. So this is two
pieces: a thin Rust→WASM shim that Zed loads, and a native Go language server that does
the scanning.

The server uses [`osv-scalibr`](https://github.com/google/osv-scalibr) to find what a
project depends on, and its own matcher against a local copy of the OSV database. The
advisory archives are downloaded once, cached, and refreshed daily; after that, scanning
touches the network not at all.

Findings are anchored on the **manifest** line responsible rather than on a lockfile you
never open, and the span covers the dependency's name rather than the whole line.

## What you see

For each vulnerable dependency, a diagnostic on its declaration naming the advisory, the
worst severity, and the version that fixes it:

```
npm:lodash@4.17.15 — 6 advisories, worst High (CVSS 7.2). Fixed in 4.17.21
```

Alongside it:

- **A summary per manifest** when more than one dependency is affected — "3 vulnerable
  dependencies (2 high)" — anchored on the declaration every file of its kind must
  contain, so it survives reformatting.
- **Severity that reflects context.** Development-only dependencies are demoted; a
  malicious package is never demoted, because "remove this now" does not become less
  true for a dev dependency.
- **Honest uncertainty.** A version inferred from a range rather than read from a
  lockfile says so, because the installed version may differ.
- **Download progress.** npm's archive is 205 MB, and the first scan of a JavaScript
  project cannot report anything until it lands, so the wait is reported rather than
  silent.

## Supported manifests

| Ecosystem | Read from | Precise spans |
|---|---|---|
| npm | `package.json`, `package-lock.json` | yes |
| Go | `go.mod` | yes |
| Python | `requirements.txt` | not yet |

Lockfile-free projects still work: a constraint is resolved to its lowest satisfying
version and the finding is marked as inferred. A lockfile, where present, supersedes the
range — including a workspace lockfile at the repository root governing a nested member.

## Building

Requires Go and, for the extension half, a Rust toolchain with the `wasm32-wasip1`
target (pinned in `rust-toolchain.toml`).

```sh
make server      # the language server
make extension   # the Zed shim, to wasm
make test        # go test -race ./...
make lint        # go vet + golangci-lint
```

Point Zed at the binary with `lsp.package-checker.binary.path`, then install the
extension as a dev extension.

`scripts/lsp-smoke.py` drives the server over stdio without the editor, which is the
quick way to see what it would publish:

```sh
python3 scripts/lsp-smoke.py --root path/to/project
```

## Design notes

Findings from the probes that shaped the architecture, kept so they do not have to be
rediscovered.

### Extraction and matching are separate on purpose

The obvious approach — call `osv-scanner`'s `pkg/osvscanner` and publish what it returns
— reparses the advisory database on **every scan**. Measured against a one-dependency
project:

| | Full `pkg/osvscanner` | Extraction only |
|---|---|---|
| Wall time | 4.5 s | **500 µs** |
| Allocated | 3.1 GB | **12 MB** |

For a CLI that runs once this is correct and efficient. For a server that rescans after
every `npm install` it is not. So extraction comes from `osv-scalibr` — 21 ecosystems of
manifest and lockfile parsing, with line numbers, which is the genuinely hard part to
replicate — and the matching is ours.

Owning the matcher means owning per-ecosystem version ordering, which is subtle. A
build-tagged differential test checks our results against `osv-scanner`'s own over the
same fixtures.

### The database is loaded once, not per scan

Archives are streamed from disk into a compact in-memory index, built once per process
and rebuilt only when the archives change.

| Ecosystem | Advisories | Load | Retained |
|---|---|---|---|
| crates.io | 2,700 | 74 ms | 3 MB |
| Go | 9,082 | 214 ms | 11 MB |
| npm | 228,368 | 3.5 s | 110 MB |

Only the ecosystems a project actually uses are loaded, so a Go project holds 11 MB
rather than npm's 110 MB. A project using all three sits around 500 MB resident.

**Advisory prose dominated the index.** The `details` field averages 662 bytes and,
across npm's 228k advisories, accounted for 151 MB of a 257 MB index — retained so hover
text could be rendered for the two or three advisories a project actually matches. It is
now read from the archive on demand, which took peak RSS from 559 MB to 341 MB.

**97% of npm's archive is `MAL-` entries**, not CVEs. The ecosystem's size is driven by
the malicious-package feed rather than by vulnerability data.

### What Zed does with diagnostics

**Zed displays diagnostics for files that were never opened**, so the concern from
[zed#42784](https://github.com/zed-industries/zed/issues/42784) does not apply to
unsolicited server-pushed diagnostics. Re-publishing on `didOpen` is defensive rather
than load-bearing.

**`positionEncoding` negotiates to UTF-8**, so manifest byte offsets are used as columns
directly. The UTF-16 conversion exists for clients that decline it.

**`codeDescription` renders as a clickable link**, so advisory URLs reach the user
without needing hover support.

### Extraction caveats worth knowing

- A package found by two extractors is returned **twice** — once from `package.json`,
  once from `package-lock.json` — so reconciliation is required, and it has to be scoped
  to one project or a sibling's lockfile will suppress a dependency that is genuinely
  present.
- The manifest's own package is extracted alongside its dependencies and must be
  filtered out; a project is not a dependency of itself.
- `DirsToSkip` expects paths relative to the scan roots, so skipping by *name*
  (`node_modules`, `.venv`) needs `SkipDirRegex`.
- The Go extractor reports the toolchain itself as `stdlib`, anchored on the `go`
  directive. That directive is a **minimum**, not the toolchain in use, and the
  diagnostic says so.

## License

Apache-2.0. Vulnerability data from OSV.dev and the GitHub Advisory Database is
CC-BY 4.0.
