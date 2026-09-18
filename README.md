# zed-package-checker

A [Zed](https://zed.dev) extension that flags **vulnerable and malicious dependencies**
as editor diagnostics, across npm, Go modules and Python — the capability JetBrains
IDEs get from their Package Checker plugin, which Zed has no equivalent for.

Vulnerability data comes from [OSV.dev](https://osv.dev). On a project's first scan the
server asks osv.dev about the dependencies it found — **their names, ecosystems and
versions, and nothing else**; not your manifest, not your code. Those answers are kept on
disk, so every later scan is local and needs no network at all.

That first request is what makes the first run take about a second instead of the minutes
a 253 MB advisory download would. `"online": {"enabled": false}` turns it off and waits
for the download instead; `"exclude"` keeps named packages off the wire either way.

> **Status: early development.** It works, but there is no release to install yet —
> you build it yourself. See [`docs/PLAN.md`](docs/PLAN.md) for the design and what
> is still to come.

## How it works

Zed extensions cannot publish diagnostics — only a language server can. So this is two
pieces: a thin Rust→WASM shim that Zed loads, and a native language server that does the
scanning.

There are two implementations of that server, and they agree diagnostic for diagnostic —
`server_rs/scripts/compare-servers.py` drives both over stdio and diffs everything they
publish. `server_rs/` (Rust) is where new work lands and is the one with the fast first
run described below; `server/` (Go) is what releases currently ship, and stays as the
independent implementation those comparisons are run against.

The server finds what a project depends on by parsing its manifests and lockfiles, and
matches them itself. There are two places the advisories can come from, and the matcher
cannot tell them apart — `server_rs/scripts/compare-sources.py` exists to prove that:

- **Per-package, over the network.** One batched request naming the dependencies, a
  second for the few that matched, and the advisory records themselves from the same
  public bucket the archives live in. Kept on disk and refreshed every twelve hours, so
  it is one round trip on first run and none thereafter. A few hundred kilobytes.
- **The whole archive.** Every advisory for every package in an ecosystem, 253 MB across
  the four. Downloaded concurrently, smallest first, each published as it lands. This is
  what `"offline": true` uses, and what the network path falls back to.

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

## Configuration

Everything is optional; the defaults are what the server does with no configuration at
all. Set it under `lsp.package-checker.initialization_options` in Zed's settings:

```json
{
  "lsp": {
    "package-checker": {
      "initialization_options": {
        "online": {
          "enabled": true,
          "exclude": ["@mycompany/", "Go:github.internal/"],
          "ttlHours": 12
        },
        "offline": false
      }
    }
  }
}
```

| Setting | Default | What it does |
|---|---|---|
| `online.enabled` | `true` | Ask osv.dev about this project's dependencies rather than waiting for the full archive. |
| `online.exclude` | `[]` | Package names never to send, matched as a prefix against `ecosystem:name` or the bare name. Excluded packages are matched locally or not at all — never reported clean without being checked. |
| `online.ttlHours` | `12` | How long a cached answer is trusted before being asked again. |
| `offline` | `false` | Never touch the network at all: no queries, and no archive downloads either. |

`online.exclude` is there because an internal package name can reveal more than the
dependency does, and osv.dev has no advisories for private packages anyway.

## Building

Requires Go, a Rust toolchain, and the `wasm32-wasip1` target for the extension half
(pinned in `rust-toolchain.toml`).

```sh
make server      # the Go server
make server-rs   # the Rust server
make extension   # the Zed shim, to wasm
make test        # go test -race ./...
make test-rs     # cargo test
make lint        # go vet + golangci-lint
make lint-rs     # cargo fmt --check + clippy -D warnings
```

Point Zed at whichever binary with `lsp.package-checker.binary.path`, then install the
extension as a dev extension.

`scripts/lsp-smoke.py` drives a server over stdio without the editor, which is the quick
way to see what it would publish. `--db-root` at an empty directory exercises a cold
first run, and `--options` sends settings:

```sh
python3 scripts/lsp-smoke.py \
  --binary server_rs/target/release/package-checker-lsp \
  --root path/to/project \
  --db-root /tmp/empty \
  --options '{"online":{"enabled":false}}'
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
| crates.io | 2,702 | 14 ms | 3 MB |
| Go | 9,082 | 37 ms | 11 MB |
| PyPI | 25,029 | 110 ms | 59 MB |
| npm | 228,368 | 613 ms | 110 MB |

Only the ecosystems a project actually uses are loaded, so a Go project holds 11 MB
rather than npm's 110 MB — the single largest saving available, since most projects
never touch npm's archive at all.

npm's load was 3.5 s when first written. Three changes account for the rest: entries
are decoded across every core, a faster DEFLATE implementation replaced the standard
library's, and the reader it needs is recycled between entries rather than allocated
per entry — that last one alone was 44 KB of garbage per advisory, and took the
collector from 75 collections during a load to 21.

The server also sets its own soft heap limit, sized from the ecosystems it is about to
load. Parallel decoding raises the allocation rate enough that Go's collector
overshoots; the limit returns peak memory to roughly the retained size without the
throughput cost that tuning `GOGC` would bring.

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
