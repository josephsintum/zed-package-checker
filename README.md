# zed-package-checker

A [Zed](https://zed.dev) extension that flags **vulnerable and malicious dependencies**
as editor diagnostics, across npm, Go modules and Python — the capability JetBrains
IDEs get from their Package Checker plugin, which Zed has no equivalent for.

Vulnerability data comes from [OSV.dev](https://osv.dev), matched **entirely on your
machine**. Your dependency list never leaves the box.

> **Status: early development.** Nothing is installable yet.
> See [`docs/PLAN.md`](docs/PLAN.md) for the full design and staged build order.

## How it works

Zed extensions cannot publish diagnostics — only a language server can. So this is
two pieces: a thin Rust→WASM shim that Zed loads, which downloads and launches a
native Go language server that does the actual scanning.

The server embeds [`osv-scanner/v2`](https://github.com/google/osv-scanner) as a
library, scans the whole project on startup and on manifest changes, and anchors each
finding on the line of the **manifest** dependency responsible — so a vulnerability in
a transitive package shows up on the `express` line of your `package.json`, not in a
lockfile you never open.

## Stage 0 — feasibility findings

Stage 0 was a throwaway probe answering the questions that could have invalidated the
architecture. Recorded here so they don't have to be rediscovered.

| # | Question | Answer |
|---|---|---|
| 1 | Does `pkg/osvscanner` cross-compile `CGO_ENABLED=0`? | **Yes** — all 6 targets (darwin/linux/windows × arm64/amd64) |
| 2 | Stripped binary size? | **~41 MB** (39.8–43.5 MB). Well under the 80 MB threshold; no need to hand-pick extractors |
| 3 | Is `PackageInfo.Inventory` non-nil at the API surface, with line numbers? | **Yes** — `Inventory.Location.Descriptor.File.LineNumber` returned `14` correctly |
| 4 | Do the offline flags work without the env var? | **Yes** — `CompareOffline` + `LocalDBPath` + `DownloadDatabases` work programmatically |
| 5 | Is the DB parsed per scan or cached per process? | **Per scan.** See below — this is the significant finding |
| 6 | Do `packagejson`/`pyprojecttoml` extractors work via `PluginsEnabled`? | **Yes, with config** — needs `IncludeDependencies` via a plugin-specific proto |
| 7 | Can we skip osv-scanner's matcher and extract via scalibr directly? | **Yes** — 500 µs and 12 MB instead of 4.5 s and 3.1 GB |

### Details worth keeping

**The on-disk DB path is `osv-scalibr`, not `osv-scanner`.** The database lands at
`<LocalDBPath>/osv-scalibr/<Ecosystem>/all.zip`.

**`GroupInfo.MaxSeverity` is a numeric string** (`"8.1"`, `"5.3"`) — `strconv.ParseFloat`,
no label mapping needed.

**`Inventory.Location.Descriptor.File.Path` is root-relative with no leading slash**
(e.g. `private/tmp/...`), because the scan root is `/`. Use `Source.Path` from the
enclosing `PackageSource` for the absolute path and take only the line number from
`File`.

**`ParentIDs` is empty for npm**, as predicted — the transitive dependency graph has
to be reconstructed from `package-lock.json` ourselves.

**`packagejson` only reads dependencies when `includeDependencies` is set**, which comes
from plugin-specific config (`ScalibrConfig`), not plain `PluginsEnabled`. It also reads
only `dependencies` — not `devDependencies`, `optionalDependencies` or `peerDependencies`.

### The performance finding

`zipDB.load()` runs **on every scan**, not once per process. Measured on a
one-dependency fixture against the real npm database:

| | Wall time | Allocated |
|---|---|---|
| Scan 1 (incl. 205 MB download) | 11.2 s | 3.4 GB |
| Scan 2 (same process, warm disk) | **4.5 s** | 3.1 GB |

The cost is fixed regardless of project size — it decompresses and `protojson.Unmarshal`s
every advisory in the ecosystem (~100k for npm) and keeps the handful that match. A
4.5 second, 3 GB scan on every file save is not viable for an editor.

### The resolution: extract with scalibr, match ourselves

A second probe drove `osv-scalibr` directly for **extraction only**, skipping
osv-scanner's bundled vulnerability matching:

| | Full `pkg/osvscanner` | Extraction-only |
|---|---|---|
| Wall time | 4.5 s | **500 µs** |
| Allocated | 3.1 GB | **12 MB** |
| Binary (stripped) | 40.9 MB | 39.4 MB |

So the architecture splits: **`osv-scalibr` for extraction** (21 ecosystems of manifest
and lockfile parsing, with line numbers, which is the genuinely hard part to replicate)
and **our own matcher** against a compact index built in CI. That removes the per-scan
parse entirely and shrinks the npm download from 205 MB to an estimated ~15 MB.

Binary size barely moves, because the container and matcher dependencies arrive through
scalibr core either way.

Confirmed in the same probe:

- `StoreAbsolutePath: true` yields absolute paths, resolving the root-relative issue above.
- `DirsToSkip` expects paths relative to the scan roots; skipping by *name*
  (`node_modules`, `.venv`) requires `SkipDirRegex` or `SkipDirGlob`.
- `packagejson` with `IncludeDependencies` resolved `^4.17.15` to `4.17.15` at the
  correct line — the lockfile-free path works.
- A package found by two extractors is returned **twice** (once from `package.json`,
  once from `package-lock.json`), so deduplication is required.
- The manifest's own package (`npm-direct-fixture@1.0.0`) is extracted alongside its
  dependencies and must be filtered out.

## Stage 1 — walking skeleton

Proved the whole pipe end to end — Zed loads the extension, the shim resolves and
spawns the binary, and diagnostics reach the editor — before any real scanning
exists. Verified in Zed against this repository as the workspace:

- The extension compiles and installs; the server runs at ~13 MB resident.
- `positionEncoding` negotiates to **utf-8**, so manifest byte offsets can be used
  as columns directly with no conversion.
- Three `package.json` files under `probe/` and `server/testdata/` each receive a
  diagnostic.

Two findings that settle open design questions:

**Zed displays diagnostics for files that were never opened.** Two of the three
manifests had no buffer open and still appeared in the diagnostics panel. The
concern from [zed#42784](https://github.com/zed-industries/zed/issues/42784) does
not apply to unsolicited server-pushed diagnostics, so re-publishing on `didOpen`
is defensive rather than load-bearing. Anchoring transitive findings on the
manifest remains the right design regardless, because it is where the user can
act on them.

**`codeDescription` renders as a clickable link** in the diagnostic, so advisory
URLs reach the user without needing hover support.

Also worth keeping: a workspace root is typically a repository whose manifests sit
several directories down, so scanning must walk the tree. Checking the root alone
finds nothing in a real project.

## License

Apache-2.0. Vulnerability data from OSV.dev and the GitHub Advisory Database is
CC-BY 4.0.
