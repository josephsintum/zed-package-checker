# zed-package-checker

A [Zed](https://zed.dev) extension that flags **vulnerable and malicious dependencies**
as editor diagnostics, across npm, Go modules, Python and Cargo — the capability
JetBrains IDEs get from their Package Checker plugin, which Zed has no equivalent for.

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

The server finds what a project depends on by parsing its manifests and lockfiles, and
matches them itself. There are two places the advisories can come from, and the matcher
cannot tell them apart — `server/scripts/compare-sources.py` exists to prove that:

- **Per-package, over the network.** One batched request naming the dependencies, a
  second for the few that matched, and the advisory records themselves from the same
  public bucket the archives live in. Kept on disk and refreshed every twelve hours, so
  it is one round trip on first run and none thereafter. A few hundred kilobytes.
- **The whole archive.** Every advisory for every package in an ecosystem, 253 MB across
  the four. Downloaded concurrently, smallest first, each published as it lands. This is
  what `"offline": true` uses, and what the network path falls back to.

Findings are anchored on the **manifest** line responsible rather than on a lockfile you
never open, and the squiggle covers whatever you would edit — the version for a direct
dependency, the name of the dependency that pulled it in for a transitive one — rather
than the whole line.

## What you see

For each vulnerable dependency, a diagnostic on its declaration naming the advisory, the
worst severity, and the version that fixes it:

```
npm:lodash@4.17.15 — 6 advisories, worst High (CVSS 7.2). Fixed in 4.17.21
```

Alongside it:

- **Transitive dependencies attributed to what pulled them in.** Most vulnerabilities
  are not in anything you declared. For npm, the install tree in `package-lock.json` is
  reconstructed so the finding lands on the direct dependency responsible, in the
  `package.json` that declares it — the root's, or the workspace member's — and names the
  chain: *"npm:minimist@1.2.0 — 4 advisories, worst Critical (CVSS 9.8). Fixed in 1.2.6.
  Pulled in by tar → mkdirp"*. The vulnerable package is always the subject; nothing
  claims `tar` is vulnerable because of what it depends on.
- **A summary per manifest** when more than one dependency is affected — "3 vulnerable
  dependencies (2 high), 1 of them transitive" — anchored on the declaration every file
  of its kind must contain, so it survives reformatting.
- **Severity that reflects context.** Development-only dependencies are demoted; a
  malicious package is never demoted, because "remove this now" does not become less
  true for a dev dependency.
- **Honest uncertainty.** A version inferred from a range rather than read from a
  lockfile says so, because the installed version may differ.
- **A quick fix that writes the version for you**, where a published version clears every
  advisory on the package. It rewrites the digits and nothing else, so `^4.17.0` becomes
  `^4.18.0` and a `go.mod`'s `v` prefix survives. Lockfiles are never rewritten — where
  one pinned the version, the action says so and leaves reinstalling to you. The
  diagnostic names the key that applies it, so the fix is not something you have to know
  to go looking for.
- **Download progress.** npm's archive is 205 MB, and the first scan of a JavaScript
  project cannot report anything until it lands, so the wait is reported rather than
  silent.

## Supported manifests

| Ecosystem | Read from | Precise spans |
|---|---|---|
| npm | `package.json`, `package-lock.json` (v1, v2 and v3) | yes |
| Go | `go.mod` (with `replace` and `toolchain` applied) | yes |
| Python | `requirements.txt`, and the files it includes with `-r` | yes |
| Cargo | `Cargo.toml`, `Cargo.lock` | yes |

Transitive attribution needs a lockfile, since a manifest names only what you asked for.
It is npm-only for now — `pnpm-lock.yaml`, `yarn.lock` and `bun.lock` each record a
different structure and need their own reader, so their transitive dependencies are still
reported on their own lockfile lines.

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

Requires a Rust toolchain with the `wasm32-wasip1` target for the extension half
(pinned in `rust-toolchain.toml`).

```sh
make server      # the language server, to target/release/
make extension   # the Zed shim, to wasm
make test        # cargo test
make lint        # cargo fmt --check + clippy -D warnings, both crates
```

Point Zed at the binary with `lsp.package-checker.binary.path`, then install the
extension as a dev extension.

`scripts/lsp-smoke.py` drives a server over stdio without the editor, which is the quick
way to see what it would publish. `--db-root` at an empty directory exercises a cold
first run, and `--options` sends settings:

```sh
python3 scripts/lsp-smoke.py \
  --binary target/release/package-checker-lsp \
  --root path/to/project \
  --db-root /tmp/empty \
  --options '{"online":{"enabled":false}}'
```

## Design notes

Findings from the probes that shaped the architecture, kept so they do not have to be
rediscovered.

### Extraction and matching are separate on purpose

The obvious approach — run an off-the-shelf scanner such as `osv-scanner` on every scan
and publish what it returns — reparses the advisory database **every time**. Measured
against a one-dependency project:

| | Full scan through `osv-scanner` | Extraction only |
|---|---|---|
| Wall time | 4.5 s | **500 µs** |
| Allocated | 3.1 GB | **12 MB** |

For a CLI that runs once this is correct and efficient. For a server that rescans after
every `npm install` it is not. So the server parses manifests itself — six parsers that
keep the spans of what they find, so discovery and anchoring are one pass — and matches
itself against an index built once per process.

Owning the matcher means owning per-ecosystem version ordering, which is subtle: the
`semver` crate rejects `1.2`, a leading `v` and `1.2.3.4`, all of which appear in real
advisories, and `pep440_rs` rejects 3,185 version strings the PyPI archive actually
contains. Both comparators are therefore written to `osv-scalibr`'s `semantic` package,
and `server/tests/differential.rs` checks them against 116,142 of its recorded answers
over the real archives.

### The database is loaded once, not per scan

Archives are memory-mapped and decoded across every core into a compact in-memory
index, built once per process and rebuilt only when the archives change.

| Ecosystem | Advisories | Load | Retained |
|---|---|---|---|
| Go | 9,082 | 17 ms | 8 MB |
| PyPI | 25,029 | 46 ms | 45 MB |
| npm | 228,368 | 390 ms | 86 MB |

Only the ecosystems a project actually uses are loaded, so a Go project holds 8 MB
rather than npm's 86 MB — the single largest saving available, since most projects
never touch npm's archive at all.

**The representation is most of the memory.** A `String` carries a capacity word that a
`Box<str>` does not, and a `Vec` one that a `Box<[T]>` does not. Across 228,368
advisories, each holding an id, a summary, a CVSS vector and affected ranges of two
version strings apiece, those spare words dominated: the first working index retained
223 MB for npm, and boxing the immutable advisory fields took it to 90 MB. The obvious
representation is the wrong one, and nothing in the compiler says so.

**Advisory prose dominated the index.** The `details` field averages 662 bytes and,
across npm's 228k advisories, accounted for more than half of an early index — retained
so hover text could be rendered for the two or three advisories a project actually
matches. It is read from the archive on demand instead.

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

- A package declared in a manifest and pinned in its lockfile is seen **twice**, so
  reconciliation is required, and it has to be scoped to one project or a sibling's
  lockfile will suppress a dependency that is genuinely present. A workspace lockfile
  at the root governs the manifests below it.
- `Cargo.lock` lists the project's own crate alongside its dependencies, and nothing in
  the entry marks it as local; it is dropped by name, because a project is not a
  dependency of itself.
- A package declared in more than one section — `dependencies` and `devDependencies`,
  say — is attributed to the one that ships.
- The Go toolchain is reported as `stdlib`, against the `toolchain` directive when there
  is one and the `go` directive otherwise. The latter is a **minimum**, not the toolchain
  in use, and the diagnostic says so. `replace` directives are applied, because the
  build uses the replacement; a replacement by local path drops the module, since a
  directory has no version to look up.

## License

Apache-2.0. Vulnerability data from OSV.dev and the GitHub Advisory Database is
CC-BY 4.0.
