# Would Rust have been the better choice?

`docs/PLAN.md` chose Go, in a section called **"Why Go, not Rust"**. This document
is the attempt to find out whether that holds up, by building the same server in
Rust and measuring both against the same advisory archives, the same fixtures and
the same clock.

Everything below is measured, on one machine (Apple silicon, 14 cores), against
the archives already in `~/Library/Caches/zed-package-checker/db`. Load and
memory figures are reproduced by `scripts/bench.sh`; diagnostic equivalence by
`scripts/compare-servers.py`. Nothing is quoted from the Go server's README.

The Go side is built from the same worktree, at commit `189e893`, so both
implementations are the same age. Work in progress on `main` — a
`locate/requirements.go` among it — is deliberately not included, and one
finding below is already being closed there.

## The verdict, in one paragraph

**Rust would have been the better choice for this server, and the margin is
larger than expected — but not for the reason the plan argued about.** The
premise that scalibr is irreplaceable was already false: the Go server uses four
of its extractors and has hand-written the database, the matcher and the
anchoring anyway. Replacing those four extractors cost 425 lines. What Rust
bought in return is a server that retains **23% less** memory for the life of the
editor session and ships in a **4.9 MB binary instead of 43.8 MB**, with 19
direct dependencies instead of 161.

On speed, the first answer was wrong and the correction is the most useful thing
here. Rust loaded npm's advisory database **9× faster** than the Go server as
written — but most of that was two implementation choices, not the language. The
Go loader has since been given both (parallel decoding, and a faster inflater it
already had in its dependency graph), and the gap is now **2.6×**. Those changes
are implemented and tested in this worktree; `docs/CARRY-BACK.md` is how to take
them. What it cost is a 3.7× slower build,
a cross-compilation story that needs a tool Go does not, and roughly 400 lines of
hand-ported version-comparison logic that had to be differential-tested against
scalibr to be trusted at all. On this workload — a long-lived process that parses
229,049 JSON documents and then sits in an editor's memory all day — those are
not close.

---

## The premise was already false when it was written

The Go plan's argument rests on osv-scalibr being irreplaceable:

> `osv-scalibr` covers 21 ecosystems... so Rust would mean reimplementing 21
> extractors, per-ecosystem version-range matching, the offline DB, and
> reachability.

Read against the code that now exists, three of those four are already
reimplemented in Go, and the fourth was never built:

| Claim | What `server/` does today |
|---|---|
| 21 extractors | `extract/extract.go` constructs **four**: `packagejson`, `packagelockjson`, `gomod`, `requirements` |
| version-range matching comes free | `internal/match` is hand-written. Only `semantic.Parse` is borrowed |
| the offline DB comes free | `internal/db`, 2,131 lines, replaced osv-scanner's loader entirely after Stage 0 |
| reachability comes free | Not built. Stage 16, Go-only, default off |

What scalibr actually still provides is **manifest parsing for four file
formats**. The question is whether that is worth 9 direct dependencies pulling
~175 indirect ones — go-git, buildkit, the Docker client, diskfs, NTFS/ext4/RPM
parsers, gRPC, OpenTelemetry, SQLite — and a 46 MB binary.

---

## Advisory database: load time and memory

The workload that actually hurts. npm's archive holds 229,049 separately
compressed JSON documents, 379 MB uncompressed, 97% of them `MAL-`
malicious-package reports rather than CVEs.

Both implementations read the **same files on disk**, on the same machine
(M-series, 14 cores), page cache warm, fastest of three runs. `retained` is each
language's own allocator accounting — Go's `runtime.ReadMemStats` after a forced
GC, ours a counting global allocator. `peak` is the kernel's maximum resident set
size, which is the only figure that means the same thing on both sides.

The Go column appears twice, because this experiment changed it. "Go, as
written" is the loader at commit `189e893`: single-threaded, using the standard
library's inflater. "Go, improved" is that loader after the changes this
comparison suggested — parallel decoding, `klauspost/compress` registered as
`archive/zip`'s decompressor, and the discarded `details` field removed — which
are merged into `main` as `ba15557` and `d8768b8`. See `docs/CARRY-BACK.md`.

| Ecosystem | Implementation | Load | Retained | Peak RSS |
|---|---|---:|---:|---:|
| Go (9,082 advisories) | Go, as written | 213 ms | 10.7 MiB | 37 MiB |
| | Go, improved | 79 ms | 10.9 MiB | 56 MiB |
| | Rust, sequential | 103 ms | **7.8 MiB** | **20 MiB** |
| | Rust, parallel | **17 ms** | 7.9 MiB | 33 MiB |
| PyPI (25,029) | Go, as written | 656 ms | 58.2 MiB | 121 MiB |
| | Go, improved | 153 ms | 58.6 MiB | 176 MiB |
| | Rust, sequential | 322 ms | **44.5 MiB** | **82 MiB** |
| | Rust, parallel | **46 ms** | 44.6 MiB | 116 MiB |
| npm (228,368) | Go, as written | 3,511 ms | 110.4 MiB | 331 MiB |
| | Go, improved | 1,022 ms | 110.6 MiB | 476 MiB |
| | Rust, sequential | 1,860 ms | **85.4 MiB** | **222 MiB** |
| | Rust, parallel | **390 ms** | 85.5 MiB | 430 MiB |

**The headline number moved from 9.0× to 2.6×** once the Go loader was given the
same two advantages. That is the most useful result in this document, and it is
a result about the code, not about the language.

Both implementations index **exactly the same advisories over exactly the same
packages** — 9,082/1,592, 25,029/13,316, 228,368/224,492 — which is the first
evidence that the port is faithful rather than merely fast.

Three things worth separating out.

**Single-threaded Rust is consistently 2× Go, and better on every axis.** Same
algorithm, same archive, one thread: 1.9–2.1× the speed, 22–24% less retained
memory, 30–40% less peak RSS.

**Parallelism is worth another 4–7×, and costs peak memory.** `zip::ZipArchive`
is `Clone + Send + Sync`, so a memory-mapped archive can be decoded across every
core with each worker holding its own cursor. npm drops from 3.5 s to 390 ms —
9× the Go server. But peak RSS rises from 222 MiB to 430 MiB, above Go's 331 MiB,
because the mapping faults the whole 205 MB archive in and the per-entry results
are collected before being folded. Retained memory is unchanged, so this is a
transient cost during the one load, not a steady-state one. Which strategy is
right depends on whether the user is waiting: on first run they are.

**The memory win is entirely `Box<str>`, and it is not free.** The first working
version retained **223 MiB for npm — twice Go's 110 MiB.** The cause is that
Rust's `String` carries a capacity word that Go's immutable `string` does not,
and `Vec` carries one that a Go slice does not. Across 228,368 advisories, each
holding an id, a summary, a CVSS vector, and affected ranges of two version
strings apiece, those spare words dominated:

| | `String`/`Vec` | `Box<str>`/`Box<[T]>` |
|---|---:|---:|
| advisory structs | 34.7 MiB | 23.8 MiB |
| affected entries | 77.9 MiB | 17.6 MiB |
| ranges | 62.9 MiB | 10.8 MiB |
| **total retained** | **222.9 MiB** | **89.7 MiB** |

A 60% reduction from a representation choice the compiler does not prompt you to
make. Go's default representation is the efficient one here; Rust's default is
not, and you have to know that. Counting against Rust: the obvious code is the
wrong code. Counting for it: the right code is expressible, and Go offers no
equivalent lever — its 110 MiB is the floor, not a starting point.

### Where the 9× actually comes from

"Rust is faster" is not an explanation, so the sequential load was split into its
two phases — inflating each zip entry, and parsing the JSON — on both sides, over
the same npm archive and the same 229,049 entries. The Go figures come from a
harness decoding into the same partial struct `internal/db` uses.

| Phase | Go, stdlib | Go, klauspost | Rust |
|---|---:|---:|---:|
| Inflate | 2,421 ms | 1,912 ms | **981 ms** |
| Parse | 744 ms | 762 ms | **245 ms** |

Three things fall out of this, and the first is the important one.

**Inflating the archive is the dominant cost on both sides** — 75% of Go's
sequential load and 51% of ours. This is mostly a *library* difference, not a
language one: Rust's `zip` pulls `flate2` with the `zlib-rs` backend, a
SIMD-optimised DEFLATE implementation, while Go's `archive/zip` uses stdlib
`compress/flate`. And Go is not stuck with it: `archive/zip` supports
`RegisterDecompressor`, and `github.com/klauspost/compress` is **already in the
server's module graph** as an indirect dependency. Registering it takes six lines
and recovers 21% of the inflate cost. It does not close the gap — `zlib-rs` is
still about 2× klauspost here — but it is the cheapest available speedup in the
Go server and requires no new dependency.

**Parsing is ~3× faster, and the gap is understated.** Rust's 245 ms includes
building the domain `Advisory` — every `Box<str>`, every range — while Go's
744 ms is bare `json.Unmarshal` with `toModel` still to come. The causes are
`serde` generating a parser at compile time against `encoding/json` reflecting
over struct tags at run time, and borrowed deserialisation: a `Cow<str>` points
into the input buffer when the JSON string has no escapes, where Go always
allocates.

Part of that is the `details` field, and it is worth naming precisely rather than
hand-waving, because an earlier draft of this document overstated it. Declaring
`details` and then discarding it — which is exactly what `internal/db` does —
costs, per advisory:

```
BenchmarkWithDetails-14      4496 ns/op    2800 B/op    18 allocs/op
BenchmarkWithoutDetails-14   3906 ns/op     853 B/op    16 allocs/op
```

13% of parse time and **1,947 wasted bytes per advisory**, roughly 445 MB of
allocation churn across npm's archive, for a string that is thrown away. Real,
and free to avoid in Rust because an undeclared field is skipped rather than
materialised — but 13% of 24% of the load, so about 3% of the total. It is not
where the time goes.

**The parallelism is a choice, not a language property.** 1,830 ms → 390 ms is
4.7× on 14 cores, and it is the single largest term in the 9×. Nothing stops Go
doing the same: the archive is embarrassingly parallel, `zip.File.Open` is safe
to call concurrently on separate entries, and a `sync.WaitGroup` over a worker
pool would get most of it. The Go loader is single-threaded because it was
written that way, not because Go made it so.

So the honest accounting of the 9×: **about 4.7× is parallelism Go could also
have, about 2× is a DEFLATE library Go can adopt today, and about 2× is the
language** — the JSON parser, the absence of GC pressure, and not allocating
strings it throws away.

That prediction was then tested rather than left as arithmetic. Both changes were
made to the Go loader in this worktree — 60 lines in `internal/db/load.go` — and
npm's load went **3,511 ms → 1,022 ms**, against Rust's 390 ms. The predicted
landing point was "somewhere near 700 ms"; the real one is 1,022 ms, so the
estimate was optimistic by about 40%, and the residual 2.6× is the language plus
whatever Go's scheduler and GC cost under fan-out. The full Go test suite passes
under `-race`, twenty consecutive runs of the database tests pass, and both
servers still publish identical diagnostics.

---

## Version ordering: the correctness gate

`internal/match` delegates ordering to `osv-scalibr/semantic`. **No Rust crate is
equivalent**, and the two obvious candidates both fail in ways that would be
silent:

- The `semver` crate rejects `1.2`, a leading `v`, and `1.2.3.4` — all of which
  appear in real advisories. scalibr's comparator never fails at all.
- `pep440_rs` rejects **3,185 distinct version strings that the PyPI archive
  actually contains** — setuptools-era spellings like `0.3m1`, `0.1-charmander`,
  `0.1.0.dev-120828c`. scalibr accepts every one through a legacy fallback,
  because it implements PEP 440 *plus* setuptools, not PEP 440. Using the crate
  would have skipped those advisories: a false negative in a security tool,
  visible in no test that did not compare against the real data.

So both comparators are ported by hand — roughly 400 lines. They are checked
against **116,082 real comparisons**, generated by running scalibr's own
`semantic.Parse(...).CompareStr(...)` over every distinct version string in the
three cached archives (`tools/semantic-oracle`). Agreement is exact: 116,082 of
116,082, with no version rejected.

Two quirks the port had to reproduce rather than improve on, both now pinned by
tests: a fourth numeric component is folded into the prerelease string, so
`1.2.3.4` sorts *below* `1.2.3`; and version components are arbitrary-precision,
which Go does with a `big.Int` allocated per component per comparison and which
here is a digit-substring comparison with no allocation at all.

---

## Findings that were not on the list

**Rust 1.89 put advisory file locking in `std`.** The Go server needs
`github.com/gofrs/flock` for cross-process coordination on the shared cache;
`File::try_lock` made that dependency unnecessary here. One fewer third-party
component in the part of the system whose failure mode is a corrupted 205 MB
download.

**Nine Go packages became one Rust crate.** The Go layout exists partly because
Go's only mechanism for a dependency boundary is a separate package plus a test
that walks imports — `internal/arch` is 156 lines doing exactly that. Module
privacy gives the same guarantee for free, so the Rust build is one crate, one
manifest, twelve flat files.

**The ported tests caught a real semantics difference immediately.** Rust's
`Iterator::max_by_key` returns the *last* maximum on a tie where Go's `>` loop
keeps the first, which would have made the advisory shown in a diagnostic depend
on archive ordering. Found by porting `model_test.go` case for case, before any
of it ran against real data.

---

## Extraction: the thing scalibr was supposed to make impossible

Six parsers, 700 lines, in `src/manifest.rs`:

| Manifest | How | Notes |
|---|---|---|
| `package.json` | `jsonc-parser` | Spans come from the CST, so discovery and anchoring are one pass |
| `package-lock.json` | `jsonc-parser` | Both the v1 `dependencies` tree and the v2/v3 `packages` map |
| `go.mod` | hand-written, ~90 lines | `require` blocks and singles, the `go` directive, `// indirect` |
| `requirements.txt` | hand-written, ~80 lines | Continuations, extras, environment markers, comparators |
| `Cargo.toml` | hand-written, ~110 lines | Bare and inline-table forms, renamed crates, target tables |
| `Cargo.lock` | hand-written, ~45 lines | `[[package]]` records, with the project's own crate dropped |

Cargo is line-based rather than parsed for the same reason the Go locator is: a
TOML decoder hands back values without telling you where they were written, and
the position is the point.

They are checked against the Go server's own fixtures, asserting the exact
`(file, line, column)` of every dependency — `tests/extraction.rs` — and they
agree, including the go.mod line numbers the Go extractor test pins.

The structural difference is that **`internal/locate` has no counterpart**. The
Go server needs it because scalibr reports a line number and nothing finer, so
each manifest is read a second time to narrow the anchor to the dependency's
name. A parser that keeps spans does both at once: 640 lines of Go with no Rust
equivalent, because the work does not exist.

That shows up directly in the output. The Go server has no locator for
`requirements.txt`, so Python findings keep a whole-line anchor:

```
go     [1:0-2:0]  PyPI:requests@2.19.1 — 10 advisories, worst High (CVSS 7.5)...
rust   [1:0-1:8]  PyPI:requests@2.19.1 — 10 advisories, worst High (CVSS 7.5)...
```

Same advisory, same severity, same message; the span covers the package name
rather than the line. This was the one behavioural difference between the two
servers, and it **no longer exists**: the Go locator for `requirements.txt` and
`Cargo.toml` landed on `main` (`58b3abd`, `7f184ec`) while this was being
written, so both servers now produce the same span. It is worth recording only
because of where the work went — in Go it is a separate package and a second read
of every manifest; here it fell out of the parser that was already running.

The comparison figures below are against `189e893`, the commit this branch is
based on, and so still show the difference.

## Output equivalence

`scripts/compare-servers.py` drives both binaries over stdio across all five
fixtures and compares every published diagnostic: full range, severity, code and
message. It does not reuse `scripts/lsp-smoke.py`, which prints only the start of
a range — and the end is exactly where the two were expected to differ.

| Fixture | Result |
|---|---|
| `go-mod` | identical, 4 diagnostics |
| `npm-direct` | identical, 1 diagnostic |
| `npm-nolock` | identical, 1 diagnostic |
| `npm-range-vs-lock` | identical, 1 diagnostic |
| `py-requirements` | identical, 3 diagnostics |
| `rust-cargo` | identical, 1 diagnostic |

**Every diagnostic matched**, and the list of accepted differences was empty.
That includes the summary diagnostic, the demotion rules, the "version inferred
from a range" and Go-toolchain wording, and the anchoring of a lockfile finding
onto its manifest declaration.

*It briefly stopped being true, and is true again.* Auditing the diagnostic path
afterwards found two defects both servers shared — "Fixed in X" naming the worst
advisory's fix rather than a version that clears every advisory, and
`Advisory::malicious()` reading the id but not the aliases — plus a third found
in review here, a backported fix being offered as a downgrade. All were fixed in
this server first and then carried into the Go one (`docs/CARRY-BACK.md` Tier 4),
so `EXPECTED` is empty again and the six fixtures agree byte for byte.

That round trip is the point of keeping two implementations: the corrected
behaviour was written twice, independently, in two languages, and the two agree.

Getting there found one bug in each direction. The Go server's whole-line anchor
on `requirements.txt` was closed on `main` while this was being written. The Rust
server rendered "Fixed in 0.2.23 or 0.2.23" for a Cargo advisory carrying the
same fix on two release lines — the same defect `8c6ece7` had just fixed in Go,
reproduced faithfully because the port was faithful.

## End to end

Time from process start to diagnostics arriving, driven by the same smoke
client, fastest of three, archives already on disk. Both include the same
1,000 ms debounce, so the figure in brackets is the work itself.

| Fixture | Go, as written | Go, improved | Rust |
|---|---:|---:|---:|
| `go-mod` | 1,316 ms (316 ms) | 1,162 ms (162 ms) | **1,110 ms (110 ms)** |
| `npm-direct` | 4,704 ms (3,704 ms) | 2,119 ms (1,119 ms) | **1,522 ms (522 ms)** |

The improved Go server more than halves the wait on a JavaScript project. The
remaining gap is real but no longer the difference between usable and not.

## What it cost to build

| | Go | Rust |
|---|---:|---:|
| Non-test lines | 4,795 | 4,511 |
| Test lines | 4,455 | 1,090 |
| Source files | 56 across 9 packages | 21 in one flat crate |
| Direct dependencies | 9 | 19 |
| Transitive dependencies | 152 | 113 |
| Stripped binary | 43.8 MB | **4.9 MB** |
| Cold release build | **10 s** | 37 s |
| Warm release build | **0.5 s** | 0.2 s |
| Cross-compile, 6 targets | **92 s, no extra tooling** | see below |

The line counts are not like for like and should not be read as "Rust is
shorter". The Go server has `internal/locate` and `internal/arch` with no
counterpart here, and its test suite is far more thorough. The honest reading is
that the two are the same size for the same behaviour.

The dependency numbers are the striking ones. Go's *nine* direct dependencies
pull **152** indirect ones, almost entirely scalibr's container and OS-package
scanning — go-git, buildkit, the Docker client, diskfs, NTFS/ext4/RPM parsers,
gRPC, OpenTelemetry, SQLite — none of which this program uses. Rust's 19 direct
dependencies pull 113, and every one of them is reachable from code that runs.
The 43.8 MB binary is the same story weighed on a scale.

### Cross-compilation is Go's win, and it is a real one

`CGO_ENABLED=0 go build` produced all six release targets in 92 seconds with
nothing installed. Rust managed the two Apple targets and failed the other four:

```
x86_64-apple-darwin          OK  5.8 MB
aarch64-unknown-linux-musl   FAILED: failed to find tool "aarch64-linux-musl-gcc"
x86_64-unknown-linux-musl    FAILED: failed to find tool "x86_64-linux-musl-gcc"
x86_64-pc-windows-msvc       FAILED: failed to run custom build command for `ring`
```

The cause is one crate: `ring`, the cryptography behind `rustls`, behind `ureq`,
which has C and assembly in it and therefore needs a C cross-compiler per target.
`cargo-zigbuild` or `cross` fixes all four, at the price of another tool in CI
that Go's release job does not need. This is the clearest point in Go's favour
and it is structural, not incidental: a Go binary with no cgo has no native
toolchain to cross-configure, ever.

## The things that were not in the plan

**Rust's default representation is the wrong one, and the compiler will not tell
you.** Retained memory started at *twice* Go's, and the fix — `Box<str>` and
`Box<[T]>` in place of `String` and `Vec` for the immutable advisory types —
required knowing that a `String` carries a capacity word a Go `string` does not.
That is 60% of the retained index, invisible in every test, discovered only by
measuring. Go's defaults are simply correct here.

**The absence of a crate was more dangerous than the absence of a library.**
Rewriting scalibr's extraction was a known, bounded cost. The unbounded risk was
`pep440_rs`, which looks exactly like the right dependency, is maintained by the
Astral team, has two million downloads a quarter — and rejects 3,185 version
strings that are in the PyPI advisory archive right now. Reaching for it would
have produced a server that silently missed advisories, with every test passing.
Only comparing against scalibr's own answers over the real data caught it.

**`std` absorbed a dependency mid-experiment.** Rust 1.89 stabilised advisory
file locking, so `File::try_lock` replaced what Go needs `github.com/gofrs/flock`
for — in the part of the system whose failure mode is a corrupted 205 MB
download.

**Nine Go packages became one Rust crate.** Much of the Go layout exists to
express dependency boundaries, enforced by `internal/arch` walking every
package's imports. Module privacy gives that for free. So does the concurrency
discipline: `-race`, `-count=100` and `goleak.VerifyTestMain` in two packages are
all checking properties the Rust compiler refuses to let you violate.

**The borrow checker caught a design smell and then a real one.** `main`'s two
deferred-assignment knots — a closure over a `*Engine` assigned later, another
over a `*Server` — do not survive translation. Replacing them with a channel
created before either end (`Engine::pending`) removed the window in which those
pointers are nil. Separately, the first attempt at the background-download path
was raw pointers smuggled past the checker; the compiler was right, and the
correct version is three `Arc::clone`s.

## Where this leaves `docs/PLAN.md`

The "Why Go, not Rust" section should be rewritten rather than deleted, because
its *conclusion* is defensible on grounds it never mentioned:

- **Wrong:** "Rust would mean reimplementing 21 extractors, per-ecosystem
  version-range matching, the offline DB, and reachability." Four extractors, and
  the other three were reimplemented in Go regardless.
- **Right, and understated:** `CGO_ENABLED=0` cross-compilation. That is the one
  place Go is straightforwardly better and no amount of Rust effort closes it
  without adding a tool.
- **Right, and still true:** `golang.org/x/vuln` has no Rust counterpart. If
  reachability analysis is ever built, it is Go-shaped work. It is also Stage 16,
  default off, and unbuilt.
- **Backwards:** the plan's own risk table flags `go.lsp.dev/protocol` as "one
  tag after years dormant". `tower-lsp-server` shipped five days before this was
  written and serves 1.25 million downloads a quarter. The LSP layer is the part
  where Rust's ecosystem is *healthier*, and the plan counts it a reason for Go.

## What was not built

Reachability; the transitive npm graph (Stage 11, unbuilt on both sides); hover
and code actions; `$/progress` download reporting; EPSS and KEV enrichment; the
cross-process download tests. The database module implements locking, atomic
publish, checksum verification and self-healing, but only the load path is
covered by tests — the download path is exercised by `dbcheck --fetch` by hand,
not by a fake server the way `internal/db`'s Go tests are.

One behavioural difference from the Go server was introduced deliberately: the
24-hour TTL. In the Go server it is only consulted from `Ensure`, which the
scanner only reaches when the archive is **absent**, so a long-running server
with an existing archive never revalidates — "refreshed daily" describes a
constant, not a scheduler. That is a bug the rewrite surfaced; this server has
the same gap and it is noted here rather than fixed, because fixing it in the
port and not in the original would make the comparison dishonest.
