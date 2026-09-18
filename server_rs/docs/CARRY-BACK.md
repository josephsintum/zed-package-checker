# Carrying the findings back into the Go server

The Rust rewrite was a research exercise; **this file is the part of it that is
worth shipping.** Nothing here proposes changing language. Everything is a change
to `server/`, ranked by measured value against effort, with the numbers that
justify it.

Measurements are npm's archive — 229,049 entries, 379 MB uncompressed — on an
Apple-silicon machine with 14 cores, fastest of three, page cache warm.
Reproduce with `server_rs/scripts/bench.sh`.

---

## Tier 1 — merged into `main`

Items 1–3 and item 5 are on `main`:

```
ba15557  Decode advisory archives in parallel with a faster inflater
d8768b8  Stop decoding the advisory prose the index throws away
```

Gates, all run on that branch: `go test -race ./...` green, `internal/db` green
over twenty consecutive race runs, `go vet` clean, `gofmt` clean, and the six
fixtures produce **byte-identical diagnostics** to `main` — compared by running
both binaries through `scripts/lsp-smoke.py` and diffing, not by eye.

Item 4 is **measured but not applied.** It is a policy decision about the
server's memory and deserves to be a deliberate choice rather than a side effect
of a performance patch.

| | npm load | Peak RSS |
|---|---:|---:|
| `main` | 3,511 ms | 331 MiB |
| `main`, after `d8768b8` | **973 ms** | 467 MiB |
| plus item 4 (measured only) | ~1,120 ms | **351 MiB** |

End to end, time to first diagnostics, fastest of three:

| Fixture | before (`bd009c9`) | after (`d8768b8`) |
|---|---:|---:|
| `npm-direct` | 4,580 ms | **2,061 ms** |
| `go-mod` | 1,302 ms | **1,136 ms** |

### 1. Register a faster inflater — 6 lines

Inflating the archive is **75% of the load**, measured by `tools/load-phases`.
`archive/zip` uses stdlib `compress/flate`; it also exposes
`RegisterDecompressor` precisely so that can be replaced, and
`github.com/klauspost/compress` was **already in the module graph** as an
indirect dependency of osv-scalibr. Promoting it to direct costs nothing new in
the dependency tree.

```go
r.RegisterDecompressor(zip.Deflate, func(in io.Reader) io.ReadCloser {
    return kpflate.NewReader(in)
})
```

Inflate: 2,325 ms → 1,916 ms. Peak RSS cost: +7 MiB, measured in isolation.

### 2. Decode entries in parallel — ~55 lines

The archive is embarrassingly parallel and `zip.File.Open` is documented as safe
to call concurrently on separate entries. Decoding — inflate, unmarshal, convert
— fans out across `GOMAXPROCS`; indexing does not, because the map is one shared
structure, so exactly one goroutine writes to it and is fed over a channel.

Two properties worth keeping in the review:

- **Output is unchanged despite insertion order changing.** `match.applicable`
  sorts each package's advisories by severity and then by id, which is a total
  order because ids are unique. Verified by the diagnostics comparison.
- **The results channel is drained to completion even after cancellation**, so no
  worker is left blocked on a send. `TestLoadHonoursCancellation` still passes,
  and `internal/scan`'s `goleak` check covers the call site.

### 3. Reuse a decode buffer instead of a decoder per entry

`json.NewDecoder(f).Decode(&raw)` allocates a decoder and its read buffer for
each of 229,049 entries. A per-worker `[]byte` plus `json.Unmarshal` does not.
Folded into the change above.

### 4. Bound the heap during load — one line, not applied

**Measured by setting `GOMEMLIMIT` in the environment; no code change has been
made.** The recommendation is to move it into the binary, but where the number
comes from is a decision, not a fix — see below.

Parallel decoding raises the allocation rate enough that Go's concurrent
collector overshoots: peak RSS went 331 → 469 MiB while the retained index
stayed at 110 MiB. This is **not** worker count — `GOMAXPROCS=1` still peaks at
456 MiB — it is the GC's heap target chasing a faster mutator.

A soft memory limit fixes it almost for free:

| Setting | Load | Peak RSS |
|---|---:|---:|
| default (`GOGC=100`) | 1,032 ms | 469 MiB |
| `GOGC=50` | 1,867 ms | 305 MiB |
| `GOGC=25` | 3,962 ms | 250 MiB |
| **`GOMEMLIMIT=350MiB`** | **1,117 ms** | **351 MiB** |

`GOGC` trades throughput away steeply. A soft limit does not: 8% slower than
uncapped, and back to roughly the original footprint. Prefer
`debug.SetMemoryLimit` in `main` over the environment variable, so the server
carries its own policy rather than depending on how Zed launched it.

The value is not arbitrary and should not be hard-coded as one. It wants to be a
function of what will be resident — roughly the retained index plus headroom —
and npm's 110 MiB is the worst case. A project on all three ecosystems retains
more. Worth deriving from the ecosystems being loaded, and worth a comment
saying why, because a bare `350<<20` will read as a magic number in a year.

---

## Tier 2 — measured here, not yet implemented

### 5. Stop decoding `details` — one line — **done** (`d8768b8`)

`osvAdvisory` declares `Details string`, fills it, and `toModel` then drops it,
because `DB.Details` re-reads it from the archive on demand. Benchmarked:

```
BenchmarkWithDetails-14      4496 ns/op    2800 B/op    18 allocs/op
BenchmarkWithoutDetails-14   3906 ns/op     853 B/op    16 allocs/op
```

**1,947 wasted bytes per advisory** — about 445 MB of allocation churn across
npm — and 13% of parse time, for a string that is thrown away. Deleting the field
is safe precisely because nothing reads it: `DB.Details` decodes into its own
struct, and `TestToModelLeavesDetailsOutOfTheIndex` asserts on the model type,
not the wire type.

Measured best of five: **1,014 ms → 973 ms**, a 4%
improvement. That matches the prediction from the microbenchmark — 13% of parse,
and parse is ~24% of the load — and is a reminder that a single run is noise: the
first measurement of this change came out *slower*.

### 6. Parse the installed version once per package, not once per comparison

`match.compare` calls `semantic.Parse(pkg.Version, …)` on every invocation, and
it is invoked once per range bound of every candidate advisory. For a package
with seventy-six advisories that is seventy-six-plus redundant parses of the same
string, each allocating a `big.Int` per component. Hoisting the parse to
`applicable`, above the loop, is contained entirely within `internal/match`.

Not separately benchmarked here — matching is a small share of a scan — but it is
a strict improvement with no behavioural change.

### 7. Store each advisory once in the index

`byPackage map[PackageKey][]Advisory` appends a **144-byte struct copy per
affected package**, plus a separately allocated slice per key: 224,492 slices for
npm. Storing `[]Advisory` once and making the map hold index ranges into it is
what the Rust index does, and is most of why it retains 85 MiB against Go's 110.

Medium effort, touches `internal/db/index.go` and `internal/match`'s `Index`
interface. Worth doing only if memory becomes a complaint — it is the one item
here with a real API cost.

---

## Tier 3 — gaps this exercise surfaced, unrelated to speed

### 8. The 24-hour refresh does not happen

`defaultTTL` is only consulted inside `Ensure`, and the running server only
reaches `Ensure` from `scan.warmInBackground`, which only fires when `Ready`
reports the archive **absent**. A long-lived server with an archive on disk
therefore never revalidates it: the README's "refreshed daily" describes a
constant, not a scheduler. A ticker in the engine, firing `ReasonDatabaseSync`,
is the missing piece.

This is carried in `server_rs` too, deliberately unfixed, so the comparison is
not flattered by fixing a bug on one side only.

### 9. `heal()` opens the archive on every `Ensure`

A central-directory read of a 205 MB file, on a path the scanner reaches. Cheap
relative to a load, not free, and it happens when nothing is wrong. Gating it on
the archive's mtime changing since the last successful load would keep the
self-healing property without paying for it every time.

---

## Tier 4 — correctness, found by auditing the diagnostic path — **taken**

These are not about speed, and unlike Tiers 1–3 they change what a user reads.
All four were implemented and tested in `server_rs/` first and are now in
`server/` as well, so `scripts/compare-servers.py` is back to an empty `EXPECTED`
table and the six fixtures agree byte for byte.

Go is no longer a port target after this tier: new work lands in `server_rs/`,
which becomes the shipping server. `server/` stays in CI as the reference
implementation and the differential oracle.

The first thing built on that footing is the per-package advisory cache — one
batched osv.dev query on first run instead of a 253 MB download, persisted and
refreshed on a TTL. It is Rust-only by decision, so `compare-servers.py` now
covers the behaviour the two share rather than everything either does.

### 10. "Fixed in X" names a version that does not fix it

`messageFor` (`internal/lsp/diagnostics.go:136`) reports the **worst advisory's**
fixed versions. Across several advisories that is not a remedy, and the archives
say so:

| Package | We say | Actually clears every advisory |
|---|---|---|
| `npm:lodash@4.17.15` | 4.17.21 | **4.18.0** |
| `PyPI:requests@2.19.1` | 2.20.0 | **2.33.0** |

The `npm-range-vs-lock` fixture already demonstrated the bug and nobody noticed:
it pins lodash at **4.17.21** — the version `npm-direct` tells you to upgrade to
— and is still flagged, by three advisories.

The fix is to pick the lowest published fix that no advisory on the package still
affects, verified by running the match again against that candidate. Cheap here,
because the whole database is already in memory: single-digit candidates against
single-digit advisories, once per finding per scan.

Three outcomes rather than two, because "no fix is published" and "fixes exist
but none clears everything" are different sentences: `Clears(v)` → `". Fixed in
{v}"`, `Partial` → `". No single version clears all of them"` (or `". No
published version clears it"` when there is only one), `None` → say nothing, as
today.

**The trap, found in review here and worth knowing before you write it:** the
candidate list must be filtered to versions *above* the installed one. An
advisory patched on two release lines at once publishes a fix on each, and the
lower one is genuinely unaffected — so "the lowest candidate that clears
everything" answers 1.2.3 for a project on 2.0.0, and the diagnostic instructs a
downgrade. The old "list every fixed version" wording could not do this, because
it never named a single version to move to. Django-style advisories (2.2.28 /
3.2.13 / 4.0.4) hit it routinely.

This also removes the Go-toolchain special case (`diagnostics.go`), whose comment
— *"Across seventy-six it is merely the worst one's fix and clears almost none of
the others"* — describes exactly the defect being fixed. With a verified fix,
`Go toolchain 1.21` now reads `Fixed in 1.25.13`.

**Prerequisite, and not optional:** `internal/db/osv.go` does not decode OSV's
range `type`, so `GIT` ranges are flattened like `ECOSYSTEM` ones. **1,575
advisories carry them** — 1,574 PyPI, 1 npm — every one with a commit hash as its
`fixed` value. It is masked today only because PYSEC entries carry no CVSS and so
rarely win `worst()`; a computation that considers *every* advisory unmasks it,
and neither comparator rejects a forty-character hash — both order it silently.
Drop `GIT` ranges only, so an absent or unrecognised type is still indexed: the
filter can lose a hash, never an advisory. Verified against the real archives —
PyPI still indexes 25,029 advisories over 13,316 packages, unchanged.

### 11. A confirmed-malicious package can be reported as an ordinary advisory

`Advisory.Malicious()` (`internal/model/advisory.go:115`) checks the id only.
OSV files some confirmed-malicious events under a `GHSA-` id and cross-references
the canonical `MAL-` one **only as an alias** — twelve such advisories are in the
npm archive now, all from the Shai-Hulud compromise (`debug`, `color-name`,
`error-ex`, `nx`, …).

**Stated precisely, because the first version of this entry overstated it:** in
today's npm archive this changes no finding. Eleven of the twelve are also
covered by a standalone `MAL-` record over the same package, and
`Finding.Malicious()` is an `any`, so the finding is already labelled. The
twelfth (`GHSA-cxm3-wv7p-598c`, over `@nx/key`) is **withdrawn**, so it is never
indexed at all. Checked by building an id→record map over all 229,049 npm
advisories rather than by looking records up by filename, which is what produced
the wrong answer the first time.

Take it anyway, as hardening rather than a fix, for two reasons:

- **The rescue is incidental.** It holds only while a sibling `MAL-` record
  happens to cover the same package *at the same version*. Nothing in OSV
  guarantees that, and the archive is re-downloaded daily.
- **The per-advisory predicate is wrong as written.** `GHSA-9ppg-jx86-fqw7` *is*
  a malicious-package record; asking that advisory whether it is malicious
  currently returns false. Everything that consults one advisory rather than the
  finding — `Severity()`, the sort in `applicable`, and so the `code` and
  `codeDescription` a user clicks — gets the wrong answer even where the finding
  as a whole is labelled correctly.

One line: check `Aliases` as well as `ID`. Not `Related`, which means "see also"
rather than "the same thing under another name". `Aliases` is already populated
and read nowhere, so this is its first real use on both sides.

### 12. Nothing says a manifest edit will not clear the diagnostic

A finding resolved in a lockfile is anchored on the manifest declaration, which
is right — that is where the user can act — but editing it alone does nothing
until the lockfile is regenerated. The `relatedInformation` link already points
at the lockfile; many clients only show it on hover.

One clause, in the existing fact-comma-so-consequence style:
`". Version comes from the lockfile, so editing this file alone will not clear it"`.

Derive it and the `relatedInformation` branch from **one** predicate
(`evidence.Path != anchorSite().Path`), so the sentence and the link cannot come
to disagree about when a lockfile is involved.

**Note before taking this:** `reconcile` looks up `declared` by exact directory
while `lockedAtOrAbove` walks upward (`internal/extract/convert.go:88-126`), so
in an npm workspace — lockfile at the root, `package.json` in `packages/app/` —
the member loses its anchor and the squiggle lands on the lockfile. The sentence
will be absent exactly where it is most needed. Worth fixing first.

### 13. Every read of a project file is unbounded

`os.ReadFile` in `internal/scan/scan.go:313`, `internal/lsp/anchor.go:55` and
`internal/lsp/encoding.go:25`, plus whatever scalibr does internally. A manifest
comes from whatever repository the user opened. The Go side is additionally
looser than the Rust one on file *count*: `WithMaxInodes` exists and is never
called, so `maxInodes` is 0, which means unlimited.

Cap the bytes and skip an oversized file rather than truncating it — `Cargo.lock`
and `requirements.txt` are line-based, so a prefix parses cleanly and turns "too
big to scan" into "half your dependencies are clean". 16 MiB is the figure used
here; a monorepo `package-lock.json` reaches ten.

### Not carried back from this round

**Nothing about scan speed.** The scan was measured phase by phase
(`server_rs/src/bin/scanbench.rs`, the counterpart to `cmd/scanharness`) against
the fixtures, this repository, two real monorepos, and a synthetic 100,200-file
tree with nothing prunable in it — the deliberate worst case, right at the inode
cap:

| Tree | Files walked | Walk | Read+parse | Match |
|---|---:|---:|---:|---:|
| `npm-direct` fixture | 3 | 0.1 ms | 0.1 ms | 0.01 ms |
| This repository | 134 | 0.8 ms | 0.6 ms | 2.9 ms |
| A 136k-file monorepo | 4,914 | 6.4 ms | ~0 ms | 0.2 ms |
| Synthetic, 100k files, nothing prunable | 100,200 | 59.3 ms | 1.7 ms | 1.2 ms |

The worst case is **62 ms behind a 1,000 ms debounce**. An mtime-gated parse
cache would save 1.7 ms of it; a parallel walk would attack the 59 ms that is
already 6% of the window it sits behind; the duplicate read on the publish path
is 10–200 KiB. None of them is worth writing, and that is the result — not a
gap left open.

---

## Deliberately not carried back

- **Rewriting in Rust.** The remaining gap after Tier 1 is 2.6× on load and
  ~23% on retained memory. That is not worth abandoning a working server, a
  tested osv-scalibr integration, and `CGO_ENABLED=0` cross-compilation for.
- **Chasing the last 2.6×.** It is the language: a compile-time-generated JSON
  parser, no GC, and string headers without a capacity word. Go cannot get there
  and should not try.
- **The `requirements.txt` span locator.** Landed on `main` while this was being
  written (`58b3abd`, `7f184ec`), along with Cargo support. The one behavioural
  difference this comparison found no longer exists.

---

## Suggested order

1. ~~Items 1–3~~ and ~~item 5~~ — merged (`ba15557`, `d8768b8`).
2. **Item 4**, once you have decided where the limit comes from. It is a policy
   decision about memory and deserves its own argument in the commit message,
   not a line smuggled in with a speed patch.
3. **Item 10**, ahead of everything else left: it is a wrong answer a user acts
   on rather than a slow one, and its GIT-range prerequisite has to land with it.
   Items 11 and 13 are cheap and belong in the same pass.
4. **Item 8** when the refresh story is next touched — it is a correctness bug
   with a user-visible consequence, not an optimisation.
5. **Item 12** after the workspace-anchor bug it depends on.
6. Items 6, 7 and 9 only if something makes them matter.

`README.md` needs updating either way: its npm row says 3.5 s and 3.5 s is no
longer true.
