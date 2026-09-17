# Carrying the findings back into the Go server

The Rust rewrite was a research exercise; **this file is the part of it that is
worth shipping.** Nothing here proposes changing language. Everything is a change
to `server/`, ranked by measured value against effort, with the numbers that
justify it.

Measurements are npm's archive — 229,049 entries, 379 MB uncompressed — on an
Apple-silicon machine with 14 cores, fastest of three, page cache warm.
Reproduce with `server_rs/scripts/bench.sh`.

---

## Tier 1 — landed on branch `db-parallel-load`

Items 1–3 and item 5 are committed on **`db-parallel-load`**, branched from
`main` at `bd009c9`:

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
| `db-parallel-load` | **973 ms** | 467 MiB |
| plus item 4 (measured only) | ~1,120 ms | **351 MiB** |

End to end, time to first diagnostics, fastest of three:

| Fixture | `main` | `db-parallel-load` |
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

Measured on `db-parallel-load`, best of five: **1,014 ms → 973 ms**, a 4%
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

1. ~~Items 1–3~~ and ~~item 5~~ — done, on `db-parallel-load`. Review and merge.
2. **Item 4**, once you have decided where the limit comes from. It is a policy
   decision about memory and deserves its own argument in the commit message,
   not a line smuggled in with a speed patch.
3. **Item 8** when the refresh story is next touched — it is a correctness bug
   with a user-visible consequence, not an optimisation.
4. Items 6, 7 and 9 only if something makes them matter.

`README.md` needs updating either way: its npm row says 3.5 s and 3.5 s is no
longer true.
