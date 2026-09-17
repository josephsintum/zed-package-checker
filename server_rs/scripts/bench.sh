#!/usr/bin/env bash
# Head-to-head advisory-database benchmark: the Go server against this one, over
# the same archives on disk.
#
# Timing and memory are taken from separate binaries on purpose. The counting
# allocator that reports what the index retains uses one atomic counter, which
# every worker contends during a parallel load — with it linked in, npm's
# parallel load measured 508 ms instead of 394 ms. An accurate clock and an
# accurate allocator counter cannot come from the same process.
# No `set -e`: a benchmark that dies silently on one missing measurement is
# worse than one that prints a blank cell.
set -uo pipefail

RS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Built from this worktree, so both implementations are measured at the same
# commit rather than against whatever binary happens to be lying around.
GO_DBCHECK="${GO_DBCHECK:-$RS_DIR/../server/dist/dbcheck}"
if [ ! -x "$GO_DBCHECK" ]; then
  echo "building the Go harness..." >&2
  (cd "$RS_DIR/.." && make dbcheck >&2)
fi
ECOSYSTEMS=("${@:-Go PyPI npm}")
read -ra ECOSYSTEMS <<< "${ECOSYSTEMS[*]}"
RUNS="${RUNS:-3}"

cd "$RS_DIR"
echo "building..." >&2
cargo build --release --quiet --bin dbcheck
cp target/release/dbcheck target/release/dbcheck-timing
cargo build --release --quiet --bin dbcheck --features count-alloc
cp target/release/dbcheck target/release/dbcheck-memory

# maximum resident set size, in MiB, from the kernel rather than from either
# language's own accounting.
peak_mib() { /usr/bin/time -l "$@" 2>&1 >/dev/null | awk '/maximum resident/ {printf "%.0f", $1/1048576}'; }

# Reports the fastest of RUNS runs, in milliseconds. Fastest rather than mean:
# the slow runs are other things happening on the machine, not the program.
fastest() {
  local i
  for i in $(seq 1 "$RUNS"); do
    # grep -m1 rather than `| head -1`: head closing the pipe raises SIGPIPE,
    # which under `set -e -o pipefail` kills this loop's subshell before its
    # output reaches awk.
    "$@" 2>/dev/null | grep -m1 -oE '(load +|in )[0-9.]+ *m?s'
  done | awk '
    { v = $NF
      if (v ~ /ms$/) { sub(/ms$/, "", v); ms = v + 0 }
      else           { sub(/s$/,  "", v); ms = v * 1000 }
      if (best == 0 || ms < best) best = ms }
    END { printf "%.0f", best }'
}

printf '%-12s %-12s %10s %12s %11s\n' ecosystem implementation "load ms" "retained MiB" "peak MiB"
for eco in "${ECOSYSTEMS[@]}"; do
  # Warm the page cache so the first implementation measured is not penalised.
  cat "$HOME/Library/Caches/zed-package-checker/db/osv-scalibr/$eco/all.zip" >/dev/null

  go_ms=$(fastest "$GO_DBCHECK" -runs 1 -load "$eco")
  go_ret=$("$GO_DBCHECK" -runs 1 -load "$eco" | grep -oE 'retained heap after load: [0-9.]+' | grep -oE '[0-9.]+$')
  go_peak=$(peak_mib "$GO_DBCHECK" -runs 1 -load "$eco")
  printf '%-12s %-12s %10s %12s %11s\n' "$eco" go "$go_ms" "$go_ret" "$go_peak"

  for mode in sequential parallel; do
    flag=""; [ "$mode" = sequential ] && flag="--sequential"
    ms=$(fastest ./target/release/dbcheck-timing $flag "$eco")
    ret=$(./target/release/dbcheck-memory $flag "$eco" | grep -oE 'retained [0-9.]+' | awk '{print $2}')
    peak=$(peak_mib ./target/release/dbcheck-timing $flag "$eco")
    printf '%-12s %-12s %10s %12s %11s\n' "$eco" "rust-$mode" "$ms" "$ret" "$peak"
  done
done
