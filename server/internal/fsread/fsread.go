// Package fsread reads a project's files, bounded.
//
// A manifest comes from whatever repository the user opened, so its size is not
// ours to assume. The cap is a correctness bound rather than a preference:
// positions are reported as int32 line and column offsets, and nothing in the
// pipeline checks for overflow.
package fsread

import (
	"errors"
	"io"
	"log/slog"
	"os"
)

// MaxManifestBytes is the most of one file that is ever read.
//
// The largest monorepo lockfiles reach about ten megabytes, so this leaves real
// headroom without approaching the sizes at which offsets stop fitting.
const MaxManifestBytes int64 = 16 << 20

// ErrTooLarge reports a file past the cap. Returned rather than logged here so
// the caller decides what a skipped file means for it.
var ErrTooLarge = errors.New("file larger than the scan cap")

// Manifest returns a file's contents, or an error if it cannot be read or is
// larger than MaxManifestBytes.
func Manifest(path string) ([]byte, error) {
	return bounded(path, MaxManifestBytes)
}

// ManifestOrNil returns a file's contents, or nil when it cannot be read.
//
// For the callers whose contract is already "no source, degrade gracefully".
// An oversized file is logged, because a skipped manifest is not merely absent
// from the report: it is published as having nothing wrong with it.
func ManifestOrNil(log *slog.Logger, path string) []byte {
	src, err := Manifest(path)
	if err == nil {
		return src
	}
	if errors.Is(err, ErrTooLarge) && log != nil {
		log.Warn("manifest too large to scan", "path", path, "cap", MaxManifestBytes)
	}
	return nil
}

// bounded is split out from Manifest so the cap can be exercised with a
// nine-byte file rather than a sixteen-megabyte one.
//
// Skips an oversized file rather than truncating it: Cargo.lock and
// requirements.txt are line-based, so a prefix parses cleanly and "too big to
// scan" would read as "half your dependencies are fine".
func bounded(path string, cap int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only

	// Measured through the open handle rather than the path, so the file
	// checked is the file read.
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > cap {
		return nil, ErrTooLarge
	}

	// The stat above is a hint, not a guarantee: a file being written can grow
	// between the two calls. Reading one byte past the cap is what turns it
	// into a bound.
	src, err := io.ReadAll(io.LimitReader(f, cap+1))
	if err != nil {
		return nil, err
	}
	if int64(len(src)) > cap {
		return nil, ErrTooLarge
	}
	return src, nil
}
