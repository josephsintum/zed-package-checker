package db

import (
	"encoding/json"
	"errors"
	"hash/crc32"
	"io"
	"io/fs"
	"os"
	"time"
)

// castagnoli is the CRC32 polynomial Google Cloud Storage uses for its
// x-goog-hash checksums. The IEEE polynomial, which crc32.ChecksumIEEE uses by
// default, produces different values and will never match.
var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// meta records what we know about a downloaded archive.
//
// Kept beside the archive so a refresh check costs one conditional request
// rather than re-reading and re-hashing hundreds of megabytes.
type meta struct {
	// ETag from the response, sent back as If-None-Match.
	ETag string `json:"etag"`

	// FetchedAt is when the archive was last confirmed current, which is
	// updated on a 304 as well as on a download.
	FetchedAt time.Time `json:"fetchedAt"`

	// CRC32C is the checksum the server reported, retained so corruption can
	// be detected without asking the network.
	CRC32C uint32 `json:"crc32c"`
}

// readMeta loads the bookkeeping for an archive.
//
// A missing or unparsable file is not an error: it means the archive must be
// treated as stale and re-fetched, which is always safe.
func (d *DB) readMeta(path string) (meta, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return meta{}, false
	}
	var m meta
	if err := json.Unmarshal(raw, &m); err != nil {
		return meta{}, false
	}
	return m, true
}

// writeMeta stores bookkeeping atomically, so a crash cannot leave a truncated
// file that later parses as something plausible.
func (d *DB) writeMeta(path string, m meta) error {
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, raw, 0o644)
}

// checksum returns the CRC32C of a file, or an error if it cannot be read.
func checksum(path string) (uint32, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	h := crc32.New(castagnoli)
	if _, err := io.Copy(h, f); err != nil {
		return 0, err
	}
	return h.Sum32(), nil
}

// exists reports whether a regular file is present at path.
func exists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().IsRegular()
}

// isNotExist reports whether err means "no such file", tolerating wrapping.
func isNotExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist)
}
