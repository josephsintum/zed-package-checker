package db

import (
	"archive/zip"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// fetch downloads one ecosystem's archive if it is missing or out of date.
//
// Returns true when new bytes were installed, false when the cached copy was
// already current. The caller holds the lock for this ecosystem.
func (d *DB) fetch(ctx context.Context, e model.Ecosystem) (updated bool, err error) {
	archive := d.archivePath(e)
	url := archiveURL(e)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Errorf("build request for %s: %w", url, err)
	}
	// Only offer a validator when the archive it describes is actually present;
	// otherwise a 304 would leave us with metadata and no data.
	if m, ok := d.readMeta(d.metaPath(e)); ok && m.ETag != "" && exists(archive) {
		req.Header.Set("If-None-Match", m.ETag)
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		// Still current. Record the check so staleness is measured from now
		// rather than from the last time the bytes changed, which for a quiet
		// ecosystem could be weeks ago.
		m, _ := d.readMeta(d.metaPath(e))
		m.FetchedAt = d.now()
		if err := d.writeMeta(d.metaPath(e), m); err != nil {
			return false, err
		}
		return false, nil
	case http.StatusOK:
	default:
		return false, fmt.Errorf("fetch %s: unexpected status %s", url, resp.Status)
	}

	wantCRC, haveCRC := crc32cFromHeader(resp.Header)

	var written int64
	err = writeAtomic(archive, func(w io.Writer) error {
		n, copyErr := io.Copy(w, resp.Body)
		written = n
		return copyErr
	}, func(tmp string) error {
		return verifyArchive(tmp, wantCRC, haveCRC)
	})
	if err != nil {
		return false, fmt.Errorf("install %s: %w", archive, err)
	}

	err = d.writeMeta(d.metaPath(e), meta{
		ETag:      resp.Header.Get("ETag"),
		FetchedAt: d.now(),
		CRC32C:    wantCRC,
	})
	if err != nil {
		return false, err
	}

	d.log.Info("database updated",
		"ecosystem", e.String(), "bytes", written, "url", url)
	return true, nil
}

// verifyArchive checks a freshly downloaded file before it is published.
//
// Two independent checks, because they catch different failures: the checksum
// catches a truncated or corrupted transfer, while opening the zip catches a
// well-transferred file that is not the archive we expect — an error page or a
// redirect body served with a 200.
func verifyArchive(path string, wantCRC uint32, haveCRC bool) error {
	if haveCRC {
		got, err := checksum(path)
		if err != nil {
			return fmt.Errorf("checksum %s: %w", path, err)
		}
		if got != wantCRC {
			return fmt.Errorf("checksum mismatch: got %08x, want %08x", got, wantCRC)
		}
	}
	return validateZip(path)
}

// validateZip reports whether path is a readable zip archive.
func validateZip(path string) error {
	r, err := zip.OpenReader(path)
	if err != nil {
		return fmt.Errorf("not a readable zip archive: %w", err)
	}
	defer r.Close()

	if len(r.File) == 0 {
		return fmt.Errorf("zip archive is empty")
	}
	return nil
}

// crc32cFromHeader extracts the CRC32C checksum Cloud Storage advertises.
//
// The header looks like `x-goog-hash: crc32c=W3hLNw==`, may repeat for other
// algorithms, and may be absent entirely — against a mirror or a test server,
// for instance — in which case the zip structure check stands alone.
func crc32cFromHeader(h http.Header) (sum uint32, ok bool) {
	for _, value := range h.Values("x-goog-hash") {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			encoded, found := strings.CutPrefix(part, "crc32c=")
			if !found {
				continue
			}
			raw, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil || len(raw) != 4 {
				continue
			}
			return binary.BigEndian.Uint32(raw), true
		}
	}
	return 0, false
}

// defaultHTTPClient is deliberately not http.DefaultClient, which has no
// timeout: a stalled connection would otherwise hang a refresh forever.
func defaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Minute, // npm's archive is 205 MB
	}
}
