package db

import (
	"os"
	"path/filepath"

	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// archiveHost serves the OSV database, one zip per ecosystem.
const archiveHost = "https://osv-vulnerabilities.storage.googleapis.com"

// archiveName is the file every ecosystem's advisories are published as.
const archiveName = "all.zip"

// vendorDir matches the layout osv-scanner uses, so the same cache can be
// pointed at osv-scanner when differential-testing our matcher against it.
const vendorDir = "osv-scalibr"

// DefaultRoot returns the cache directory the database lives in.
//
// A cache rather than a config directory: it is derived data, reproducible by
// re-downloading, and users should be free to delete it to reclaim the space.
func DefaultRoot() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "zed-package-checker", "db"), nil
}

// dirFor returns the directory holding one ecosystem's files.
func (d *DB) dirFor(e model.Ecosystem) string {
	return filepath.Join(d.root, vendorDir, e.String())
}

// archivePath is the advisory archive itself, at the path osv-scanner expects.
func (d *DB) archivePath(e model.Ecosystem) string {
	return filepath.Join(d.dirFor(e), archiveName)
}

// metaPath holds our own bookkeeping beside the archive: the validator to send
// on the next conditional request, and when it was last fetched.
func (d *DB) metaPath(e model.Ecosystem) string {
	return filepath.Join(d.dirFor(e), archiveName+".meta")
}

// lockPath guards refreshes of one ecosystem across processes.
func (d *DB) lockPath(e model.Ecosystem) string {
	return filepath.Join(d.dirFor(e), archiveName+".lock")
}

// archiveURL is where an ecosystem's advisories are published.
func archiveURL(e model.Ecosystem) string {
	// Ecosystem names are used verbatim, including case and the dot in
	// "crates.io"; normalising them produces 404s.
	return archiveHost + "/" + e.String() + "/" + archiveName
}
