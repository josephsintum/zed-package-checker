package db

import (
	"archive/zip"
	"encoding/json"
	"fmt"

	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// Details returns an advisory's full description, read from the archive.
//
// Kept out of the in-memory index because it dominates its size while being
// needed only for the few advisories a project actually matches. Reading it
// back costs one seek into the archive's central directory, which is cheap and
// happens while a user is hovering rather than during a scan.
func (d *DB) Details(e model.Ecosystem, advisoryID string) (string, error) {
	archive := d.archivePath(e)
	r, err := zip.OpenReader(archive)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", archive, err)
	}
	defer r.Close()

	// Archives name each entry after its advisory id.
	f, err := r.Open(advisoryID + ".json")
	if err != nil {
		return "", fmt.Errorf("find %s in %s: %w", advisoryID, e, err)
	}
	defer f.Close()

	var raw struct {
		Details string `json:"details"`
	}
	if err := json.NewDecoder(f).Decode(&raw); err != nil {
		return "", fmt.Errorf("decode %s: %w", advisoryID, err)
	}
	return raw.Details, nil
}
