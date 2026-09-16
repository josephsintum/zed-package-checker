package db

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// Load parses the archives for the given ecosystems into an in-memory index.
//
// Expensive — seconds and a few hundred megabytes of transient allocation for a
// large ecosystem — so it runs once at startup and again only when the archives
// change. Callers hold the result; they do not call this per scan.
//
// Ensure must have run first; a missing archive is reported as ErrNotReady
// rather than silently producing an index with nothing in it, because "not
// downloaded yet" and "nothing is vulnerable" must never look alike.
func (d *DB) Load(ctx context.Context, ecosystems []model.Ecosystem) (*Index, error) {
	start := d.now()
	idx := &Index{
		byPackage: make(map[model.PackageKey][]model.Advisory),
		builtAt:   start,
	}

	for _, e := range ecosystems {
		if !e.Valid() {
			continue
		}
		archive := d.archivePath(e)
		if !exists(archive) {
			return nil, fmt.Errorf("%w: %s", ErrNotReady, e)
		}
		count, skipped, err := loadArchive(ctx, archive, e, idx)
		if err != nil {
			return nil, fmt.Errorf("load %s: %w", e, err)
		}
		if skipped > 0 {
			// Not fatal, but never silent: indexing fewer advisories than the
			// archive holds is a false negative, and a security tool that
			// under-reports without saying so is worse than one that fails.
			d.log.Warn("advisories skipped as unreadable",
				"ecosystem", e.String(), "skipped", skipped, "indexed", count)
		}
		idx.ecosystems = append(idx.ecosystems, e)
		idx.advisories += count
	}

	d.log.Info("advisory index built",
		"ecosystems", len(idx.ecosystems),
		"advisories", idx.advisories,
		"packages", idx.Packages(),
		"took", d.now().Sub(start).Round(time.Millisecond).String())
	return idx, nil
}

// loadArchive streams one ecosystem's archive into idx, returning how many
// advisories were indexed and how many entries could not be decoded.
//
// The archive is opened from disk rather than read into memory. osv-scanner
// does the latter — os.ReadFile followed by bytes.NewReader — which holds the
// entire 205 MB npm archive live for the whole walk and is the single largest
// term in its memory use. Entries are decoded one at a time and discarded, so
// only what the index retains survives.
func loadArchive(ctx context.Context, path string, e model.Ecosystem, idx *Index) (indexed, skipped int, err error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return 0, 0, fmt.Errorf("open %s: %w", path, err)
	}
	defer r.Close()

	var (
		entries  int
		firstErr error
	)
	for i, entry := range r.File {
		// Loading a large ecosystem takes seconds; a cancelled scan or a
		// shutting-down server should not wait for it to finish.
		if i%512 == 0 {
			if err := ctx.Err(); err != nil {
				return indexed, skipped, err
			}
		}
		if !strings.HasSuffix(entry.Name, ".json") {
			continue
		}
		entries++

		advisory, ok, err := decodeEntry(entry, e)
		if err != nil {
			// One malformed advisory must not cost the user every other one.
			// Archives are generated, so this should not happen; if it does,
			// the remaining thousands are still worth having. The count goes
			// back to the caller rather than being dropped on the floor.
			skipped++
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", entry.Name, err)
			}
			continue
		}
		if !ok {
			continue
		}

		for _, affected := range advisory.Affected {
			idx.byPackage[affected.Package] = append(idx.byPackage[affected.Package], advisory)
		}
		indexed++
	}

	// Every entry failing is corruption, not content. An archive of entirely
	// withdrawn or out-of-ecosystem advisories decodes cleanly and simply
	// indexes nothing, so the two are distinguishable — and they must be:
	// reporting a damaged archive as a successful empty load is how "not
	// loaded" comes to look like "nothing is vulnerable".
	if entries > 0 && skipped == entries {
		return indexed, skipped, fmt.Errorf("%w: all %d advisories in %s failed to decode: %w",
			ErrNotReady, entries, path, firstErr)
	}
	return indexed, skipped, nil
}

// decodeEntry reads and converts one advisory from the archive.
func decodeEntry(entry *zip.File, e model.Ecosystem) (model.Advisory, bool, error) {
	f, err := entry.Open()
	if err != nil {
		return model.Advisory{}, false, err
	}
	defer f.Close()

	var raw osvAdvisory
	if err := json.NewDecoder(f).Decode(&raw); err != nil {
		return model.Advisory{}, false, err
	}
	advisory, ok := raw.toModel(e)
	return advisory, ok, nil
}
