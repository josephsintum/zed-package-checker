package db

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"time"

	kpflate "github.com/klauspost/compress/flate"

	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// decodeQueue bounds how many entries are in flight between the walker, the
// decoders and the indexer, so the archive is never buffered whole.
const decodeQueue = 512

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

	// Inflating is 75% of a load's wall time for npm, and compress/flate is the
	// slow part of it. klauspost was already in the module graph, as an
	// indirect dependency of osv-scalibr.
	r.RegisterDecompressor(zip.Deflate, func(in io.Reader) io.ReadCloser {
		return kpflate.NewReader(in)
	})

	// Decoding is pure per entry, so it fans out across every core. Indexing is
	// not: one goroutine owns the map and is fed over a channel.
	//
	// Insertion order therefore no longer matches archive order. Safe because
	// match sorts each package's advisories by severity then id, which is a
	// total order — but it is the reason this is not simply a parallel map.
	type decoded struct {
		advisory model.Advisory
		name     string
		ok       bool
		err      error
	}

	jobs := make(chan *zip.File, decodeQueue)
	results := make(chan decoded, decodeQueue)

	go func() {
		defer close(jobs)
		for _, entry := range r.File {
			if !strings.HasSuffix(entry.Name, ".json") {
				continue
			}
			select {
			case jobs <- entry:
			case <-ctx.Done():
				return
			}
		}
	}()

	var wg sync.WaitGroup
	for range runtime.GOMAXPROCS(0) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// One buffer per worker, rather than a json.Decoder and its read
			// buffer allocated 229,049 times.
			buf := make([]byte, 0, 16<<10)
			for entry := range jobs {
				advisory, ok, err := decodeEntry(entry, e, &buf)
				results <- decoded{advisory: advisory, name: entry.Name, ok: ok, err: err}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	var (
		entries  int
		firstErr error
	)
	// Drained to completion even after cancellation, so no worker is left
	// blocked on a send and no goroutine outlives this call.
	for res := range results {
		entries++
		if res.err != nil {
			// One malformed advisory must not cost the user every other one.
			// Archives are generated, so this should not happen; if it does,
			// the remaining thousands are still worth having. The count goes
			// back to the caller rather than being dropped on the floor.
			skipped++
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", res.name, res.err)
			}
			continue
		}
		if !res.ok {
			continue
		}
		for _, affected := range res.advisory.Affected {
			idx.byPackage[affected.Package] = append(idx.byPackage[affected.Package], res.advisory)
		}
		indexed++
	}

	// Loading a large ecosystem takes seconds; a cancelled scan or a
	// shutting-down server should not keep its results.
	if err := ctx.Err(); err != nil {
		return indexed, skipped, err
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
//
// buf is the caller's scratch space, reused across entries and not retained.
func decodeEntry(entry *zip.File, e model.Ecosystem, buf *[]byte) (model.Advisory, bool, error) {
	f, err := entry.Open()
	if err != nil {
		return model.Advisory{}, false, err
	}
	defer f.Close()

	*buf = (*buf)[:0]
	if err := readAll(f, buf); err != nil {
		return model.Advisory{}, false, err
	}

	var raw osvAdvisory
	if err := json.Unmarshal(*buf, &raw); err != nil {
		return model.Advisory{}, false, err
	}
	advisory, ok := raw.toModel(e)
	return advisory, ok, nil
}

// readAll appends everything r produces to buf.
//
// Not io.ReadAll, which allocates a fresh slice per call.
func readAll(r io.Reader, buf *[]byte) error {
	for {
		if len(*buf) == cap(*buf) {
			*buf = append(*buf, 0)[:len(*buf)]
		}
		n, err := r.Read((*buf)[len(*buf):cap(*buf)])
		*buf = (*buf)[:len(*buf)+n]
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
