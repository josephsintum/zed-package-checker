// Package scan assembles extraction, the advisory database and matching into
// the single Scanner the engine schedules.
//
// It owns one piece of state worth understanding: the parsed advisory index.
// Building that costs seconds and hundreds of megabytes for a large ecosystem,
// so it is built once and reused, and rebuilt only when the set of ecosystems
// in the project changes or the database is refreshed underneath it.
package scan

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/josephsintum/zed-package-checker/server/internal/db"
	"github.com/josephsintum/zed-package-checker/server/internal/fsread"
	"github.com/josephsintum/zed-package-checker/server/internal/locate"
	"github.com/josephsintum/zed-package-checker/server/internal/match"
	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// Extractor finds a project's dependencies.
type Extractor interface {
	Extract(ctx context.Context, root string) ([]model.ExtractedPackage, error)
}

// Database provides the advisory archives and the parsed index over them.
type Database interface {
	Ready(ecosystems []model.Ecosystem) bool
	Ensure(ctx context.Context, ecosystems []model.Ecosystem) error
	Load(ctx context.Context, ecosystems []model.Ecosystem) (*db.Index, error)
}

// Scanner produces a report for a project.
type Scanner struct {
	extractor Extractor
	database  Database
	log       *slog.Logger

	// onReady is called once a background download finishes, so the caller can
	// ask for the rescan that will finally produce findings.
	onReady func()

	// setMemoryLimit applies a soft heap limit, when the caller supplied one.
	// Held here rather than called from db because the size is db's knowledge
	// but the process's memory policy is main's decision.
	setMemoryLimit func(int64)
	// limitApplied is the largest limit set so far, guarded by mu. Only ever
	// raised: lowering it under a live index would make the collector fight a
	// heap it cannot shrink.
	limitApplied int64

	// mu guards the cached index. Scans can overlap: cancelling a superseded
	// scan is best-effort, so a new one may start while the old is still
	// unwinding.
	mu        sync.Mutex
	index     *db.Index
	indexedAt time.Time
	// refreshedAt is when the database was last asked to revalidate, which is
	// not the same question as when the index was last built: a revalidation
	// that changes nothing leaves the index alone.
	refreshedAt time.Time
	warming     bool

	// A background download outlives the scan that started it, so the Scanner
	// owns it: done stops it, wg makes the stop observable.
	done     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// warmTimeout bounds a background download.
const warmTimeout = 30 * time.Minute

// Option configures a Scanner.
type Option func(*Scanner)

// OnDatabaseReady sets the callback fired when a background download completes.
func OnDatabaseReady(f func()) Option { return func(s *Scanner) { s.onReady = f } }

// WithMemoryLimit supplies the setter for the process's soft heap limit,
// normally debug.SetMemoryLimit.
//
// Injected rather than called directly so that a package which merely loads a
// database does not reach out and reconfigure the runtime.
func WithMemoryLimit(set func(int64)) Option {
	return func(s *Scanner) { s.setMemoryLimit = set }
}

// New builds a Scanner.
func New(log *slog.Logger, extractor Extractor, database Database, opts ...Option) *Scanner {
	s := &Scanner{
		extractor: extractor,
		database:  database,
		log:       log,
		done:      make(chan struct{}),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Scan extracts the project's dependencies and reports which are vulnerable.
//
// When the advisory database for a project's ecosystems has not been downloaded
// yet, the download is started in the background and db.ErrNotReady returned.
// That is deliberately not an empty report: "still downloading" and "nothing is
// vulnerable" must never look alike, because the second is what a user acts on.
func (s *Scanner) Scan(ctx context.Context, root string) (model.Report, error) {
	pkgs, err := s.extractor.Extract(ctx, root)
	if err != nil {
		return model.Report{}, fmt.Errorf("extract: %w", err)
	}
	if len(pkgs) == 0 {
		// The server attaches to nearly every language, so most workspaces it
		// starts in have no dependencies at all. Do no database work for them.
		return model.Report{Root: root, ScannedAt: time.Now()}, nil
	}

	ecosystems := model.EcosystemsOf(pkgs)
	if !s.database.Ready(ecosystems) {
		s.warmInBackground(ctx, ecosystems)
		return model.Report{}, fmt.Errorf("%w: %v", db.ErrNotReady, ecosystems)
	}

	index, err := s.indexFor(ctx, ecosystems)
	if err != nil {
		return model.Report{}, err
	}
	s.refreshIfDue(ctx, ecosystems)

	findings, err := match.New(s.log, index).Findings(ctx, pkgs)
	if err != nil {
		return model.Report{}, fmt.Errorf("match: %w", err)
	}
	locateSpans(s.log, findings)

	return model.Report{
		Root:      root,
		Findings:  findings,
		ScannedAt: time.Now(),
	}, nil
}

// indexFor returns an index covering the given ecosystems, reusing the cached
// one when it already does.
func (s *Scanner) indexFor(ctx context.Context, ecosystems []model.Ecosystem) (*db.Index, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.index != nil && s.index.Covers(ecosystems) {
		return s.index, nil
	}

	// Raised before the load, not after: the overshoot happens while decoding.
	if s.setMemoryLimit != nil {
		if want := db.MemoryLimitFor(ecosystems); want > s.limitApplied {
			s.limitApplied = want
			s.setMemoryLimit(want)
		}
	}

	index, err := s.database.Load(ctx, ecosystems)
	if err != nil {
		return nil, fmt.Errorf("load advisories: %w", err)
	}
	s.index = index
	s.indexedAt = time.Now()
	return index, nil
}

// Invalidate discards the cached index, forcing the next scan to rebuild it.
// Called when the database has been refreshed underneath us.
func (s *Scanner) Invalidate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.index = nil
}

// refreshCheckEvery is how often a scan offers the database a chance to
// revalidate. Shorter than the database's own 24-hour freshness window, because
// this only asks — db decides whether anything is actually stale, and answers
// with one small metadata read when it is not.
const refreshCheckEvery = time.Hour

// refreshIfDue asks the database to revalidate, at most once an hour.
//
// Without this the freshness window was a constant nobody consulted. Ready
// reports only whether an archive exists, so once one is on disk the server
// never reached Ensure again: an editor left open for a week went on matching
// against week-old advisories, while the README promised a daily refresh.
//
// The work is the same as a cold start's — Ensure checks staleness, revalidates
// with the ETag, and only downloads when the server says the archive changed —
// so it reuses the same background path, which already guarantees one at a time
// and stops on Close.
func (s *Scanner) refreshIfDue(ctx context.Context, ecosystems []model.Ecosystem) {
	s.mu.Lock()
	if !s.refreshedAt.IsZero() && time.Since(s.refreshedAt) < refreshCheckEvery {
		s.mu.Unlock()
		return
	}
	s.refreshedAt = time.Now()
	s.mu.Unlock()

	s.warmInBackground(ctx, ecosystems)
}

// Close stops any background download and waits for it to unwind.
//
// Safe to call more than once, and safe to call on a Scanner that never
// downloaded anything.
func (s *Scanner) Close() error {
	s.stopOnce.Do(func() { close(s.done) })
	s.wg.Wait()
	return nil
}

// warmInBackground downloads the archives for ecosystems without blocking the
// scan, and asks for a rescan once they land.
//
// Only one warm runs at a time: a project with a missing database produces a
// failed scan on every trigger, and each of those must not start its own
// download.
func (s *Scanner) warmInBackground(ctx context.Context, ecosystems []model.Ecosystem) {
	select {
	case <-s.done:
		// Closed. Adding to the WaitGroup after Wait has returned is undefined,
		// and today only the order of main's deferred Closes prevents it.
		return
	default:
	}

	s.mu.Lock()
	if s.warming {
		s.mu.Unlock()
		return
	}
	s.warming = true
	s.mu.Unlock()

	// Deliberately not the scan's context: the download must survive the scan
	// that triggered it being cancelled, or it would restart from nothing on
	// every attempt. WithoutCancel drops the cancellation but keeps the values,
	// so whatever the request context carries is still reachable from here —
	// which is what lets progress be reported to the editor.
	warmCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), warmTimeout)

	s.wg.Go(func() {
		defer cancel()
		defer func() {
			s.mu.Lock()
			s.warming = false
			s.mu.Unlock()
		}()

		// Reached both by a cold start and by an hourly revalidation, so the
		// wording covers a download that may not happen.
		s.log.Info("checking the advisory database", "ecosystems", ecosystems)
		if err := s.database.Ensure(warmCtx, ecosystems); err != nil {
			s.log.Warn("advisory database download failed", "error", err)
			return
		}

		s.Invalidate()
		s.log.Info("advisory database ready", "ecosystems", ecosystems)
		if s.onReady != nil {
			s.onReady()
		}
	})

	// Close must interrupt a download rather than wait out warmTimeout. This
	// exits as soon as the download finishes, since that cancels warmCtx.
	s.wg.Go(func() {
		select {
		case <-s.done:
			cancel()
		case <-warmCtx.Done():
		}
	})
}

// locateSpans narrows each finding from a whole line to the exact span of the
// dependency's name, and records where its version is written.
//
// Best-effort throughout: extraction gives a line, which is already a usable
// diagnostic. A manifest that has changed since the scan started, or one caught
// mid-save, simply keeps that line rather than failing the scan over a squiggle
// that would have been a little tidier.
//
// Each manifest is read at most once, however many of its dependencies are
// vulnerable.
func locateSpans(log *slog.Logger, findings []model.Finding) {
	parsed := map[string]map[string]model.Anchor{}

	for i := range findings {
		site := findings[i].AnchorSite()
		locator := locatorFor(filepath.Base(site.Path))
		if locator == nil {
			continue
		}

		anchors, read := parsed[site.Path]
		if !read {
			// Cached even when it fails, so an unreadable manifest is not
			// re-read once per finding.
			if src := fsread.ManifestOrNil(log, site.Path); src != nil {
				anchors = locator(src, site.Path)
			}
			parsed[site.Path] = anchors
		}

		if anchor, ok := lookupAnchor(anchors, findings[i].Package); ok {
			findings[i].Declared = &anchor
		}
	}
}

// locator resolves a manifest's dependency spans, keyed by dependency name.
type locator func(src []byte, path string) map[string]model.Anchor

// lookupAnchor finds a package's anchor, allowing for the two spellings a name
// can have.
//
// PyPI names are compared after PEP 503 normalisation — "Flask_SQLAlchemy" and
// "flask-sqlalchemy" are one package — and a requirements file may use either
// while the extractor reports whichever it read.
func lookupAnchor(anchors map[string]model.Anchor, pkg model.Package) (model.Anchor, bool) {
	if anchor, ok := anchors[pkg.Name]; ok {
		return anchor, true
	}
	if pkg.Ecosystem == model.EcosystemPyPI {
		anchor, ok := anchors[locate.NormalisePyPI(pkg.Name)]
		return anchor, ok
	}
	return model.Anchor{}, false
}

// locatorFor returns the locator for a manifest, or nil for a file whose spans
// nothing can narrow yet — a lockfile, or requirements.txt until Stage 13.
func locatorFor(name string) locator {
	switch {
	case name == "package.json":
		return locate.PackageJSON
	case name == "go.mod":
		return locate.GoMod
	case name == "Cargo.toml":
		// Not merely a tighter span: scalibr's cargotoml records no line at
		// all, so without this a Rust finding sits on line 1.
		return locate.CargoToml
	case strings.HasPrefix(name, "requirements") && strings.HasSuffix(name, ".txt"):
		return locate.Requirements
	default:
		return nil
	}
}

// NotReady reports whether err means the database is still downloading, rather
// than that something went wrong.
func NotReady(err error) bool { return errors.Is(err, db.ErrNotReady) }
