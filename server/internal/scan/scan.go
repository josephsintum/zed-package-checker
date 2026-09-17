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
	"slices"
	"sync"
	"time"

	"github.com/josephsintum/zed-package-checker/server/internal/db"
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

	// mu guards the cached index. Scans can overlap: cancelling a superseded
	// scan is best-effort, so a new one may start while the old is still
	// unwinding.
	mu        sync.Mutex
	index     *db.Index
	indexedAt time.Time
	warming   bool

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

	ecosystems := ecosystemsOf(pkgs)
	if !s.database.Ready(ecosystems) {
		s.warmInBackground(ctx, ecosystems)
		return model.Report{}, fmt.Errorf("%w: %v", db.ErrNotReady, ecosystems)
	}

	index, err := s.indexFor(ctx, ecosystems)
	if err != nil {
		return model.Report{}, err
	}

	findings, err := match.New(s.log, index).Findings(ctx, pkgs)
	if err != nil {
		return model.Report{}, fmt.Errorf("match: %w", err)
	}

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

		s.log.Info("downloading advisory database", "ecosystems", ecosystems)
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

// NotReady reports whether err means the database is still downloading, rather
// than that something went wrong.
func NotReady(err error) bool { return errors.Is(err, db.ErrNotReady) }

// ecosystemsOf returns the distinct ecosystems present, in a stable order.
func ecosystemsOf(pkgs []model.ExtractedPackage) []model.Ecosystem {
	var out []model.Ecosystem
	for _, p := range pkgs {
		if !slices.Contains(out, p.Package.Ecosystem) {
			out = append(out, p.Package.Ecosystem)
		}
	}
	slices.Sort(out)
	return out
}
