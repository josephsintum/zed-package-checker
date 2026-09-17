package scan

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/josephsintum/zed-package-checker/server/internal/db"
	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// TestMain fails any test that leaves a goroutine behind. The Scanner owns a
// background download, and an owned goroutine that outlives Close is the bug
// this package most needs to be told about.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

type fakeExtractor struct {
	pkgs []model.ExtractedPackage
	err  error
}

func (f *fakeExtractor) Extract(context.Context, string) ([]model.ExtractedPackage, error) {
	return f.pkgs, f.err
}

// fakeDB stands in for the advisory database. Ensure optionally blocks, so a
// download can be held open while the test exercises shutdown.
type fakeDB struct {
	mu      sync.Mutex
	ready   bool
	ensures int
	loads   int

	// block, when non-nil, holds Ensure until it is closed or ctx is cancelled.
	block chan struct{}
	// entered is closed the first time Ensure is called.
	entered chan struct{}
	once    sync.Once
}

func (f *fakeDB) Ready([]model.Ecosystem) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ready
}

func (f *fakeDB) Ensure(ctx context.Context, _ []model.Ecosystem) error {
	f.mu.Lock()
	f.ensures++
	f.mu.Unlock()
	if f.entered != nil {
		f.once.Do(func() { close(f.entered) })
	}
	if f.block == nil {
		f.mu.Lock()
		f.ready = true
		f.mu.Unlock()
		return nil
	}
	select {
	case <-f.block:
		f.mu.Lock()
		f.ready = true
		f.mu.Unlock()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (f *fakeDB) Load(context.Context, []model.Ecosystem) (*db.Index, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loads++
	return nil, nil
}

func (f *fakeDB) counts() (ensures, loads int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ensures, f.loads
}

func npmPackages() []model.ExtractedPackage {
	return []model.ExtractedPackage{{
		Package: model.Package{
			PackageKey: model.PackageKey{Ecosystem: model.EcosystemNPM, Name: "lodash"},
			Version:    "4.17.15",
		},
		Evidence: model.Site{Path: "/proj/package.json", Range: model.WholeLine(3)},
	}}
}

func TestScanWithoutDependenciesDoesNoDatabaseWork(t *testing.T) {
	// The server attaches to nearly every language, so most workspaces it
	// starts in have nothing to scan. Those must not trigger a 205 MB download.
	database := &fakeDB{}
	s := New(discardLogger(), &fakeExtractor{}, database)
	defer func() { _ = s.Close() }()

	report, err := s.Scan(t.Context(), "/proj")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(report.Findings) != 0 {
		t.Errorf("findings = %d, want 0", len(report.Findings))
	}
	if ensures, loads := database.counts(); ensures != 0 || loads != 0 {
		t.Errorf("database touched: %d ensures, %d loads; want none", ensures, loads)
	}
}

func TestScanReportsNotReadyRatherThanClean(t *testing.T) {
	// "Still downloading" and "nothing is vulnerable" must never look alike:
	// the second is the one a user acts on.
	database := &fakeDB{ready: false, block: make(chan struct{})}
	s := New(discardLogger(), &fakeExtractor{pkgs: npmPackages()}, database)
	defer func() { _ = s.Close() }()

	_, err := s.Scan(t.Context(), "/proj")
	if !errors.Is(err, db.ErrNotReady) {
		t.Fatalf("Scan with no database returned %v, want ErrNotReady", err)
	}
	if !NotReady(err) {
		t.Error("NotReady did not recognise its own sentinel")
	}
}

func TestRepeatedScansStartOnlyOneDownload(t *testing.T) {
	// A project with a missing database fails every scan it is asked for, and
	// each failure must not start its own download.
	database := &fakeDB{block: make(chan struct{}), entered: make(chan struct{})}
	s := New(discardLogger(), &fakeExtractor{pkgs: npmPackages()}, database)
	defer func() { _ = s.Close() }()

	for range 5 {
		if _, err := s.Scan(t.Context(), "/proj"); !errors.Is(err, db.ErrNotReady) {
			t.Fatalf("Scan returned %v, want ErrNotReady", err)
		}
	}

	<-database.entered
	if ensures, _ := database.counts(); ensures != 1 {
		t.Errorf("started %d downloads, want exactly 1", ensures)
	}
}

func TestCloseStopsADownloadInFlight(t *testing.T) {
	// Without this the server waits out warmTimeout on shutdown.
	database := &fakeDB{block: make(chan struct{}), entered: make(chan struct{})}
	s := New(discardLogger(), &fakeExtractor{pkgs: npmPackages()}, database)

	if _, err := s.Scan(t.Context(), "/proj"); !errors.Is(err, db.ErrNotReady) {
		t.Fatalf("Scan returned %v, want ErrNotReady", err)
	}
	<-database.entered

	done := make(chan struct{})
	go func() {
		_ = s.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return; the download was not interrupted")
	}
}

func TestCloseIsIdempotentAndSafeWithoutADownload(t *testing.T) {
	s := New(discardLogger(), &fakeExtractor{}, &fakeDB{})
	if err := s.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestDownloadCompletionInvalidatesAndAsksForARescan(t *testing.T) {
	database := &fakeDB{}
	rescans := make(chan struct{}, 1)
	s := New(discardLogger(), &fakeExtractor{pkgs: npmPackages()}, database,
		OnDatabaseReady(func() { rescans <- struct{}{} }))
	defer func() { _ = s.Close() }()

	if _, err := s.Scan(t.Context(), "/proj"); !errors.Is(err, db.ErrNotReady) {
		t.Fatalf("first Scan returned %v, want ErrNotReady", err)
	}

	select {
	case <-rescans:
	case <-time.After(5 * time.Second):
		t.Fatal("no rescan requested after the download finished")
	}

	// The database now reports ready, so the next scan gets as far as loading.
	if _, err := s.Scan(t.Context(), "/proj"); err != nil {
		t.Fatalf("second Scan: %v", err)
	}
	if _, loads := database.counts(); loads != 1 {
		t.Errorf("loads = %d, want 1 once the database became ready", loads)
	}
}

func TestAReadyDatabaseIsStillRevalidated(t *testing.T) {
	// Ready only reports that an archive exists. Before this, a server whose
	// archive was already on disk never reached Ensure again and so never
	// consulted its freshness window — an editor open for a week matched
	// against week-old advisories.
	database := &fakeDB{ready: true, entered: make(chan struct{})}
	s := New(discardLogger(), &fakeExtractor{pkgs: npmPackages()}, database)
	defer func() { _ = s.Close() }()

	if _, err := s.Scan(t.Context(), "/proj"); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	select {
	case <-database.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("a scan against a ready database never asked it to revalidate")
	}
}

func TestRevalidationIsRateLimited(t *testing.T) {
	// Revalidating on every keystroke-triggered rescan would put a metadata
	// read on the scan path for no benefit.
	database := &fakeDB{ready: true, entered: make(chan struct{})}
	s := New(discardLogger(), &fakeExtractor{pkgs: npmPackages()}, database)
	defer func() { _ = s.Close() }()

	for range 5 {
		if _, err := s.Scan(t.Context(), "/proj"); err != nil {
			t.Fatalf("Scan: %v", err)
		}
	}
	<-database.entered

	// Let any further attempt land before counting.
	time.Sleep(50 * time.Millisecond)
	if ensures, _ := database.counts(); ensures != 1 {
		t.Errorf("revalidated %d times across five scans, want once", ensures)
	}
}
