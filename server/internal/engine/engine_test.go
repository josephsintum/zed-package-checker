package engine

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

func TestMain(m *testing.M) {
	// Every goroutine this package starts must be owned by an Engine and end
	// when it closes. A leak here is a server that never shuts down cleanly.
	goleak.VerifyTestMain(m)
}

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// fakeTimer lets a test fire the debounce rather than waiting for it.
type fakeTimer struct {
	mu      sync.Mutex
	c       chan time.Time
	armed   bool
	resets  atomic.Int64
	stopped atomic.Int64
}

func newFakeTimer() *fakeTimer {
	return &fakeTimer{c: make(chan time.Time, 1)}
}

func (f *fakeTimer) C() <-chan time.Time { return f.c }

func (f *fakeTimer) Reset(time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.armed = true
	f.resets.Add(1)
	// Discard a pending expiry, as a real reset does.
	select {
	case <-f.c:
	default:
	}
}

func (f *fakeTimer) Stop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.armed = false
	f.stopped.Add(1)
	select {
	case <-f.c:
	default:
	}
}

// fire expires the timer if it is armed, as real time passing would.
func (f *fakeTimer) fire(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	armed := f.armed
	f.armed = false
	f.mu.Unlock()
	if !armed {
		t.Fatal("timer fired while not armed; the debounce was never reset")
	}
	f.c <- time.Now()
}

// fakeScanner returns canned reports and counts calls.
type fakeScanner struct {
	mu      sync.Mutex
	reports []model.Report
	err     error
	calls   atomic.Int64

	// block, when non-nil, holds each scan until it is closed, so a scan can be
	// observed mid-flight.
	block chan struct{}

	// started is signalled once per scan that has begun.
	started chan struct{}
}

func (f *fakeScanner) Scan(ctx context.Context, root string) (model.Report, error) {
	n := f.calls.Add(1)
	if f.started != nil {
		select {
		case f.started <- struct{}{}:
		default:
		}
	}
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return model.Report{}, ctx.Err()
		}
	}
	if err := ctx.Err(); err != nil {
		return model.Report{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return model.Report{}, f.err
	}
	idx := int(n) - 1
	if idx >= len(f.reports) {
		if len(f.reports) == 0 {
			return model.Report{Root: root}, nil
		}
		idx = len(f.reports) - 1
	}
	return f.reports[idx], nil
}

// fakePublisher records every publish, including empty ones.
type fakePublisher struct {
	mu   sync.Mutex
	sent []publishCall
	err  error
}

type publishCall struct {
	path     string
	findings int
}

func (f *fakePublisher) Publish(_ context.Context, path string, findings []model.Finding) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, publishCall{path: path, findings: len(findings)})
	return f.err
}

func (f *fakePublisher) calls() []publishCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]publishCall(nil), f.sent...)
}

// waitFor polls until cond holds, failing rather than hanging.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// finding builds one anchored at path.
func finding(name, path string, line int) model.Finding {
	return model.Finding{
		Package: model.Package{
			PackageKey: model.PackageKey{Ecosystem: model.EcosystemNPM, Name: name},
			Version:    "1.0.0",
		},
		Advisories: []model.Advisory{{ID: "GHSA-" + name}},
		Evidence:   model.Site{Path: path, Range: model.WholeLine(line)},
	}
}

// newTestEngine wires an engine to fakes and cleans it up.
func newTestEngine(t *testing.T, s Scanner, p Publisher) (*Engine, *fakeTimer) {
	t.Helper()
	ft := newFakeTimer()
	e := New(discardLogger(), s, p, withTimer(func(time.Duration) timer { return ft }))
	t.Cleanup(func() { _ = e.Close() })
	e.Start(context.Background(), "/proj")
	return e, ft
}

func TestRapidRequestsCoalesceToOneScan(t *testing.T) {
	// A git checkout can touch dozens of manifests. All of them together must
	// produce one scan, not dozens.
	scanner := &fakeScanner{}
	pub := &fakePublisher{}
	e, ft := newTestEngine(t, scanner, pub)

	for range 40 {
		e.Request(ReasonFileChanged)
	}
	waitFor(t, "requests to be absorbed", func() bool { return ft.resets.Load() > 0 })

	ft.fire(t)
	waitFor(t, "the scan to run", func() bool { return scanner.calls.Load() == 1 })

	// Give any extra scan a chance to appear before asserting there is none.
	time.Sleep(20 * time.Millisecond)
	if got := scanner.calls.Load(); got != 1 {
		t.Errorf("ran %d scans, want exactly 1", got)
	}
}

func TestRequestsWhileScanningSupersedeIt(t *testing.T) {
	// A scan describes the project as it was when it started. If the project
	// changes underneath, publishing those results would show a state that no
	// longer exists.
	scanner := &fakeScanner{
		block:   make(chan struct{}),
		started: make(chan struct{}, 4),
		reports: []model.Report{
			{Findings: []model.Finding{finding("stale", "/proj/package.json", 1)}},
			{Findings: []model.Finding{finding("fresh", "/proj/package.json", 1)}},
		},
	}
	pub := &fakePublisher{}
	e, ft := newTestEngine(t, scanner, pub)

	e.Request(ReasonStartup)
	waitFor(t, "the debounce to arm", func() bool { return ft.resets.Load() == 1 })
	ft.fire(t)
	<-scanner.started

	// Supersede the in-flight scan, then let it finish.
	e.Request(ReasonFileChanged)
	waitFor(t, "the second request", func() bool { return ft.resets.Load() == 2 })
	close(scanner.block)

	ft.fire(t)
	waitFor(t, "the second scan to publish", func() bool { return len(pub.calls()) > 0 })
	time.Sleep(20 * time.Millisecond)

	// The superseded scan's results must never have been published.
	findings := e.Findings("/proj/package.json")
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if got := findings[0].Package.Name; got != "fresh" {
		t.Errorf("published findings from the superseded scan: %q", got)
	}
}

func TestFilesThatBecomeCleanArePublishedEmpty(t *testing.T) {
	// Without this the editor keeps showing a vulnerability the user just fixed.
	scanner := &fakeScanner{reports: []model.Report{
		{Findings: []model.Finding{
			finding("a", "/proj/package.json", 1),
			finding("b", "/proj/go.mod", 2),
		}},
		{Findings: []model.Finding{
			finding("b", "/proj/go.mod", 2),
		}},
	}}
	pub := &fakePublisher{}
	e, ft := newTestEngine(t, scanner, pub)

	e.Request(ReasonStartup)
	waitFor(t, "first debounce", func() bool { return ft.resets.Load() == 1 })
	ft.fire(t)
	waitFor(t, "first scan", func() bool { return len(pub.calls()) == 2 })

	e.Request(ReasonFileChanged)
	waitFor(t, "second debounce", func() bool { return ft.resets.Load() == 2 })
	ft.fire(t)
	waitFor(t, "second scan", func() bool { return len(pub.calls()) > 2 })
	time.Sleep(20 * time.Millisecond)

	var cleared bool
	for _, c := range pub.calls()[2:] {
		if c.path == "/proj/package.json" && c.findings == 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Errorf("package.json was never cleared: %+v", pub.calls())
	}
}

func TestClearPublishesEmptyImmediately(t *testing.T) {
	// A deleted manifest should not wait for a debounce to stop showing
	// diagnostics.
	pub := &fakePublisher{}
	e, _ := newTestEngine(t, &fakeScanner{}, pub)

	e.Clear("/proj/package.json")
	waitFor(t, "the clear to publish", func() bool { return len(pub.calls()) == 1 })

	got := pub.calls()[0]
	if got.path != "/proj/package.json" || got.findings != 0 {
		t.Errorf("published %+v, want an empty set for package.json", got)
	}
}

func TestFindingsServesCachedResults(t *testing.T) {
	// Re-publishing on didOpen relies on this, and it must not trigger a scan.
	scanner := &fakeScanner{reports: []model.Report{{Findings: []model.Finding{
		finding("a", "/proj/package.json", 1),
		finding("b", "/proj/go.mod", 2),
	}}}}
	e, ft := newTestEngine(t, scanner, &fakePublisher{})

	e.Request(ReasonStartup)
	waitFor(t, "debounce", func() bool { return ft.resets.Load() == 1 })
	ft.fire(t)
	waitFor(t, "scan", func() bool { return scanner.calls.Load() == 1 })

	waitFor(t, "findings to be available", func() bool {
		return len(e.Findings("/proj/package.json")) == 1
	})
	if got := len(e.Findings("/proj/go.mod")); got != 1 {
		t.Errorf("go.mod has %d findings, want 1", got)
	}
	if got := e.Findings("/proj/unrelated.json"); got != nil {
		t.Errorf("unrelated file returned %v, want nil", got)
	}
	if got := scanner.calls.Load(); got != 1 {
		t.Errorf("reading findings triggered %d scans, want 1 total", got)
	}
}

func TestFailedScanKeepsPreviousDiagnostics(t *testing.T) {
	// Clearing on failure would tell the user the project became clean, which
	// is not what a failed scan means.
	scanner := &fakeScanner{reports: []model.Report{
		{Findings: []model.Finding{finding("a", "/proj/package.json", 1)}},
	}}
	pub := &fakePublisher{}
	e, ft := newTestEngine(t, scanner, pub)

	e.Request(ReasonStartup)
	waitFor(t, "debounce", func() bool { return ft.resets.Load() == 1 })
	ft.fire(t)
	waitFor(t, "first scan", func() bool { return len(pub.calls()) == 1 })

	scanner.mu.Lock()
	scanner.err = errors.New("database unavailable")
	scanner.mu.Unlock()

	e.Request(ReasonFileChanged)
	waitFor(t, "second debounce", func() bool { return ft.resets.Load() == 2 })
	ft.fire(t)
	waitFor(t, "the failing scan", func() bool { return scanner.calls.Load() == 2 })
	time.Sleep(20 * time.Millisecond)

	if got := len(pub.calls()); got != 1 {
		t.Errorf("a failed scan published %d times, want 0 beyond the first", got-1)
	}
	if got := len(e.Findings("/proj/package.json")); got != 1 {
		t.Errorf("findings were dropped on failure: got %d, want 1", got)
	}
}

func TestPublishFailureDoesNotStopTheEngine(t *testing.T) {
	scanner := &fakeScanner{reports: []model.Report{
		{Findings: []model.Finding{finding("a", "/proj/package.json", 1)}},
	}}
	pub := &fakePublisher{err: errors.New("connection closed")}
	e, ft := newTestEngine(t, scanner, pub)

	e.Request(ReasonStartup)
	waitFor(t, "debounce", func() bool { return ft.resets.Load() == 1 })
	ft.fire(t)
	waitFor(t, "the publish attempt", func() bool { return len(pub.calls()) == 1 })

	// The engine must still be serving.
	e.Request(ReasonFileChanged)
	waitFor(t, "a second debounce", func() bool { return ft.resets.Load() == 2 })
}

func TestRequestNeverBlocks(t *testing.T) {
	// The LSP handler calls this from the protocol goroutine; blocking there
	// would stall the editor.
	e, _ := newTestEngine(t, &fakeScanner{}, &fakePublisher{})

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 10_000 {
			e.Request(ReasonFileChanged)
			e.Clear("/proj/x.json")
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Request or Clear blocked")
	}
}

func TestCloseIsIdempotentAndSafeWithoutStart(t *testing.T) {
	e := New(discardLogger(), &fakeScanner{}, &fakePublisher{})
	if err := e.Close(); err != nil {
		t.Fatalf("Close without Start: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestCloseStopsAnInFlightScan(t *testing.T) {
	scanner := &fakeScanner{
		block:   make(chan struct{}),
		started: make(chan struct{}, 1),
	}
	ft := newFakeTimer()
	e := New(discardLogger(), scanner, &fakePublisher{},
		withTimer(func(time.Duration) timer { return ft }))
	e.Start(context.Background(), "/proj")

	e.Request(ReasonStartup)
	waitFor(t, "debounce", func() bool { return ft.resets.Load() == 1 })
	ft.fire(t)
	<-scanner.started

	// Close must return even though a scan is blocked, because cancelling its
	// context unblocks it.
	closed := make(chan error, 1)
	go func() { closed <- e.Close() }()

	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(2 * time.Second):
		close(scanner.block)
		t.Fatal("Close hung with a scan in flight")
	}
	close(scanner.block)
}

func TestFindingsAfterCloseReturnsNil(t *testing.T) {
	e := New(discardLogger(), &fakeScanner{}, &fakePublisher{})
	e.Start(context.Background(), "/proj")
	if err := e.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := e.Findings("/proj/package.json"); got != nil {
		t.Errorf("Findings after Close = %v, want nil", got)
	}
}

func TestContextCancellationStopsTheEngine(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	e := New(discardLogger(), &fakeScanner{}, &fakePublisher{},
		withTimer(func(time.Duration) timer { return newFakeTimer() }))
	e.Start(ctx, "/proj")

	cancel()
	// Close still has to be called to join the goroutine, and must not hang.
	done := make(chan struct{})
	go func() { defer close(done); _ = e.Close() }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close hung after context cancellation")
	}
}
