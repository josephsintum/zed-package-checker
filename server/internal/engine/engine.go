package engine

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// DefaultDebounce is how long the engine waits for changes to settle before
// scanning.
//
// A single `npm install` writes the manifest and the lockfile within
// milliseconds of each other, and a `git checkout` can touch dozens of files.
// One second matches what JetBrains uses for the same job.
const DefaultDebounce = time.Second

// Engine schedules scans and tracks what has been published.
//
// Every field below the channels is owned by run() and touched from nowhere
// else. Callers interact only through the methods, which communicate over
// channels, so there is no shared mutable state and therefore no locking.
type Engine struct {
	scanner   Scanner
	publisher Publisher
	log       *slog.Logger
	debounce  time.Duration
	newTimer  func(time.Duration) timer

	requests chan Reason
	queries  chan query
	clears   chan string
	done     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup

	// Owned by run().
	root      string
	report    model.Report
	published map[string]bool
	scanGen   uint64
}

// Option configures an Engine.
type Option func(*Engine)

// WithDebounce sets how long changes must settle before a scan runs.
func WithDebounce(d time.Duration) Option { return func(e *Engine) { e.debounce = d } }

// withTimer replaces the debounce timer, for tests.
func withTimer(f func(time.Duration) timer) Option {
	return func(e *Engine) { e.newTimer = f }
}

// New builds an Engine. Start must be called before it does anything.
func New(log *slog.Logger, scanner Scanner, publisher Publisher, opts ...Option) *Engine {
	e := &Engine{
		scanner:   scanner,
		publisher: publisher,
		log:       log,
		debounce:  DefaultDebounce,
		newTimer:  newRealTimer,
		// Capacity one, with non-blocking sends: a pending request already
		// means "rescan", so extra ones are dropped rather than queued and the
		// channel can never back up.
		requests:  make(chan Reason, 1),
		queries:   make(chan query),
		clears:    make(chan string, 16),
		done:      make(chan struct{}),
		published: make(map[string]bool),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Start begins scheduling. It returns immediately; scanning happens in the
// background until ctx is cancelled or Close is called.
func (e *Engine) Start(ctx context.Context, root string) {
	e.root = root
	e.wg.Go(func() { e.run(ctx) })
}

// Close stops the engine and waits for every goroutine it started.
//
// Safe to call more than once, and safe to call without Start.
func (e *Engine) Close() error {
	e.stopOnce.Do(func() { close(e.done) })
	e.wg.Wait()
	return nil
}

// Request asks for a scan. Never blocks.
//
// The request is dropped when one is already pending, which is not a loss:
// a scan that has not started yet will see whatever the filesystem holds when
// it does.
func (e *Engine) Request(reason Reason) {
	select {
	case e.requests <- reason:
	default:
	}
}

// Clear publishes an empty diagnostic set for a path, used when a manifest is
// deleted or renamed. Never blocks.
func (e *Engine) Clear(path string) {
	select {
	case e.clears <- path:
	default:
	}
}

// Findings returns the current findings for a path, or nil.
//
// Used to re-publish when a file is opened, which is how diagnostics survive
// the editor discarding them for a closed buffer. Returns nil if the engine has
// stopped.
func (e *Engine) Findings(path string) []model.Finding {
	reply := make(chan []model.Finding, 1)
	select {
	case e.queries <- query{path: path, reply: reply}:
		return <-reply
	case <-e.done:
		return nil
	}
}

// query is a synchronous read served by run().
type query struct {
	path  string
	reply chan []model.Finding
}

// scanResult carries a completed scan back to the loop.
//
// gen identifies which request produced it, so results from a scan that has
// been superseded can be recognised and discarded. Cancellation is best-effort:
// a scan may finish despite its context being cancelled, and publishing those
// results would show findings for a state of the project that no longer exists.
type scanResult struct {
	gen    uint64
	report model.Report
	err    error
}

// run is the only goroutine that touches engine state.
func (e *Engine) run(ctx context.Context) {
	t := e.newTimer(e.debounce)
	defer t.Stop()

	results := make(chan scanResult, 1)
	var cancelInFlight context.CancelFunc
	cancelPending := func() {
		if cancelInFlight != nil {
			cancelInFlight()
			cancelInFlight = nil
		}
	}
	defer cancelPending()

	for {
		select {
		case reason := <-e.requests:
			// Supersede any scan already running: its results describe a state
			// of the project that has just changed.
			cancelPending()
			e.log.Debug("scan requested", "reason", string(reason))
			t.Reset(e.debounce)

		case <-t.C():
			e.scanGen++
			scanCtx, cancel := context.WithCancel(ctx)
			cancelInFlight = cancel
			gen := e.scanGen

			e.wg.Go(func() {
				report, err := e.scanner.Scan(scanCtx, e.root)
				select {
				case results <- scanResult{gen: gen, report: report, err: err}:
				case <-e.done:
				case <-ctx.Done():
				}
			})

		case res := <-results:
			if res.gen != e.scanGen {
				// Superseded by a newer request while it was running.
				continue
			}
			cancelInFlight = nil
			e.handleResult(ctx, res)

		case path := <-e.clears:
			e.publishOne(ctx, path, nil)
			delete(e.published, path)

		case q := <-e.queries:
			q.reply <- e.findingsFor(q.path)

		case <-ctx.Done():
			return
		case <-e.done:
			return
		}
	}
}

// handleResult records a completed scan and publishes the difference.
func (e *Engine) handleResult(ctx context.Context, res scanResult) {
	if res.err != nil {
		if errors.Is(res.err, context.Canceled) {
			return
		}
		// A failed scan leaves the previous diagnostics in place. Clearing them
		// would suggest the project became clean, which is not what happened.
		e.log.Warn("scan failed", "error", res.err)
		return
	}

	e.report = res.report
	byFile := res.report.ByFile()

	// Named before anything is published, because e.published means "last
	// scan's files" here and "this scan's files" a few lines below.
	previous := e.published

	for path, findings := range byFile {
		e.publishOne(ctx, path, findings)
	}

	// Files that had findings last time and have none now must be published
	// empty, or the editor keeps showing what was fixed.
	for path := range previous {
		if _, still := byFile[path]; !still {
			e.publishOne(ctx, path, nil)
		}
	}

	e.published = make(map[string]bool, len(byFile))
	for path := range byFile {
		e.published[path] = true
	}

	e.log.Info("scan complete",
		"findings", len(res.report.Findings), "files", len(byFile))
}

// publishOne sends one file's diagnostics, logging rather than failing: a
// publish that does not land is not a reason to stop scanning.
func (e *Engine) publishOne(ctx context.Context, path string, findings []model.Finding) {
	if err := e.publisher.Publish(ctx, path, findings); err != nil {
		e.log.Warn("publish failed", "path", path, "error", err)
	}
}

// findingsFor returns the findings anchored at path in the current report.
func (e *Engine) findingsFor(path string) []model.Finding {
	var out []model.Finding
	for _, f := range e.report.Findings {
		if f.AnchorSite().Path == path {
			out = append(out, f)
		}
	}
	return out
}
