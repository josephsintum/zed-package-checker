// Package db owns the local copy of the OSV advisory database.
//
// It is responsible for the files on disk: downloading the archives for the
// ecosystems a project actually uses, keeping them current, and making sure a
// reader never sees a partially written or corrupted one. Parsing advisories
// out of them is not its job.
//
// The cache is shared between processes. Zed runs one language server per
// worktree, so several servers routinely point at the same directory, and every
// write here is built for that.
package db

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gofrs/flock"

	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// ErrNotReady means the advisory database for an ecosystem is not yet usable,
// typically because it is still downloading.
//
// Distinct from "nothing was found" on purpose: reporting a project as clean
// while the database is missing would be a silent false negative, which in a
// security tool is the worst possible failure.
var ErrNotReady = errors.New("advisory database not ready")

// defaultTTL is how long a downloaded archive is trusted before it is checked
// again. Advisories are published continuously but a day-old database is a
// reasonable trade against waking the network on every editor start.
const defaultTTL = 24 * time.Hour

// peerWait bounds how long we wait for another process that is already
// refreshing an ecosystem. Generous enough for npm's 205 MB on a slow link,
// short enough that a dead peer does not hang a scan forever.
const peerWait = 15 * time.Minute

// Progress observes a download so it can be shown to the user.
//
// npm's archive is 205 MB and the first scan of a JS project blocks on it, so
// without this the editor sits silent for minutes and the extension reads as
// broken. Implementations are called from the goroutine driving the download
// and must not block it.
//
// total is -1 when the server sent no Content-Length, in which case only the
// running byte count is meaningful.
type Progress interface {
	// Start is called once, before any bytes are read.
	Start(ctx context.Context, e model.Ecosystem, total int64)

	// Advance is called repeatedly, already rate-limited by the caller.
	Advance(ctx context.Context, e model.Ecosystem, downloaded, total int64)

	// Done is called exactly once per Start, with the outcome.
	Done(ctx context.Context, e model.Ecosystem, err error)
}

// DB manages the on-disk advisory archives.
type DB struct {
	root       string
	httpClient *http.Client
	log        *slog.Logger
	ttl        time.Duration
	progress   Progress

	// now is overridable so staleness can be tested without sleeping.
	now func() time.Time

	// validated records the modification time an archive had when it last
	// passed validation, so a healthy one is not re-read on every Ensure.
	validatedMu sync.Mutex
	validated   map[model.Ecosystem]time.Time
}

// Option configures a DB.
type Option func(*DB)

// WithRoot sets the cache directory. Defaults to DefaultRoot.
func WithRoot(path string) Option { return func(d *DB) { d.root = path } }

// WithHTTPClient replaces the client used for downloads.
func WithHTTPClient(c *http.Client) Option { return func(d *DB) { d.httpClient = c } }

// WithTTL sets how long a downloaded archive is trusted before being rechecked.
func WithTTL(ttl time.Duration) Option { return func(d *DB) { d.ttl = ttl } }

// WithProgress reports download advance. Nothing is reported without it.
func WithProgress(p Progress) Option { return func(d *DB) { d.progress = p } }

// withClock overrides the clock, for tests.
func withClock(now func() time.Time) Option { return func(d *DB) { d.now = now } }

// New builds a DB. The cache directory is created lazily on first use.
func New(log *slog.Logger, opts ...Option) (*DB, error) {
	d := &DB{
		httpClient: defaultHTTPClient(),
		log:        log,
		ttl:        defaultTTL,
		now:        time.Now,
		validated:  make(map[model.Ecosystem]time.Time),
	}
	for _, opt := range opts {
		opt(d)
	}
	if d.root == "" {
		root, err := DefaultRoot()
		if err != nil {
			return nil, fmt.Errorf("locate cache directory: %w", err)
		}
		d.root = root
	}
	return d, nil
}

// Root returns the cache directory.
func (d *DB) Root() string { return d.root }

// ArchivePath returns where an ecosystem's advisory archive lives, whether or
// not it has been downloaded.
func (d *DB) ArchivePath(e model.Ecosystem) string { return d.archivePath(e) }

// Ready reports whether every listed ecosystem has a usable archive on disk.
//
// Cheap by design: it is called on the scan path and must not touch the network
// or hash hundreds of megabytes.
func (d *DB) Ready(ecosystems []model.Ecosystem) bool {
	for _, e := range ecosystems {
		if !exists(d.archivePath(e)) {
			return false
		}
	}
	return true
}

// Ensure makes the archives for the given ecosystems available, downloading
// any that are missing or stale.
//
// It blocks and may take minutes on a cold start, so callers run it off the
// scan path. Only the ecosystems actually present in a project are passed, so
// a Go project never pays for npm's 205 MB.
func (d *DB) Ensure(ctx context.Context, ecosystems []model.Ecosystem) error {
	var errs []error
	for _, e := range ecosystems {
		if !e.Valid() {
			continue
		}
		if err := d.ensureOne(ctx, e); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", e, err))
		}
	}
	return errors.Join(errs...)
}

// ensureOne brings a single ecosystem up to date.
func (d *DB) ensureOne(ctx context.Context, e model.Ecosystem) error {
	if err := os.MkdirAll(d.dirFor(e), 0o755); err != nil {
		return fmt.Errorf("create %s: %w", d.dirFor(e), err)
	}

	// Repair before deciding freshness: a corrupt archive is stale regardless
	// of what its metadata claims.
	d.heal(e)

	if !d.stale(e) {
		return nil
	}

	lock := flock.New(d.lockPath(e))
	locked, err := lock.TryLockContext(ctx, 50*time.Millisecond)
	if err != nil {
		return fmt.Errorf("lock %s: %w", d.lockPath(e), err)
	}
	if !locked {
		// Another process is already downloading this ecosystem. Downloading it
		// a second time would waste the bandwidth and race on the same path, so
		// wait for that one instead.
		return d.awaitPeer(ctx, e, lock)
	}
	defer func() { _ = lock.Unlock() }()

	// Re-check under the lock: a peer may have finished between our staleness
	// check and acquiring it.
	if !d.stale(e) {
		return nil
	}

	_, err = d.fetch(ctx, e)
	return err
}

// awaitPeer blocks until the process holding the lock finishes, then reports
// whether the archive it produced is usable.
//
// Without this, a process that skipped the download would sit at ErrNotReady
// until something else triggered a rescan, which for a quiet project might be
// never.
func (d *DB) awaitPeer(ctx context.Context, e model.Ecosystem, lock *flock.Flock) error {
	d.log.Info("waiting for another process to refresh the database",
		"ecosystem", e.String())

	// Bounded: a peer that died holding the lock, or one stuck on a slow
	// connection, must not block us indefinitely.
	ctx, cancel := context.WithTimeout(ctx, peerWait)
	defer cancel()

	locked, err := lock.TryLockContext(ctx, 250*time.Millisecond)
	if err != nil {
		return fmt.Errorf("wait for peer refresh of %s: %w", e, err)
	}
	if !locked {
		return fmt.Errorf("%w: timed out waiting for another process to refresh %s", ErrNotReady, e)
	}
	defer func() { _ = lock.Unlock() }()

	if !exists(d.archivePath(e)) {
		return fmt.Errorf("%w: peer refresh of %s produced nothing", ErrNotReady, e)
	}
	return nil
}

// validatedAt returns the modification time an archive had when it last passed
// validation, or the zero time if it never has.
func (d *DB) validatedAt(e model.Ecosystem) time.Time {
	d.validatedMu.Lock()
	defer d.validatedMu.Unlock()
	return d.validated[e]
}

func (d *DB) markValidated(e model.Ecosystem, modTime time.Time) {
	d.validatedMu.Lock()
	defer d.validatedMu.Unlock()
	d.validated[e] = modTime
}

// stale reports whether an ecosystem needs fetching.
func (d *DB) stale(e model.Ecosystem) bool {
	if !exists(d.archivePath(e)) {
		return true
	}
	m, ok := d.readMeta(d.metaPath(e))
	if !ok {
		// Archive present but unaccounted for: re-check rather than trust it.
		return true
	}
	return d.now().Sub(m.FetchedAt) >= d.ttl
}

// heal removes an archive that cannot be read.
//
// A crash midway through an unprotected write — osv-scanner's own cache code
// does exactly that — leaves a truncated zip that would otherwise persist
// indefinitely, because offline matching never re-validates it.
func (d *DB) heal(e model.Ecosystem) {
	archive := d.archivePath(e)
	info, err := os.Stat(archive)
	if err != nil || !info.Mode().IsRegular() {
		return
	}

	// Validation reads the central directory of a file that is 205 MB for npm,
	// and Ensure is now reached hourly rather than once. An archive is only
	// ever replaced by an atomic rename, so an unchanged modification time
	// means unchanged bytes, and bytes that were readable an hour ago still
	// are.
	if d.validatedAt(e).Equal(info.ModTime()) {
		return
	}

	if err := validateZip(archive); err == nil {
		d.markValidated(e, info.ModTime())
		return
	}

	d.log.Warn("discarding unreadable advisory archive",
		"ecosystem", e.String(), "path", archive)
	if err := os.Remove(archive); err != nil && !isNotExist(err) {
		d.log.Warn("could not remove archive", "path", archive, "error", err)
	}
	if err := os.Remove(d.metaPath(e)); err != nil && !isNotExist(err) {
		d.log.Warn("could not remove metadata", "path", d.metaPath(e), "error", err)
	}
}
