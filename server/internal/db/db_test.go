package db

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"hash/crc32"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeArchive builds a minimal but genuine zip, so validation exercises real
// archive parsing rather than a stub.
func fakeArchive(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, body := range entries {
		f, err := w.Create(name)
		if err != nil {
			t.Fatalf("create zip entry %s: %v", name, err)
		}
		if _, err := f.Write([]byte(body)); err != nil {
			t.Fatalf("write zip entry %s: %v", name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

// archiveServer serves a body the way Cloud Storage does, including the
// checksum header and conditional-request handling.
type archiveServer struct {
	*httptest.Server
	body     []byte
	etag     string
	requests atomic.Int64
	notMod   atomic.Int64
	delay    time.Duration
}

func newArchiveServer(t *testing.T, body []byte) *archiveServer {
	t.Helper()
	s := &archiveServer{body: body, etag: `"v1"`}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
		if s.delay > 0 {
			time.Sleep(s.delay)
		}
		if r.Header.Get("If-None-Match") == s.etag {
			s.notMod.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		sum := crc32.Checksum(s.body, castagnoli)
		raw := make([]byte, 4)
		binary.BigEndian.PutUint32(raw, sum)
		w.Header().Set("x-goog-hash", "crc32c="+base64.StdEncoding.EncodeToString(raw))
		w.Header().Set("ETag", s.etag)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(s.body)
	}))
	t.Cleanup(s.Close)
	return s
}

// newTestDB points a DB at a temp cache and a local server, by rewriting the
// request host in transit so production code keeps its real URLs.
func newTestDB(t *testing.T, srv *archiveServer, opts ...Option) *DB {
	t.Helper()
	client := &http.Client{Transport: redirectTo(srv.URL)}
	base := []Option{WithRoot(t.TempDir()), WithHTTPClient(client)}
	d, err := New(discardLogger(), append(base, opts...)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d
}

// redirectTo sends every request to a test server, preserving the path.
type redirectTo string

func (target redirectTo) RoundTrip(r *http.Request) (*http.Response, error) {
	u := *r.URL
	base := string(target)
	u.Scheme = "http"
	u.Host = base[len("http://"):]
	clone := r.Clone(r.Context())
	clone.URL = &u
	return http.DefaultTransport.RoundTrip(clone)
}

// recordingProgress captures the Progress calls fetch makes.
type recordingProgress struct {
	mu         sync.Mutex
	starts     int
	advances   int
	dones      int
	total      int64
	downloaded int64
	err        error
}

func (r *recordingProgress) Start(_ context.Context, _ model.Ecosystem, total int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.starts++
	r.total = total
}

func (r *recordingProgress) Advance(_ context.Context, _ model.Ecosystem, downloaded, _ int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.advances++
	r.downloaded = downloaded
}

func (r *recordingProgress) Done(_ context.Context, _ model.Ecosystem, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dones++
	r.err = err
}

func TestDownloadReportsProgress(t *testing.T) {
	// The link between the download and the editor: without this the 205 MB
	// first run looks like a hang.
	srv := newArchiveServer(t, fakeArchive(t, map[string]string{"GHSA-1.json": "{}"}))
	rec := &recordingProgress{}
	d := newTestDB(t, srv, WithProgress(rec))

	if err := d.Ensure(context.Background(), []model.Ecosystem{model.EcosystemNPM}); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.starts != 1 || rec.dones != 1 {
		t.Errorf("starts=%d dones=%d, want 1 of each", rec.starts, rec.dones)
	}
	if rec.err != nil {
		t.Errorf("Done reported %v, want success", rec.err)
	}
	if rec.advances == 0 {
		t.Error("no progress reported between start and done")
	}
	if rec.downloaded <= 0 {
		t.Errorf("final downloaded = %d, want the archive size", rec.downloaded)
	}
	if rec.total > 0 && rec.downloaded != rec.total {
		t.Errorf("downloaded %d of a stated %d; the counts must agree at the end",
			rec.downloaded, rec.total)
	}
}

func TestACachedArchiveReportsNoProgress(t *testing.T) {
	// A 304 moves no bytes, so opening a progress entry for it would flash an
	// empty download at the user on every startup.
	srv := newArchiveServer(t, fakeArchive(t, map[string]string{"GHSA-1.json": "{}"}))
	rec := &recordingProgress{}
	d := newTestDB(t, srv, WithProgress(rec), WithTTL(0))

	ctx := context.Background()
	if err := d.Ensure(ctx, []model.Ecosystem{model.EcosystemNPM}); err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	rec.mu.Lock()
	afterFirst := rec.starts
	rec.mu.Unlock()

	if err := d.Ensure(ctx, []model.Ecosystem{model.EcosystemNPM}); err != nil {
		t.Fatalf("second Ensure: %v", err)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.starts != afterFirst {
		t.Errorf("starts went %d -> %d across a revalidation that moved no bytes",
			afterFirst, rec.starts)
	}
}

func TestEnsureDownloadsThenReusesCache(t *testing.T) {
	srv := newArchiveServer(t, fakeArchive(t, map[string]string{"GHSA-1.json": "{}"}))
	d := newTestDB(t, srv)
	ctx := context.Background()
	npm := []model.Ecosystem{model.EcosystemNPM}

	if d.Ready(npm) {
		t.Fatal("Ready before any download")
	}
	if err := d.Ensure(ctx, npm); err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	if !d.Ready(npm) {
		t.Fatal("not Ready after a successful download")
	}
	if got := srv.requests.Load(); got != 1 {
		t.Errorf("made %d requests, want 1", got)
	}

	// Within the TTL nothing should touch the network at all.
	if err := d.Ensure(ctx, npm); err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	if got := srv.requests.Load(); got != 1 {
		t.Errorf("made %d requests after a warm start, want 1", got)
	}
}

func TestEnsureRevalidatesWhenStale(t *testing.T) {
	srv := newArchiveServer(t, fakeArchive(t, map[string]string{"GHSA-1.json": "{}"}))

	now := time.Now()
	d := newTestDB(t, srv, WithTTL(time.Hour), withClock(func() time.Time { return now }))
	ctx := context.Background()
	npm := []model.Ecosystem{model.EcosystemNPM}

	if err := d.Ensure(ctx, npm); err != nil {
		t.Fatalf("first Ensure: %v", err)
	}

	// Past the TTL the server is asked, but an unchanged ETag means a 304 and
	// no re-download.
	now = now.Add(2 * time.Hour)
	if err := d.Ensure(ctx, npm); err != nil {
		t.Fatalf("stale Ensure: %v", err)
	}
	if got := srv.requests.Load(); got != 2 {
		t.Errorf("made %d requests, want 2", got)
	}
	if got := srv.notMod.Load(); got != 1 {
		t.Errorf("got %d not-modified responses, want 1", got)
	}

	// And the freshness check must be recorded, or every scan would re-ask.
	now = now.Add(30 * time.Minute)
	if err := d.Ensure(ctx, npm); err != nil {
		t.Fatalf("post-304 Ensure: %v", err)
	}
	if got := srv.requests.Load(); got != 2 {
		t.Errorf("made %d requests after a 304 refreshed the timestamp, want 2", got)
	}
}

func TestEnsureFetchesOnlyRequestedEcosystems(t *testing.T) {
	// A Go project must never pay for npm's 205 MB.
	srv := newArchiveServer(t, fakeArchive(t, map[string]string{"GO-1.json": "{}"}))
	d := newTestDB(t, srv)

	if err := d.Ensure(context.Background(), []model.Ecosystem{model.EcosystemGo}); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	if !exists(d.archivePath(model.EcosystemGo)) {
		t.Error("Go archive missing")
	}
	for _, e := range []model.Ecosystem{model.EcosystemNPM, model.EcosystemPyPI} {
		if exists(d.archivePath(e)) {
			t.Errorf("%s was downloaded but not requested", e)
		}
	}
}

func TestEnsureRejectsCorruptDownload(t *testing.T) {
	// A body that is not a zip must never be published, however cleanly it
	// transferred: an error page served with a 200 looks like success.
	srv := newArchiveServer(t, []byte("<html>502 Bad Gateway</html>"))
	d := newTestDB(t, srv)

	err := d.Ensure(context.Background(), []model.Ecosystem{model.EcosystemNPM})
	if err == nil {
		t.Fatal("expected an error for a non-zip body")
	}
	if exists(d.archivePath(model.EcosystemNPM)) {
		t.Error("a corrupt archive was published")
	}
	// The temporary file must be cleaned up too.
	entries, _ := os.ReadDir(d.dirFor(model.EcosystemNPM))
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".lock" && entry.Name() != archiveName+".meta" {
			t.Errorf("left behind %s", entry.Name())
		}
	}
}

func TestEnsureRejectsChecksumMismatch(t *testing.T) {
	body := fakeArchive(t, map[string]string{"GHSA-1.json": "{}"})
	srv := newArchiveServer(t, body)
	// Advertise a checksum that will not match what is sent.
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-goog-hash", "crc32c=AAAAAA==")
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write(body)
	})

	d := newTestDB(t, srv)
	if err := d.Ensure(context.Background(), []model.Ecosystem{model.EcosystemNPM}); err == nil {
		t.Fatal("expected an error for a checksum mismatch")
	}
	if exists(d.archivePath(model.EcosystemNPM)) {
		t.Error("an archive with a bad checksum was published")
	}
}

func TestHealRecoversFromTruncatedArchive(t *testing.T) {
	// The failure osv-scanner's own cache can leave behind: a half-written zip
	// that offline matching never revalidates.
	srv := newArchiveServer(t, fakeArchive(t, map[string]string{"GHSA-1.json": "{}"}))
	d := newTestDB(t, srv)
	ctx := context.Background()
	npm := []model.Ecosystem{model.EcosystemNPM}

	if err := d.Ensure(ctx, npm); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	archive := d.archivePath(model.EcosystemNPM)
	original, err := os.ReadFile(archive)
	if err != nil {
		t.Fatalf("read archive: %v", err)
	}
	if err := os.WriteFile(archive, original[:len(original)/2], 0o644); err != nil {
		t.Fatalf("truncate archive: %v", err)
	}

	if d.Ready(npm) && validateZip(archive) == nil {
		t.Fatal("truncated archive still validates; the test is not exercising anything")
	}

	if err := d.Ensure(ctx, npm); err != nil {
		t.Fatalf("Ensure after corruption: %v", err)
	}
	if err := validateZip(archive); err != nil {
		t.Errorf("archive still unreadable after recovery: %v", err)
	}
	if got := srv.requests.Load(); got != 2 {
		t.Errorf("made %d requests, want 2 (the corrupt copy must be re-fetched)", got)
	}
}

func TestConcurrentEnsureDownloadsOnce(t *testing.T) {
	// Zed runs one server per worktree, so several processes routinely race on
	// this cache. Exactly one should download; the rest wait and then succeed.
	srv := newArchiveServer(t, fakeArchive(t, map[string]string{"GHSA-1.json": "{}"}))
	srv.delay = 100 * time.Millisecond

	root := t.TempDir()
	npm := []model.Ecosystem{model.EcosystemNPM}

	var wg sync.WaitGroup
	errs := make([]error, 5)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := newTestDB(t, srv, WithRoot(root))
			errs[i] = d.Ensure(context.Background(), npm)
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("worker %d: %v", i, err)
		}
	}
	if got := srv.requests.Load(); got != 1 {
		t.Errorf("made %d requests, want exactly 1", got)
	}

	d := newTestDB(t, srv, WithRoot(root))
	if !d.Ready(npm) {
		t.Error("not Ready after concurrent refresh")
	}
}

func TestReadsNeverSeeAPartialArchive(t *testing.T) {
	// Publishing is a rename, so a concurrent reader sees either the old
	// complete archive or the new one, never a half-written file.
	srv := newArchiveServer(t, fakeArchive(t, map[string]string{"GHSA-1.json": "{}"}))
	root := t.TempDir()
	npm := []model.Ecosystem{model.EcosystemNPM}

	writer := newTestDB(t, srv, WithRoot(root), WithTTL(0))
	if err := writer.Ensure(context.Background(), npm); err != nil {
		t.Fatalf("seed: %v", err)
	}
	archive := writer.archivePath(model.EcosystemNPM)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ctx.Err() == nil {
			// TTL of zero makes every call re-publish the archive.
			_ = writer.Ensure(ctx, npm)
		}
	}()

	reads, failures := 0, 0
	for ctx.Err() == nil {
		if err := validateZip(archive); err != nil {
			failures++
		}
		reads++
	}
	wg.Wait()

	if failures > 0 {
		t.Errorf("%d of %d reads saw an invalid archive", failures, reads)
	}
	if reads < 10 {
		t.Errorf("only %d reads; the test barely exercised anything", reads)
	}
}

func TestCRC32CFromHeader(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   uint32
		wantOK bool
	}{
		{"absent", nil, 0, false},
		{"md5 only", []string{"md5=6bBQJ2rnE5o/rJZDYqgAew=="}, 0, false},
		{"crc32c alone", []string{"crc32c=W3hLNw=="}, 0x5b784b37, true},
		{"repeated headers", []string{"md5=6bBQJ2rnE5o/rJZDYqgAew==", "crc32c=W3hLNw=="}, 0x5b784b37, true},
		{"comma separated", []string{"md5=6bBQJ2rnE5o/rJZDYqgAew==, crc32c=W3hLNw=="}, 0x5b784b37, true},
		{"malformed base64", []string{"crc32c=!!!"}, 0, false},
		{"wrong length", []string{"crc32c=AAA="}, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			for _, v := range tt.values {
				h.Add("x-goog-hash", v)
			}
			got, ok := crc32cFromHeader(h)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && got != tt.want {
				t.Errorf("sum = %08x, want %08x", got, tt.want)
			}
		})
	}
}

func TestArchiveURLUsesEcosystemNameVerbatim(t *testing.T) {
	// Normalising case or punctuation produces 404s.
	tests := map[model.Ecosystem]string{
		model.EcosystemNPM:    "/npm/all.zip",
		model.EcosystemGo:     "/Go/all.zip",
		model.EcosystemPyPI:   "/PyPI/all.zip",
		model.EcosystemCrates: "/crates.io/all.zip",
	}
	for e, suffix := range tests {
		t.Run(e.String(), func(t *testing.T) {
			if got, want := archiveURL(e), archiveHost+suffix; got != want {
				t.Errorf("archiveURL = %q, want %q", got, want)
			}
		})
	}
}

func TestEnsureSkipsUnsupportedEcosystems(t *testing.T) {
	srv := newArchiveServer(t, fakeArchive(t, map[string]string{"x.json": "{}"}))
	d := newTestDB(t, srv)

	if err := d.Ensure(context.Background(), []model.Ecosystem{"Maven", ""}); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if got := srv.requests.Load(); got != 0 {
		t.Errorf("made %d requests for unsupported ecosystems, want 0", got)
	}
}

func TestEnsureReportsPerEcosystemFailures(t *testing.T) {
	srv := newArchiveServer(t, fakeArchive(t, map[string]string{"x.json": "{}"}))
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gone", http.StatusNotFound)
	})
	d := newTestDB(t, srv)

	err := d.Ensure(context.Background(), []model.Ecosystem{model.EcosystemNPM, model.EcosystemGo})
	if err == nil {
		t.Fatal("expected an error")
	}
	// Both failures should be reported, not just the first.
	for _, want := range []string{"npm", "Go"} {
		if !bytes.Contains([]byte(err.Error()), []byte(want)) {
			t.Errorf("error %q does not mention %s", err, want)
		}
	}
}

func TestDefaultRootIsUnderTheUserCache(t *testing.T) {
	root, err := DefaultRoot()
	if err != nil {
		t.Skipf("no user cache directory available: %v", err)
	}
	cache, _ := os.UserCacheDir()
	if !filepath.IsAbs(root) {
		t.Errorf("root %q is not absolute", root)
	}
	if got, want := filepath.Dir(filepath.Dir(root)), cache; got != want {
		t.Errorf("root %q is not under the user cache %q", root, cache)
	}
}
