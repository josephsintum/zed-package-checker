package lsp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"go.lsp.dev/protocol"
	"go.lsp.dev/uri"

	"github.com/josephsintum/zed-package-checker/server/internal/engine"
	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// fakeClient captures published diagnostics instead of writing to a connection.
//
// Embedding UnimplementedClient means only the methods under test need
// implementing, and any other call fails loudly rather than passing silently.
type fakeClient struct {
	protocol.UnimplementedClient
	mu            sync.Mutex
	published     map[string][]protocol.Diagnostic
	registrations []string
	err           error
}

func newFakeClient() *fakeClient {
	return &fakeClient{published: make(map[string][]protocol.Diagnostic)}
}

func (c *fakeClient) PublishDiagnostics(_ context.Context, p *protocol.PublishDiagnosticsParams) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	c.published[p.URI.FsPath()] = p.Diagnostics
	return nil
}

func (c *fakeClient) RegisterCapability(_ context.Context, p *protocol.RegistrationParams) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, r := range p.Registrations {
		c.registrations = append(c.registrations, r.Method)
	}
	return nil
}

func (c *fakeClient) diagnostics(path string) []protocol.Diagnostic {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.published[path]
}

// fakeScheduler records what the server asked for.
type fakeScheduler struct {
	mu       sync.Mutex
	requests []engine.Reason
	cleared  []string
	findings map[string][]model.Finding
}

func newFakeScheduler() *fakeScheduler {
	return &fakeScheduler{findings: make(map[string][]model.Finding)}
}

func (f *fakeScheduler) Request(r engine.Reason) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r)
}

func (f *fakeScheduler) Clear(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cleared = append(f.cleared, path)
}

func (f *fakeScheduler) Findings(path string) []model.Finding {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.findings[path]
}

func (f *fakeScheduler) reasons() []engine.Reason {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]engine.Reason(nil), f.requests...)
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

// newTestServer returns a server and the context its handlers must be called
// with. The client travels on the context in production, so a test passing a
// bare background context would exercise a path the server never sees.
// discardLogger is the logger every test here wants: the server logs on paths
// under test, and none of it is what is being asserted.
func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

func newTestServer(t *testing.T) (*Server, context.Context, *fakeClient, *fakeScheduler) {
	t.Helper()
	client := newFakeClient()
	sched := newFakeScheduler()
	s := NewServer(discardLogger(), "test", sched)
	s.root = "/proj"
	return s, protocol.WithClient(t.Context(), client), client, sched
}

// finding builds one for tests.
func finding(name, version string, score float64, path string, line int) model.Finding {
	return model.Finding{
		Package: model.Package{
			PackageKey: model.PackageKey{Ecosystem: model.EcosystemNPM, Name: name},
			Version:    version,
		},
		Advisories: []model.Advisory{{
			ID:        "GHSA-" + name,
			Summary:   name + " is vulnerable",
			CVSSScore: score,
			Affected: []model.Affected{{
				Package: model.PackageKey{Ecosystem: model.EcosystemNPM, Name: name},
				Ranges:  []model.AffectedRange{{Introduced: "0", Fixed: "9.9.9"}},
			}},
		}},
		Evidence: model.Site{Path: path, Range: model.WholeLine(line)},
	}
}

func TestWatchedGlobsAndIsManifestAgree(t *testing.T) {
	// These were two hand-maintained lists and had already diverged. The
	// invariant that divergence breaks: every file the client is asked to
	// watch must also be one didSave acts on, or whichever path was missed
	// stops working with nothing to announce it.
	globs := watchedGlobs()

	for _, glob := range globs {
		// Where the glob is a pattern rather than a name, this turns it into a
		// concrete member; everywhere else it leaves the name alone.
		base := strings.Replace(strings.TrimPrefix(glob, "**/"), "*", "-dev", 1)
		if !isManifest("/proj/" + base) {
			t.Errorf("watching %q, but isManifest(%q) is false", glob, base)
		}
	}

	for _, name := range manifestNames {
		if !slices.Contains(globs, "**/"+name) {
			t.Errorf("isManifest accepts %q, but no watcher glob covers it", name)
		}
	}
}

func TestPublishWithoutAClientOnTheContextFails(t *testing.T) {
	// protocol.NewServer starts dispatching before it returns, so a client
	// stored on the server after construction races with the handlers reading
	// it — and a nil one panics. Taking it from the context removes both; this
	// pins the remaining failure mode to an error rather than a crash.
	s := NewServer(discardLogger(), "test", newFakeScheduler())
	s.root = "/proj"

	err := s.Publish(t.Context(), "/proj/package.json", nil)
	if err == nil {
		t.Fatal("Publish without a client on the context returned nil, want an error")
	}
	if !strings.Contains(err.Error(), "no client") {
		t.Errorf("Publish error = %v, want it to name the missing client", err)
	}
}

func TestPublishRendersFindings(t *testing.T) {
	s, ctx, client, _ := newTestServer(t)

	err := s.Publish(ctx, "/proj/package.json", []model.Finding{
		finding("lodash", "4.17.15", 7.5, "/proj/package.json", 5),
	})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}

	diags := client.diagnostics("/proj/package.json")
	if len(diags) != 1 {
		t.Fatalf("got %d diagnostics, want 1 (no summary for a single finding)", len(diags))
	}
	d := diags[0]
	if got := string(d.Message.(protocol.String)); !strings.Contains(got, "npm:lodash@4.17.15") {
		t.Errorf("message %q does not name the package", got)
	}
	if !strings.Contains(string(d.Message.(protocol.String)), "9.9.9") {
		t.Errorf("message %q does not mention the fixed version", d.Message)
	}
	if src, _ := d.Source.Get(); src != Name {
		t.Errorf("source = %q, want %q", src, Name)
	}
	if got := string(d.Code.(protocol.String)); got != "GHSA-lodash" {
		t.Errorf("code = %q, want the advisory id", got)
	}
}

func TestPublishEmptyClearsTheFile(t *testing.T) {
	// This is what removes a diagnostic the user has fixed.
	s, ctx, client, _ := newTestServer(t)

	if err := s.Publish(ctx, "/proj/package.json", nil); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	diags, ok := client.published["/proj/package.json"]
	if !ok {
		t.Fatal("publishing no findings sent nothing; stale diagnostics would remain")
	}
	if len(diags) != 0 {
		t.Errorf("got %d diagnostics, want an empty set", len(diags))
	}
}

func TestSummaryAppearsForMultipleFindings(t *testing.T) {
	// Per-package diagnostics scatter; the summary is the one line that says
	// the file has a problem.
	s, ctx, client, _ := newTestServer(t)

	err := s.Publish(ctx, "/proj/package.json", []model.Finding{
		finding("a", "1.0.0", 9.8, "/proj/package.json", 3),
		finding("b", "1.0.0", 7.5, "/proj/package.json", 4),
		finding("c", "1.0.0", 5.0, "/proj/package.json", 5),
	})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}

	diags := client.diagnostics("/proj/package.json")
	if len(diags) != 4 {
		t.Fatalf("got %d diagnostics, want 3 findings plus a summary", len(diags))
	}

	summary := diags[0]
	if got := string(summary.Code.(protocol.String)); got != "summary" {
		t.Fatalf("first diagnostic is %q, want the summary", got)
	}
	msg := string(summary.Message.(protocol.String))
	for _, want := range []string{"3 vulnerable dependencies", "1 critical", "1 high", "1 medium"} {
		if !strings.Contains(msg, want) {
			t.Errorf("summary %q does not mention %q", msg, want)
		}
	}
	if summary.Range.Start.Line != 0 {
		t.Errorf("summary is on line %d, want the first line", summary.Range.Start.Line)
	}
}

func TestSeverityMapping(t *testing.T) {
	tests := []struct {
		name  string
		score float64
		dev   bool
		want  protocol.DiagnosticSeverity
	}{
		{"critical is an error", 9.8, false, protocol.DiagnosticSeverityError},
		{"high is an error", 7.5, false, protocol.DiagnosticSeverityError},
		{"medium is a warning", 5.0, false, protocol.DiagnosticSeverityWarning},
		{"low is a warning", 2.0, false, protocol.DiagnosticSeverityWarning},
		{"unscored is a warning", 0, false, protocol.DiagnosticSeverityWarning},
		// Development dependencies do not ship, so they are demoted rather
		// than hidden.
		{"a dev dependency is demoted", 9.8, true, protocol.DiagnosticSeverityWarning},
		{"a low dev dependency is demoted further", 2.0, true, protocol.DiagnosticSeverityInformation},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := finding("p", "1.0.0", tt.score, "/proj/package.json", 1)
			if tt.dev {
				f.DepGroups = []string{"dev"}
			}
			if got := severityFor(f); got != tt.want {
				t.Errorf("severity = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMaliciousIsNeverDemoted(t *testing.T) {
	// "Remove this now" does not become less true for a dev dependency.
	f := finding("evil", "1.0.0", 0, "/proj/package.json", 1)
	f.Advisories[0].ID = "MAL-2024-1"
	f.DepGroups = []string{"dev"}

	if got := severityFor(f); got != protocol.DiagnosticSeverityError {
		t.Errorf("severity = %v, want Error", got)
	}
	if msg := messageFor(f); !strings.Contains(msg, "MALICIOUS") {
		t.Errorf("message %q does not flag the package as malicious", msg)
	}
}

func TestTransitiveFindingPointsAtTheLockfile(t *testing.T) {
	// The diagnostic sits on the manifest the user can edit; related
	// information says where the version was actually resolved.
	f := finding("lodash", "4.17.15", 7.5, "/proj/package-lock.json", 14)
	declared := model.Site{Path: "/proj/package.json", Range: model.WholeLine(5)}
	f.Declared = &model.Anchor{Declaration: declared}

	d := findingDiagnostic(f)
	if d.Range.Start.Line != 4 {
		t.Errorf("diagnostic is on line %d, want the manifest line", d.Range.Start.Line+1)
	}
	if len(d.RelatedInformation) != 1 {
		t.Fatalf("got %d related locations, want 1 pointing at the lockfile", len(d.RelatedInformation))
	}
	if got := d.RelatedInformation[0].Location.URI.FsPath(); got != "/proj/package-lock.json" {
		t.Errorf("related location = %q, want the lockfile", got)
	}
}

func TestFindingDataRoundTrips(t *testing.T) {
	// A code action reads this instead of re-deriving what the diagnostic meant.
	f := finding("lodash", "4.17.15", 7.5, "/proj/package.json", 5)
	d := findingDiagnostic(f)

	var data map[string]any
	if err := json.Unmarshal(d.Data, &data); err != nil {
		t.Fatalf("data is not valid JSON: %v", err)
	}
	want := []struct {
		key   string
		value any
	}{
		{"ecosystem", "npm"},
		{"name", "lodash"},
		{"version", "4.17.15"},
		{"fixedVersion", "9.9.9"},
	}
	for _, w := range want {
		if got := data[w.key]; got != w.value {
			t.Errorf("data[%q] = %v, want %v", w.key, got, w.value)
		}
	}
}

func TestInitializedRegistersWatchersAndRequestsAScan(t *testing.T) {
	s, ctx, client, sched := newTestServer(t)

	if err := s.Initialized(ctx, &protocol.InitializedParams{}); err != nil {
		t.Fatalf("Initialized: %v", err)
	}
	// Registration happens in the background so it cannot stall initialization.
	waitFor(t, "the watcher registration", func() bool {
		client.mu.Lock()
		defer client.mu.Unlock()
		return len(client.registrations) == 1 &&
			client.registrations[0] == "workspace/didChangeWatchedFiles"
	})
	if got := sched.reasons(); len(got) != 1 || got[0] != engine.ReasonStartup {
		t.Errorf("requests = %v, want one startup scan", got)
	}
}

func TestDeletedManifestIsClearedImmediately(t *testing.T) {
	// Waiting out a debounce would leave diagnostics on a file that is gone.
	s, ctx, _, sched := newTestServer(t)

	err := s.DidChangeWatchedFiles(ctx, &protocol.DidChangeWatchedFilesParams{
		Changes: []protocol.FileEvent{
			{URI: uri.File("/proj/package.json"), Type: protocol.FileChangeTypeDeleted},
			{URI: uri.File("/proj/go.mod"), Type: protocol.FileChangeTypeChanged},
		},
	})
	if err != nil {
		t.Fatalf("DidChangeWatchedFiles: %v", err)
	}

	if len(sched.cleared) != 1 || sched.cleared[0] != "/proj/package.json" {
		t.Errorf("cleared %v, want only the deleted manifest", sched.cleared)
	}
	if got := sched.reasons(); len(got) != 1 {
		t.Errorf("requests = %v, want one rescan for the batch", got)
	}
}

func TestDidSaveOnlyRescansForManifests(t *testing.T) {
	s, ctx, _, sched := newTestServer(t)

	for _, path := range []string{"/proj/src/index.js", "/proj/README.md"} {
		_ = s.DidSave(ctx, &protocol.DidSaveTextDocumentParams{
			TextDocument: protocol.TextDocumentIdentifier{URI: uri.File(path)},
		})
	}
	if got := sched.reasons(); len(got) != 0 {
		t.Errorf("saving source triggered %v, want no rescan", got)
	}

	for _, path := range []string{"/proj/package.json", "/proj/go.mod", "/proj/requirements-dev.txt"} {
		_ = s.DidSave(ctx, &protocol.DidSaveTextDocumentParams{
			TextDocument: protocol.TextDocumentIdentifier{URI: uri.File(path)},
		})
	}
	if got := len(sched.reasons()); got != 3 {
		t.Errorf("manifest saves triggered %d rescans, want 3", got)
	}
}

func TestDidOpenRepublishesWithoutScanning(t *testing.T) {
	// The editor may drop diagnostics for a file it has no buffer for.
	s, ctx, client, sched := newTestServer(t)
	sched.findings["/proj/package.json"] = []model.Finding{
		finding("lodash", "4.17.15", 7.5, "/proj/package.json", 5),
	}

	err := s.DidOpen(ctx, &protocol.DidOpenTextDocumentParams{
		TextDocument: protocol.TextDocumentItem{URI: uri.File("/proj/package.json")},
	})
	if err != nil {
		t.Fatalf("DidOpen: %v", err)
	}
	if got := len(client.diagnostics("/proj/package.json")); got != 1 {
		t.Errorf("republished %d diagnostics, want 1", got)
	}
	if got := sched.reasons(); len(got) != 0 {
		t.Errorf("opening a file triggered %v, want no scan", got)
	}
}

func TestIsManifest(t *testing.T) {
	// A slice keeps the manifests together and the near-misses together, which
	// is most of what this table is saying.
	tests := []struct {
		path string
		want bool
	}{
		{"/p/package.json", true},
		{"/p/package-lock.json", true},
		{"/p/go.mod", true},
		{"/p/go.sum", true},
		{"/p/pyproject.toml", true},
		{"/p/requirements.txt", true},
		{"/p/requirements-dev.txt", true},
		{"/p/Cargo.lock", true},

		{"/p/src/index.js", false},
		{"/p/README.md", false},
		{"/p/requirements.md", false},
		{"/p/my-package.json.bak", false},
	}
	for _, tt := range tests {
		path, want := tt.path, tt.want
		t.Run(path, func(t *testing.T) {
			if got := isManifest(path); got != want {
				t.Errorf("isManifest(%q) = %v, want %v", path, got, want)
			}
		})
	}
}

func TestPublishFailurePropagates(t *testing.T) {
	s, ctx, client, _ := newTestServer(t)
	sentinel := errors.New("connection closed")
	client.err = sentinel

	err := s.Publish(ctx, "/proj/package.json", nil)
	if !errors.Is(err, sentinel) {
		t.Errorf("Publish error = %v, want it to wrap %v", err, sentinel)
	}
}

func TestToProtocolRangeIsZeroBased(t *testing.T) {
	// WholeLine takes a one-based line; the wire is zero-based.
	got := toProtocolRange(model.WholeLine(14))
	want := protocol.Range{
		Start: protocol.Position{Line: 13, Character: 0},
		End:   protocol.Position{Line: 14, Character: 0},
	}
	if got != want {
		t.Errorf("toProtocolRange = %+v, want %+v", got, want)
	}
}

func TestWorkspaceRoot(t *testing.T) {
	folderURI := uri.File("/from/folder")
	rootURI := uri.File("/from/rooturi")

	t.Run("prefers workspace folders", func(t *testing.T) {
		p := &protocol.InitializeParams{
			WorkspaceFolders: protocol.NewNullable([]protocol.WorkspaceFolder{{URI: folderURI}}),
			RootURI:          &rootURI,
		}
		if got := workspaceRoot(p); got != "/from/folder" {
			t.Errorf("workspaceRoot = %q, want /from/folder", got)
		}
	})

	t.Run("falls back to the deprecated rootUri", func(t *testing.T) {
		if got := workspaceRoot(&protocol.InitializeParams{RootURI: &rootURI}); got != "/from/rooturi" {
			t.Errorf("workspaceRoot = %q, want /from/rooturi", got)
		}
	})

	t.Run("no root at all", func(t *testing.T) {
		if got := workspaceRoot(&protocol.InitializeParams{}); got != "" {
			t.Errorf("workspaceRoot = %q, want empty", got)
		}
	})
}

func TestNegotiatePositionEncoding(t *testing.T) {
	tests := []struct {
		name    string
		general *protocol.GeneralClientCapabilities
		want    protocol.PositionEncodingKind
	}{
		{
			name: "utf-8 preferred when offered",
			general: &protocol.GeneralClientCapabilities{PositionEncodings: []protocol.PositionEncodingKind{
				protocol.PositionEncodingKindUTF16, protocol.PositionEncodingKindUTF8,
			}},
			want: protocol.PositionEncodingKindUTF8,
		},
		{
			name:    "utf-16 when the client offers none",
			general: &protocol.GeneralClientCapabilities{},
			want:    protocol.PositionEncodingKindUTF16,
		},
		{
			// A minimal client may omit "general" entirely. Dereferencing it
			// would crash the server during initialize.
			name:    "utf-16 when general capabilities are absent",
			general: nil,
			want:    protocol.PositionEncodingKindUTF16,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &protocol.InitializeParams{}
			p.Capabilities.General = tt.general
			if got := negotiatePositionEncoding(p); got != tt.want {
				t.Errorf("negotiatePositionEncoding = %q, want %q", got, tt.want)
			}
		})
	}
}

// advisories builds n advisories against key, all unrated unless score > 0.
func advisories(key model.PackageKey, n int, score float64, fixed string) []model.Advisory {
	out := make([]model.Advisory, 0, n)
	for i := range n {
		out = append(out, model.Advisory{
			ID:        fmt.Sprintf("GO-2023-%04d", i),
			CVSSScore: score,
			Affected: []model.Affected{{
				Package: key,
				Ranges:  []model.AffectedRange{{Introduced: "0", Fixed: fixed}},
			}},
		})
	}
	return out
}

func TestMessageFor(t *testing.T) {
	stdlib := model.PackageKey{Ecosystem: model.EcosystemGo, Name: "stdlib"}
	lodash := model.PackageKey{Ecosystem: model.EcosystemNPM, Name: "lodash"}

	tests := []struct {
		name     string
		finding  model.Finding
		contains []string
		absent   []string
	}{
		{
			name: "the toolchain is not a dependency",
			finding: model.Finding{
				Package:    model.Package{PackageKey: stdlib, Version: "1.21"},
				Advisories: advisories(stdlib, 76, 0, "1.21.1"),
			},
			contains: []string{
				"Go toolchain 1.21",
				"76 known vulnerabilities",
				"go directive is a minimum",
			},
			// One advisory's fix clears almost none of seventy-six, and
			// "Unknown" is what the Go database publishes for all of them.
			absent: []string{"Fixed in", "Unknown", "stdlib", "advisories, worst"},
		},
		{
			name: "a single toolchain advisory still names its fix",
			finding: model.Finding{
				Package:    model.Package{PackageKey: stdlib, Version: "1.21"},
				Advisories: advisories(stdlib, 1, 0, "1.21.1"),
			},
			contains: []string{"Go toolchain 1.21", "1 known vulnerability", "Fixed in 1.21.1"},
			absent:   []string{"Unknown"},
		},
		{
			name: "a rated package keeps its severity and count",
			finding: model.Finding{
				Package:    model.Package{PackageKey: lodash, Version: "4.17.15"},
				Advisories: advisories(lodash, 6, 7.2, "4.17.21"),
			},
			contains: []string{"npm:lodash@4.17.15", "6 advisories, worst High (CVSS 7.2)", "Fixed in 4.17.21"},
			absent:   []string{"go directive"},
		},
		{
			name: "an unrated dependency drops the severity, not the fix",
			finding: model.Finding{
				Package:    model.Package{PackageKey: lodash, Version: "4.17.15"},
				Advisories: advisories(lodash, 3, 0, "4.17.21"),
			},
			contains: []string{"3 known vulnerabilities", "Fixed in 4.17.21"},
			absent:   []string{"Unknown"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := messageFor(tt.finding)
			for _, want := range tt.contains {
				if !strings.Contains(got, want) {
					t.Errorf("message %q does not contain %q", got, want)
				}
			}
			for _, unwanted := range tt.absent {
				if strings.Contains(got, unwanted) {
					t.Errorf("message %q should not contain %q", got, unwanted)
				}
			}
		})
	}
}
