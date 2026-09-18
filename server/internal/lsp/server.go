// Package lsp adapts the package checker to the Language Server Protocol.
//
// It is deliberately the only package in this module permitted to import
// go.lsp.dev. Everything it exposes inward is expressed in plain Go types, so
// that swapping the protocol library remains a change confined to this package.
package lsp

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"go.lsp.dev/protocol"
	"go.lsp.dev/uri"

	"github.com/josephsintum/zed-package-checker/server/internal/engine"
	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// Name is the server name reported to the client and set as the `source` field
// of every diagnostic this server publishes.
const Name = "package-checker"

// label overrides Name, so two servers can run side by side and be told apart
// in the diagnostics panel. Testing scaffolding, not a setting.
var label = Name

// SetLabel names this server in its diagnostics. Call before serving.
func SetLabel(name string) {
	if name != "" {
		label = name
	}
}

// manifestNames are files a change to which can alter what a project depends
// on.
//
// The single source of truth for "is this a dependency manifest": the watcher
// patterns are derived from it and isManifest tests against it. Kept that way
// because the two were maintained separately and had already diverged — a
// lockfile added to one and not the other silently disables either the watcher
// or the didSave fallback, and nothing fails to announce it.
var manifestNames = []string{
	"package.json", "package-lock.json", "npm-shrinkwrap.json",
	"yarn.lock", "pnpm-lock.yaml", "bun.lock",
	"go.mod", "go.sum",
	"pyproject.toml", "poetry.lock", "uv.lock",
	"Cargo.toml", "Cargo.lock",
}

// The requirements.txt family — requirements.txt, requirements-dev.txt and the
// rest — is a pattern rather than a fixed name, so it cannot live in
// manifestNames and is spelled once here instead.
const (
	requirementsPrefix = "requirements"
	requirementsSuffix = ".txt"
)

// watchedGlobs are the patterns whose matches trigger a rescan, derived from
// manifestNames so the two cannot disagree.
//
// Source files are deliberately absent: what a project depends on changes when
// a manifest or lockfile changes, and watching source would rescan on every
// save for no benefit.
func watchedGlobs() []string {
	globs := make([]string, 0, len(manifestNames)+1)
	for _, name := range manifestNames {
		globs = append(globs, "**/"+name)
	}
	return append(globs, "**/"+requirementsPrefix+"*"+requirementsSuffix)
}

// Scheduler is the scan scheduling this server drives, satisfied by
// engine.Engine.
type Scheduler interface {
	Request(reason engine.Reason)
	Clear(path string)
	Findings(path string) []model.Finding
}

// Server implements protocol.Server.
//
// Embedding protocol.UnimplementedServer means every LSP method the checker
// does not handle returns a "method not found" error rather than panicking, so
// unsupported requests degrade cleanly as methods are added stage by stage.
type Server struct {
	protocol.UnimplementedServer

	log       *slog.Logger
	version   string
	scheduler Scheduler

	// root is the workspace directory to scan, captured during Initialize.
	root string

	// utf16Columns records the negotiated encoding. Set once during Initialize
	// and read from the goroutines that publish, so it is atomic rather than
	// plain: since locate started emitting exact columns this decides whether
	// they are correct, where whole-line ranges never cared.
	utf16Columns atomic.Bool

	// ready closes once Initialize has set the root, so scheduling can start
	// against the right directory rather than an empty one.
	ready     chan struct{}
	readyOnce sync.Once
}

// NewServer builds a Server.
//
// The client handle is deliberately not stored. protocol.NewServer builds it
// from the server, so it cannot exist before the server does, and it starts
// dispatching requests before it returns — any field assigned afterwards races
// with the handlers reading it. It travels on the request context instead,
// which is where the protocol package puts it.
func NewServer(log *slog.Logger, version string, scheduler Scheduler) *Server {
	return &Server{
		log:       log,
		version:   version,
		scheduler: scheduler,
		ready:     make(chan struct{}),
	}
}

// Ready closes once the workspace root is known.
func (s *Server) Ready() <-chan struct{} { return s.ready }

// Root returns the workspace directory, known after Initialize.
func (s *Server) Root() string { return s.root }

// Publish delivers one file's findings, satisfying engine.Publisher.
//
// An empty slice is published rather than skipped: that is what clears
// diagnostics for a file which is no longer affected.
//
// ctx must carry the client, which every context derived from the one
// protocol.NewServer returns does.
func (s *Server) Publish(ctx context.Context, path string, findings []model.Finding) error {
	client, ok := protocol.ClientFromContext(ctx)
	if !ok {
		return fmt.Errorf("publish %s: no client on the context", path)
	}
	diagnostics := diagnosticsFor(path, findings)
	if s.utf16Columns.Load() {
		// locate counts columns in bytes. A client that did not offer UTF-8
		// counts UTF-16 code units, and the two differ on any line with
		// non-ASCII text before the dependency name.
		toUTF16Columns(path, diagnostics)
	}

	err := client.PublishDiagnostics(ctx, &protocol.PublishDiagnosticsParams{
		URI:         uri.File(path),
		Diagnostics: diagnostics,
	})
	if err != nil {
		return fmt.Errorf("publish %s: %w", path, err)
	}
	return nil
}

// Initialize records the workspace root, negotiates a position encoding and
// advertises capabilities.
func (s *Server) Initialize(ctx context.Context, params *protocol.InitializeParams) (*protocol.InitializeResult, error) {
	s.root = workspaceRoot(params)
	if s.root == "" {
		return nil, fmt.Errorf("initialize: no workspace root in rootUri or workspaceFolders")
	}
	encoding := negotiatePositionEncoding(params)
	s.utf16Columns.Store(encoding == protocol.PositionEncodingKindUTF16)

	s.log.Info("initialize",
		"root", s.root,
		"positionEncoding", string(encoding))
	s.readyOnce.Do(func() { close(s.ready) })

	openClose := true
	noChange := protocol.TextDocumentSyncKindNone
	includeText := false

	return &protocol.InitializeResult{
		Capabilities: protocol.ServerCapabilities{
			PositionEncoding: encoding,
			// Manifests are read from disk, not from the buffer, so document
			// contents are never needed: only open/close, to re-publish, and
			// save, to rescan.
			TextDocumentSync: &protocol.TextDocumentSyncOptions{
				OpenClose: &openClose,
				Change:    &noChange,
				Save:      &protocol.SaveOptions{IncludeText: &includeText},
			},
		},
		ServerInfo: protocol.ServerInfo{
			Name:    label,
			Version: protocol.NewOptional(s.version),
		},
	}, nil
}

// Initialized registers file watchers and asks for the first scan.
//
// Registration is a request to the client, so it runs in the background: a
// notification handler that blocks on a client round-trip stalls everything
// behind it if the client is slow to answer, and nothing here depends on the
// outcome.
func (s *Server) Initialized(ctx context.Context, params *protocol.InitializedParams) error {
	go s.registerWatchers(context.WithoutCancel(ctx))
	s.scheduler.Request(engine.ReasonStartup)
	return nil
}

// registerWatchers asks the client to report manifest changes.
//
// Failure is not fatal: didSave still catches files the user edits, so the
// server degrades to missing only changes made by tools outside the editor.
func (s *Server) registerWatchers(ctx context.Context) {
	globs := watchedGlobs()
	watchers := make([]protocol.FileSystemWatcher, 0, len(globs))
	for _, glob := range globs {
		watchers = append(watchers, protocol.FileSystemWatcher{
			GlobPattern: protocol.Pattern(glob),
		})
	}

	// RegisterOptions is raw JSON, so the options are marshalled.
	options := encodeData(protocol.DidChangeWatchedFilesRegistrationOptions{Watchers: watchers})

	client, ok := protocol.ClientFromContext(ctx)
	if !ok {
		s.log.Warn("no client on the context; file watchers not registered")
		return
	}

	err := client.RegisterCapability(ctx, &protocol.RegistrationParams{
		Registrations: []protocol.Registration{{
			ID:              "package-checker-watch-manifests",
			Method:          "workspace/didChangeWatchedFiles",
			RegisterOptions: options,
		}},
	})
	if err != nil {
		s.log.Warn("could not register file watchers; "+
			"changes made outside the editor will not trigger a rescan", "error", err)
	}
}

// DidChangeWatchedFiles reacts to manifests changing on disk.
func (s *Server) DidChangeWatchedFiles(ctx context.Context, params *protocol.DidChangeWatchedFilesParams) error {
	for _, change := range params.Changes {
		if change.Type == protocol.FileChangeTypeDeleted {
			// Clear immediately rather than waiting out a debounce: a deleted
			// manifest's diagnostics are wrong the moment it is gone.
			s.scheduler.Clear(change.URI.FsPath())
		}
	}
	if len(params.Changes) > 0 {
		s.scheduler.Request(engine.ReasonFileChanged)
	}
	return nil
}

// DidSave rescans when a manifest is saved.
//
// Redundant with the file watchers when those work, and the fallback when they
// do not: watcher support varies, particularly over SSH.
func (s *Server) DidSave(ctx context.Context, params *protocol.DidSaveTextDocumentParams) error {
	if isManifest(params.TextDocument.URI.FsPath()) {
		s.scheduler.Request(engine.ReasonFileSaved)
	}
	return nil
}

// DidOpen re-publishes what is already known about a file.
//
// The editor may drop diagnostics for a file it has no buffer for, so opening
// one has to restate them. Cheap, and never triggers a scan.
func (s *Server) DidOpen(ctx context.Context, params *protocol.DidOpenTextDocumentParams) error {
	path := params.TextDocument.URI.FsPath()
	if findings := s.scheduler.Findings(path); len(findings) > 0 {
		return s.Publish(ctx, path, findings)
	}
	return nil
}

// Shutdown is a no-op: the server holds no state that must be flushed.
func (s *Server) Shutdown(ctx context.Context) error {
	s.log.Info("shutdown requested")
	return nil
}

// Exit terminates the process, per the LSP specification.
func (s *Server) Exit(ctx context.Context) error {
	s.log.Info("exiting")
	os.Exit(0)
	return nil
}

// isManifest reports whether a path is a dependency manifest or lockfile.
func isManifest(path string) bool {
	base := filepath.Base(path)
	if slices.Contains(manifestNames, base) {
		return true
	}
	// requirements.txt, requirements-dev.txt, and the rest of the family.
	return strings.HasPrefix(base, requirementsPrefix) && strings.HasSuffix(base, requirementsSuffix)
}

// toProtocolRange converts a model range, already zero-based in the negotiated
// encoding, into the protocol's own type.
func toProtocolRange(r model.Range) protocol.Range {
	return protocol.Range{
		Start: protocol.Position{Line: uint32(r.Start.Line), Character: uint32(r.Start.Column)},
		End:   protocol.Position{Line: uint32(r.End.Line), Character: uint32(r.End.Column)},
	}
}

// workspaceRoot resolves the directory to scan, preferring the first workspace
// folder and falling back to the deprecated rootUri that some clients still
// send alone.
func workspaceRoot(params *protocol.InitializeParams) string {
	if folders, ok := params.WorkspaceFolders.Get(); ok {
		for _, folder := range folders {
			if p := folder.URI.FsPath(); p != "" {
				return p
			}
		}
	}
	// Reviewed 2026-09-16 and kept deliberately: rootUri is deprecated, but a
	// minimal client may still send only it.
	//nolint:staticcheck
	if params.RootURI != nil {
		if p := params.RootURI.FsPath(); p != "" {
			return p
		}
	}
	return ""
}

// negotiatePositionEncoding picks the most convenient encoding the client
// supports.
//
// UTF-8 is preferred because manifest parsing produces byte offsets already;
// anything else requires converting every column. UTF-16 is the protocol
// default and the guaranteed fallback.
func negotiatePositionEncoding(params *protocol.InitializeParams) protocol.PositionEncodingKind {
	// General is optional and absent from minimal clients, so it must not be
	// dereferenced blindly during initialize.
	general := params.Capabilities.General
	if general == nil {
		return protocol.PositionEncodingKindUTF16
	}
	if slices.Contains(general.PositionEncodings, protocol.PositionEncodingKindUTF8) {
		return protocol.PositionEncodingKindUTF8
	}
	return protocol.PositionEncodingKindUTF16
}
