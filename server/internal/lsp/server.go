// Package lsp adapts the package checker to the Language Server Protocol.
//
// It is deliberately the only package in this module permitted to import
// go.lsp.dev. Everything it exposes inward is expressed in plain Go types, so
// that swapping the protocol library remains a change confined to this package.
package lsp

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"go.lsp.dev/protocol"
	"go.lsp.dev/uri"
)

// Name is the server name reported to the client and set as the `source` field
// of every diagnostic this server publishes.
const Name = "package-checker"

// projectURI is used as the advisory link until real findings carry their own.
var projectURI = uri.MustParse("https://github.com/josephsintum/zed-package-checker")

// Server implements protocol.Server.
//
// Embedding protocol.UnimplementedServer means every LSP method the checker
// does not handle returns a "method not found" error rather than panicking, so
// unsupported requests degrade cleanly as methods are added stage by stage.
type Server struct {
	protocol.UnimplementedServer

	log     *slog.Logger
	version string

	// client is injected by SetClient once the JSON-RPC connection exists.
	// It is nil between construction and that call, so it must not be used
	// before Initialize.
	client protocol.Client

	// root is the workspace directory to scan, captured during Initialize.
	root string

	// posEncoding is the encoding negotiated during Initialize. Column offsets
	// in published diagnostics must be expressed in these units.
	posEncoding protocol.PositionEncodingKind
}

// NewServer builds a Server that logs to log and reports itself as version.
//
// The client is not available at construction time because protocol.NewServer
// creates it from the server; call SetClient before serving.
func NewServer(log *slog.Logger, version string) *Server {
	return &Server{log: log, version: version}
}

// SetClient injects the client handle used to push notifications such as
// diagnostics. It must be called before the connection starts serving.
func (s *Server) SetClient(client protocol.Client) { s.client = client }

// Initialize records the workspace root, negotiates a position encoding and
// advertises the capabilities implemented so far.
func (s *Server) Initialize(ctx context.Context, params *protocol.InitializeParams) (*protocol.InitializeResult, error) {
	s.root = workspaceRoot(params)
	if s.root == "" {
		return nil, fmt.Errorf("initialize: no workspace root in rootUri or workspaceFolders")
	}
	s.posEncoding = negotiatePositionEncoding(params)

	s.log.Info("initialize",
		"root", s.root,
		"positionEncoding", string(s.posEncoding),
	)

	openClose := true
	noChange := protocol.TextDocumentSyncKindNone
	includeText := false

	return &protocol.InitializeResult{
		Capabilities: protocol.ServerCapabilities{
			PositionEncoding: s.posEncoding,
			// Full sync is deliberately not requested. The checker reads
			// manifests from disk and ignores dirty buffers, so it needs
			// didOpen/didClose (to re-publish cached diagnostics) and didSave
			// (to rescan), but never document contents.
			TextDocumentSync: &protocol.TextDocumentSyncOptions{
				OpenClose: &openClose,
				Change:    &noChange,
				Save:      &protocol.SaveOptions{IncludeText: &includeText},
			},
		},
		ServerInfo: protocol.ServerInfo{
			Name:    Name,
			Version: protocol.NewOptional(s.version),
		},
	}, nil
}

// Initialized is sent once the client is ready to receive requests.
// Diagnostics may only be published from this point onward.
func (s *Server) Initialized(ctx context.Context, params *protocol.InitializedParams) error {
	// Stage 1 walking skeleton: publish a single hardcoded diagnostic so the
	// whole pipe (Zed -> extension -> binary -> stdio -> diagnostics panel) can
	// be verified before any real scanning exists.
	//
	// It is published unconditionally, whether or not the file is open, which
	// is precisely what the closed-buffer gate needs to exercise.
	return s.publishSkeletonDiagnostic(ctx)
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

// publishSkeletonDiagnostic reports a placeholder finding against every
// package.json in the workspace.
//
// It walks the tree rather than checking the root alone, because that is how
// real scanning behaves: the workspace root is frequently a repository whose
// manifests live several directories down.
func (s *Server) publishSkeletonDiagnostic(ctx context.Context) error {
	manifests, err := findManifests(s.root, "package.json")
	if err != nil {
		return fmt.Errorf("scan %s for manifests: %w", s.root, err)
	}
	if len(manifests) == 0 {
		s.log.Info("no manifests in workspace, nothing to publish", "root", s.root)
		return nil
	}

	for _, manifest := range manifests {
		diag := protocol.Diagnostic{
			Range: protocol.Range{
				Start: protocol.Position{Line: 0, Character: 0},
				End:   protocol.Position{Line: 0, Character: 1},
			},
			Severity:        protocol.DiagnosticSeverityWarning,
			Source:          protocol.NewOptional(Name),
			Code:            protocol.String("STAGE-1-SKELETON"),
			CodeDescription: protocol.CodeDescription{Href: projectURI},
			Message: protocol.String("package-checker is wired up. " +
				"This placeholder is replaced by real findings in a later stage."),
		}
		err := s.client.PublishDiagnostics(ctx, &protocol.PublishDiagnosticsParams{
			URI:         uri.File(manifest),
			Diagnostics: []protocol.Diagnostic{diag},
		})
		if err != nil {
			return fmt.Errorf("publish diagnostics for %s: %w", manifest, err)
		}
	}

	s.log.Info("published skeleton diagnostics",
		"manifests", len(manifests),
		"paths", manifests)
	return nil
}

// skipDirs are never descended into. They hold dependency trees and VCS data
// whose manifests describe other people's packages, not this project's.
var skipDirs = map[string]bool{
	"node_modules": true,
	".git":         true,
	".venv":        true,
	"venv":         true,
	"vendor":       true,
	"target":       true,
	"dist":         true,
}

// findManifests walks root and returns every file matching name.
//
// Unreadable directories are skipped rather than failing the walk: a single
// permission error deep in a tree should not cost the user every other finding.
func findManifests(root, name string) ([]string, error) {
	var found []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if path != root && (skipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".")) {
				return fs.SkipDir
			}
			return nil
		}
		if d.Name() == name {
			found = append(found, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return found, nil
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
	//nolint:staticcheck // rootUri is deprecated but still the only root some clients send.
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
// default and the guaranteed fallback when the client expresses no preference.
func negotiatePositionEncoding(params *protocol.InitializeParams) protocol.PositionEncodingKind {
	if slices.Contains(params.Capabilities.General.PositionEncodings, protocol.PositionEncodingKindUTF8) {
		return protocol.PositionEncodingKindUTF8
	}
	return protocol.PositionEncodingKindUTF16
}
