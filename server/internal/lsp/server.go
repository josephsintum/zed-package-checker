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
	"slices"

	"go.lsp.dev/protocol"
	"go.lsp.dev/uri"

	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// Name is the server name reported to the client and set as the `source` field
// of every diagnostic this server publishes.
const Name = "package-checker"

// projectURI is used as the advisory link until real findings carry their own.
var projectURI = uri.MustParse("https://github.com/josephsintum/zed-package-checker")

// Extractor discovers the dependencies under a project root.
//
// Declared here rather than imported so the protocol layer depends only on
// model types, and can be faked in tests without running a real scan.
type Extractor interface {
	Extract(ctx context.Context, root string) ([]model.ExtractedPackage, error)
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
	extractor Extractor

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
func NewServer(log *slog.Logger, version string, extractor Extractor) *Server {
	return &Server{log: log, version: version, extractor: extractor}
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
	return s.publishExtracted(ctx)
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

// publishExtracted reports every dependency found in the workspace.
//
// These are informational, not findings: nothing has been matched against an
// advisory database yet. They exist so the path from extraction to the editor
// can be seen working before matching lands, and are replaced by real findings
// once it does.
func (s *Server) publishExtracted(ctx context.Context) error {
	pkgs, err := s.extractor.Extract(ctx, s.root)
	if err != nil {
		return fmt.Errorf("extract %s: %w", s.root, err)
	}
	if len(pkgs) == 0 {
		s.log.Info("no dependencies found", "root", s.root)
		return nil
	}

	// Grouped per file: LSP replaces a file's diagnostics wholesale, so
	// publishing per package would leave only the last one visible.
	byFile := make(map[string][]protocol.Diagnostic)
	for _, p := range pkgs {
		site := anchorSite(p)
		byFile[site.Path] = append(byFile[site.Path], diagnosticFor(p, site))
	}

	for path, diags := range byFile {
		err := s.client.PublishDiagnostics(ctx, &protocol.PublishDiagnosticsParams{
			URI:         uri.File(path),
			Diagnostics: diags,
		})
		if err != nil {
			return fmt.Errorf("publish diagnostics for %s: %w", path, err)
		}
	}

	s.log.Info("published extracted dependencies",
		"packages", len(pkgs), "files", len(byFile))
	return nil
}

// anchorSite picks where to report a package: the manifest the user can edit,
// falling back to wherever the version was established.
//
// Without this the finding lands in a generated lockfile, which is both harder
// to notice and not the line anyone would change.
func anchorSite(p model.ExtractedPackage) model.Site {
	if p.Declared != nil {
		return *p.Declared
	}
	return p.Evidence
}

// diagnosticFor renders one extracted package as a diagnostic at site.
func diagnosticFor(p model.ExtractedPackage, site model.Site) protocol.Diagnostic {
	message := fmt.Sprintf("found %s", p.Package)
	if p.FromRange {
		message += " (resolved from a version range; may not be what is installed)"
	}
	if len(p.DepGroups) > 0 {
		message += fmt.Sprintf(" %v", p.DepGroups)
	}

	return protocol.Diagnostic{
		Range: toProtocolRange(site.Range),
		// Warning rather than Information purely so these are visible while
		// matching is being built: Zed's diagnostics panel lists errors and
		// warnings, and silently omits anything below. Replaced by real
		// severities derived from advisories once matching lands.
		Severity:        protocol.DiagnosticSeverityWarning,
		Source:          protocol.NewOptional(Name),
		Code:            protocol.String("STAGE-3-EXTRACTED"),
		CodeDescription: protocol.CodeDescription{Href: projectURI},
		Message:         protocol.String(message),
	}
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
// default and the guaranteed fallback when the client expresses no preference.
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
