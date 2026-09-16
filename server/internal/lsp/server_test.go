package lsp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"go.lsp.dev/protocol"
	"go.lsp.dev/uri"

	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// fakeClient captures published diagnostics instead of writing to a connection.
//
// Embedding UnimplementedClient means only the one method under test needs
// implementing, and any other call the server makes fails loudly rather than
// passing silently.
type fakeClient struct {
	protocol.UnimplementedClient
	published map[string][]protocol.Diagnostic
	err       error
}

func newFakeClient() *fakeClient {
	return &fakeClient{published: make(map[string][]protocol.Diagnostic)}
}

func (c *fakeClient) PublishDiagnostics(_ context.Context, p *protocol.PublishDiagnosticsParams) error {
	if c.err != nil {
		return c.err
	}
	c.published[p.URI.FsPath()] = p.Diagnostics
	return nil
}

// fakeExtractor returns canned results, so protocol behaviour can be tested
// without touching a filesystem.
type fakeExtractor struct {
	pkgs []model.ExtractedPackage
	err  error
}

func (f fakeExtractor) Extract(context.Context, string) ([]model.ExtractedPackage, error) {
	return f.pkgs, f.err
}

func pkg(ecosystem model.Ecosystem, name, version, path string, line int) model.ExtractedPackage {
	return model.ExtractedPackage{
		Package: model.Package{
			PackageKey: model.PackageKey{Ecosystem: ecosystem, Name: name},
			Version:    version,
		},
		Evidence: model.Site{Path: path, Range: model.WholeLine(line)},
	}
}

func newTestServer(t *testing.T, e Extractor) (*Server, *fakeClient) {
	t.Helper()
	client := newFakeClient()
	s := NewServer(slog.New(slog.NewTextHandler(io.Discard, nil)), "test", e)
	s.SetClient(client)
	s.root = "/proj"
	return s, client
}

func TestPublishExtractedGroupsByFile(t *testing.T) {
	// LSP replaces a file's diagnostics wholesale, so two packages in one file
	// must arrive in a single publish or only the last would survive.
	s, client := newTestServer(t, fakeExtractor{pkgs: []model.ExtractedPackage{
		pkg(model.EcosystemGo, "github.com/gin-gonic/gin", "1.6.0", "/proj/go.mod", 6),
		pkg(model.EcosystemGo, "gopkg.in/yaml.v2", "2.2.2", "/proj/go.mod", 7),
		pkg(model.EcosystemNPM, "lodash", "4.17.15", "/proj/package.json", 5),
	}})

	if err := s.publishExtracted(context.Background()); err != nil {
		t.Fatalf("publishExtracted: %v", err)
	}

	if got := len(client.published); got != 2 {
		t.Fatalf("published to %d files, want 2: %v", got, client.published)
	}
	if got := len(client.published["/proj/go.mod"]); got != 2 {
		t.Errorf("go.mod got %d diagnostics, want 2", got)
	}
	if got := len(client.published["/proj/package.json"]); got != 1 {
		t.Errorf("package.json got %d diagnostics, want 1", got)
	}
}

func TestPublishExtractedNothingFound(t *testing.T) {
	// The server starts for nearly every project, so most workspaces have no
	// dependencies. That must not error or publish.
	s, client := newTestServer(t, fakeExtractor{})

	if err := s.publishExtracted(context.Background()); err != nil {
		t.Fatalf("publishExtracted: %v", err)
	}
	if len(client.published) != 0 {
		t.Errorf("published %v, want nothing", client.published)
	}
}

func TestPublishExtractedPropagatesErrors(t *testing.T) {
	sentinel := errors.New("boom")

	s, _ := newTestServer(t, fakeExtractor{err: sentinel})
	if err := s.publishExtracted(context.Background()); !errors.Is(err, sentinel) {
		t.Errorf("extract error = %v, want it to wrap %v", err, sentinel)
	}

	s, client := newTestServer(t, fakeExtractor{pkgs: []model.ExtractedPackage{
		pkg(model.EcosystemNPM, "lodash", "4.17.15", "/proj/package.json", 5),
	}})
	client.err = sentinel
	if err := s.publishExtracted(context.Background()); !errors.Is(err, sentinel) {
		t.Errorf("publish error = %v, want it to wrap %v", err, sentinel)
	}
}

func TestDiagnosticFor(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(*model.ExtractedPackage)
		wantMessage string
	}{
		{
			name:        "plain package",
			mutate:      func(*model.ExtractedPackage) {},
			wantMessage: "found npm:lodash@4.17.15",
		},
		{
			name:        "from a version range",
			mutate:      func(p *model.ExtractedPackage) { p.FromRange = true },
			wantMessage: "found npm:lodash@4.17.15 (resolved from a version range; may not be what is installed)",
		},
		{
			name:        "with dependency groups",
			mutate:      func(p *model.ExtractedPackage) { p.DepGroups = []string{"dev"} },
			wantMessage: "found npm:lodash@4.17.15 [dev]",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := pkg(model.EcosystemNPM, "lodash", "4.17.15", "/proj/package.json", 5)
			tt.mutate(&p)

			d := diagnosticFor(p, anchorSite(p))
			if got := string(d.Message.(protocol.String)); got != tt.wantMessage {
				t.Errorf("message = %q, want %q", got, tt.wantMessage)
			}
			if d.Severity != protocol.DiagnosticSeverityWarning {
				t.Errorf("severity = %v, want Warning", d.Severity)
			}
			if src, _ := d.Source.Get(); src != Name {
				t.Errorf("source = %q, want %q", src, Name)
			}
		})
	}
}

func TestToProtocolRangeIsZeroBased(t *testing.T) {
	// WholeLine takes a one-based line; the protocol range must be zero-based,
	// so line 14 in an editor is line 13 on the wire.
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
		p := &protocol.InitializeParams{RootURI: &rootURI}
		if got := workspaceRoot(p); got != "/from/rooturi" {
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
			name: "utf-16 when it is the only option",
			general: &protocol.GeneralClientCapabilities{PositionEncodings: []protocol.PositionEncodingKind{
				protocol.PositionEncodingKindUTF16,
			}},
			want: protocol.PositionEncodingKindUTF16,
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
