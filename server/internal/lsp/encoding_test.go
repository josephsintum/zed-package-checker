package lsp

import (
	"os"
	"path/filepath"
	"testing"

	"go.lsp.dev/protocol"
)

func TestToUTF16Columns(t *testing.T) {
	// "café " is five runes but six bytes, so a span starting after it sits at
	// byte column 6 and UTF-16 column 5. Getting this wrong puts the squiggle
	// one character off for every client that declined UTF-8.
	path := filepath.Join(t.TempDir(), "package.json")
	if err := os.WriteFile(path, []byte("café \"lodash\"\nplain ascii\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	diagnostics := []protocol.Diagnostic{
		{Range: protocol.Range{
			Start: protocol.Position{Line: 0, Character: 6},
			End:   protocol.Position{Line: 0, Character: 13},
		}},
		{Range: protocol.Range{
			Start: protocol.Position{Line: 1, Character: 6},
			End:   protocol.Position{Line: 1, Character: 11},
		}},
	}
	toUTF16Columns(path, diagnostics)

	if got := diagnostics[0].Range.Start.Character; got != 5 {
		t.Errorf("start column = %d, want 5", got)
	}
	if got := diagnostics[0].Range.End.Character; got != 12 {
		t.Errorf("end column = %d, want 12", got)
	}
	// An all-ASCII line is the same number in both encodings.
	if got := diagnostics[1].Range.Start.Character; got != 6 {
		t.Errorf("ascii start column = %d, want it unchanged at 6", got)
	}
}

func TestToUTF16ColumnsLeavesAnUnreadableFileAlone(t *testing.T) {
	// Byte columns are right on an ASCII line and close everywhere else;
	// dropping the diagnostic would not be.
	diagnostics := []protocol.Diagnostic{
		{Range: protocol.Range{Start: protocol.Position{Line: 0, Character: 4}}},
	}
	toUTF16Columns(filepath.Join(t.TempDir(), "gone.json"), diagnostics)

	if got := diagnostics[0].Range.Start.Character; got != 4 {
		t.Errorf("column = %d, want it left at 4", got)
	}
}
