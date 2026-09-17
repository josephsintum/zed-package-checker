package lsp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSummaryAnchorLine(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		contents string
		want     int
	}{
		{
			name:     "go.mod module directive",
			file:     "go.mod",
			contents: "// a leading comment\n\nmodule example.com/thing\n\ngo 1.27\n",
			want:     3,
		},
		{
			name:     "package.json name field",
			file:     "package.json",
			contents: "{\n  \"private\": true,\n  \"name\": \"thing\",\n  \"version\": \"1.0.0\"\n}\n",
			want:     3,
		},
		{
			name:     "Cargo.toml name key",
			file:     "Cargo.toml",
			contents: "[package]\nname = \"thing\"\nversion = \"0.1.0\"\n",
			want:     2,
		},
		{
			name:     "pyproject.toml name key",
			file:     "pyproject.toml",
			contents: "[build-system]\nrequires = [\"hatchling\"]\n\n[project]\nname = \"thing\"\n",
			want:     5,
		},
		{
			name:     "a name-like key that is not the name",
			file:     "Cargo.toml",
			contents: "[package]\nnamespace = \"no\"\nname = \"thing\"\n",
			want:     3,
		},
		{
			name:     "manifest without its marker falls back",
			file:     "go.mod",
			contents: "go 1.27\n",
			want:     1,
		},
		{
			name:     "a nested name is not the manifest's own",
			file:     "package.json",
			contents: "{\n  \"author\": {\n    \"name\": \"Jane\"\n  },\n  \"name\": \"thing\"\n}\n",
			want:     5,
		},
		{
			name:     "a minified manifest is all on line 1",
			file:     "package.json",
			contents: `{"name":"thing","version":"1.0.0","dependencies":{"lodash":"^4.17.15"}}`,
			want:     1,
		},
		{
			name:     "a lockfile has no marker",
			file:     "package-lock.json",
			contents: "{\n  \"name\": \"thing\"\n}\n",
			want:     1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tt.file)
			if err := os.WriteFile(path, []byte(tt.contents), 0o644); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			if got := summaryAnchorLine(path); got != tt.want {
				t.Errorf("summaryAnchorLine = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestSummaryAnchorLineOnAnUnreadableFile(t *testing.T) {
	// The manifest was on disk when it was scanned; by the time diagnostics are
	// rendered it may not be. A summary on line 1 beats no diagnostics at all.
	missing := filepath.Join(t.TempDir(), "go.mod")
	if got := summaryAnchorLine(missing); got != 1 {
		t.Errorf("summaryAnchorLine on a missing file = %d, want 1", got)
	}
}
