package lsp

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"go.lsp.dev/protocol"
)

// writeTree creates files under root. Keys are slash-separated relative paths;
// parent directories are created as needed.
func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", rel, err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
}

// relative converts absolute results back to slash-separated paths relative to
// root, so assertions stay readable and platform independent.
func relative(t *testing.T, root string, paths []string) []string {
	t.Helper()
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		rel, err := filepath.Rel(root, p)
		if err != nil {
			t.Fatalf("rel %s: %v", p, err)
		}
		out = append(out, filepath.ToSlash(rel))
	}
	slices.Sort(out)
	return out
}

func TestFindManifests(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{
			name:  "no manifests",
			files: map[string]string{"README.md": "", "src/index.js": ""},
			want:  []string{},
		},
		{
			name:  "manifest at the root",
			files: map[string]string{"package.json": "{}"},
			want:  []string{"package.json"},
		},
		{
			name: "manifests nested several levels down",
			files: map[string]string{
				"a/package.json":        "{}",
				"a/b/c/package.json":    "{}",
				"unrelated/notes.txt":   "",
				"a/b/c/package-lock.js": "",
			},
			want: []string{"a/b/c/package.json", "a/package.json"},
		},
		{
			name: "node_modules is skipped",
			files: map[string]string{
				"package.json":                        "{}",
				"node_modules/lodash/package.json":    "{}",
				"a/node_modules/express/package.json": "{}",
			},
			want: []string{"package.json"},
		},
		{
			name: "vcs and build directories are skipped",
			files: map[string]string{
				"package.json":        "{}",
				".git/package.json":   "{}",
				"target/package.json": "{}",
				"dist/package.json":   "{}",
				"vendor/package.json": "{}",
				".venv/package.json":  "{}",
			},
			want: []string{"package.json"},
		},
		{
			name: "hidden directories are skipped",
			files: map[string]string{
				"package.json":         "{}",
				".cache/package.json":  "{}",
				".github/package.json": "{}",
			},
			want: []string{"package.json"},
		},
		{
			name: "a directory named like the manifest is not a match",
			files: map[string]string{
				"package.json/placeholder": "",
				"real/package.json":        "{}",
			},
			want: []string{"real/package.json"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeTree(t, root, tt.files)

			got, err := findManifests(root, "package.json")
			if err != nil {
				t.Fatalf("findManifests: %v", err)
			}
			if diff := relative(t, root, got); !slices.Equal(diff, tt.want) {
				t.Errorf("findManifests() = %v, want %v", diff, tt.want)
			}
		})
	}
}

func TestFindManifestsRootItselfHiddenIsStillScanned(t *testing.T) {
	// The skip rules must not apply to the root. A user whose project lives in
	// a dotted directory still expects it scanned.
	parent := t.TempDir()
	root := filepath.Join(parent, ".config")
	writeTree(t, parent, map[string]string{".config/package.json": "{}"})

	got, err := findManifests(root, "package.json")
	if err != nil {
		t.Fatalf("findManifests: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %v, want the manifest inside the dotted root", got)
	}
}

func TestFindManifestsMissingRoot(t *testing.T) {
	// A root that does not exist is a real error, unlike an unreadable
	// subdirectory encountered mid-walk.
	if _, err := findManifests(filepath.Join(t.TempDir(), "absent"), "package.json"); err == nil {
		t.Error("expected an error for a missing root")
	}
}

func TestFindManifestsSkipsUnreadableDirectories(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permissions behave differently on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}

	// One unreadable directory must not cost the caller every other finding.
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"readable/package.json": "{}",
		"locked/package.json":   "{}",
	})
	locked := filepath.Join(root, "locked")
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	got, err := findManifests(root, "package.json")
	if err != nil {
		t.Fatalf("findManifests should not fail on an unreadable directory: %v", err)
	}
	if want := []string{"readable/package.json"}; !slices.Equal(relative(t, root, got), want) {
		t.Errorf("findManifests() = %v, want %v", relative(t, root, got), want)
	}
}

func TestNegotiatePositionEncodingWithoutGeneralCapabilities(t *testing.T) {
	// "general" is optional in the protocol and a minimal client may omit it.
	// Dereferencing it would crash the server during initialize.
	if got := negotiatePositionEncoding(&protocol.InitializeParams{}); got != protocol.PositionEncodingKindUTF16 {
		t.Errorf("negotiatePositionEncoding = %q, want utf-16", got)
	}
}
