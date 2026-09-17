package locate

import (
	"strings"
	"testing"

	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// lines joins with \n and a trailing newline, so a test's literal layout is
// exactly the bytes under test.
func lines(l ...string) string { return strings.Join(l, "\n") + "\n" }

// at is the expected span of one token on one line, in zero-based columns.
type at struct {
	line       int
	start, end int
}

func (a at) check(t *testing.T, what string, got model.Range) {
	t.Helper()
	want := model.Range{
		Start: model.Position{Line: a.line, Column: a.start},
		End:   model.Position{Line: a.line, Column: a.end},
	}
	if got != want {
		t.Errorf("%s = %+v, want %+v", what, got, want)
	}
}

func TestPackageJSONSpans(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		dep     string
		wantDec at
		wantVer at
	}{
		{
			name: "a plain dependency",
			src: lines(
				`{`,
				`  "name": "x",`,
				`  "dependencies": {`,
				`    "lodash": "^4.17.0"`,
				`  }`,
				`}`),
			dep:     "lodash",
			wantDec: at{line: 3, start: 5, end: 11},
			wantVer: at{line: 3, start: 15, end: 22},
		},
		{
			name: "a scoped name keeps its scope",
			src: lines(
				`{`,
				`  "dependencies": {`,
				`    "@babel/core": "7.0.0"`,
				`  }`,
				`}`),
			dep:     "@babel/core",
			wantDec: at{line: 2, start: 5, end: 16},
			wantVer: at{line: 2, start: 20, end: 25},
		},
		{
			name: "a dev dependency is found",
			src: lines(
				`{`,
				`  "devDependencies": {`,
				`    "jest": "29.0.0"`,
				`  }`,
				`}`),
			dep:     "jest",
			wantDec: at{line: 2, start: 5, end: 9},
			wantVer: at{line: 2, start: 13, end: 19},
		},
		{
			name: "multi-byte text earlier in the file does not shift columns",
			src: lines(
				`{`,
				`  "description": "café ☕ 𝄞",`,
				`  "dependencies": {`,
				`    "lodash": "^4.17.0"`,
				`  }`,
				`}`),
			dep:     "lodash",
			wantDec: at{line: 3, start: 5, end: 11},
			wantVer: at{line: 3, start: 15, end: 22},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PackageJSON([]byte(tt.src), "/p/package.json")
			anchor, ok := got[tt.dep]
			if !ok {
				t.Fatalf("%q not located; got %d entries", tt.dep, len(got))
			}
			if anchor.Declaration.Path != "/p/package.json" {
				t.Errorf("path = %q, want the manifest's", anchor.Declaration.Path)
			}
			tt.wantDec.check(t, "declaration", anchor.Declaration.Range)
			if anchor.Version == nil {
				t.Fatal("no version span")
			}
			tt.wantVer.check(t, "version", anchor.Version.Range)
		})
	}
}

func TestCRLFDoesNotShiftSpans(t *testing.T) {
	// A carriage return sits at the end of a line, after everything located
	// here, so the columns must match the LF layout exactly.
	src := strings.Join([]string{
		`{`,
		`  "dependencies": {`,
		`    "lodash": "^4.17.0"`,
		`  }`,
		`}`,
	}, "\r\n")

	anchor, ok := PackageJSON([]byte(src), "/p/package.json")["lodash"]
	if !ok {
		t.Fatal("lodash not located in a CRLF manifest")
	}
	at{line: 2, start: 5, end: 11}.check(t, "declaration", anchor.Declaration.Range)
	at{line: 2, start: 15, end: 22}.check(t, "version", anchor.Version.Range)
}

func TestProductionWinsOverDev(t *testing.T) {
	// A package migrating between sections appears in both. The diagnostic has
	// to land on one, and the production declaration is the one that ships.
	src := lines(
		`{`,
		`  "dependencies": {`,
		`    "lodash": "^4.17.0"`,
		`  },`,
		`  "devDependencies": {`,
		`    "lodash": "^3.0.0"`,
		`  }`,
		`}`)

	anchor := PackageJSON([]byte(src), "/p/package.json")["lodash"]
	at{line: 2, start: 5, end: 11}.check(t, "declaration", anchor.Declaration.Range)
}

func TestNonDependencySectionsAreIgnored(t *testing.T) {
	src := lines(
		`{`,
		`  "scripts": {`,
		`    "lodash": "echo not a dependency"`,
		`  },`,
		`  "engines": {`,
		`    "node": ">=18"`,
		`  }`,
		`}`)

	if got := PackageJSON([]byte(src), "/p/package.json"); len(got) != 0 {
		t.Errorf("located %d entries in a manifest with no dependencies: %v", len(got), got)
	}
}

func TestMalformedManifestLocatesNothing(t *testing.T) {
	// Half-written files are ordinary — the editor saves mid-edit. The caller
	// keeps the whole-line anchor it already has.
	if got := PackageJSON([]byte(`{"dependencies": {`), "/p/package.json"); got != nil {
		t.Errorf("a truncated manifest produced %v, want nothing", got)
	}
}

func TestColumn(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		byteOffset  int
		utf8, utf16 int
	}{
		{name: "ascii", line: `  "lodash"`, byteOffset: 9, utf8: 9, utf16: 9},
		{name: "two-byte rune", line: `"café"`, byteOffset: 6, utf8: 6, utf16: 5},
		{name: "three-byte rune", line: `"a☕"`, byteOffset: 5, utf8: 5, utf16: 3},
		// Outside the basic multilingual plane: one rune, two UTF-16 units.
		{name: "surrogate pair", line: `"𝄞"`, byteOffset: 5, utf8: 5, utf16: 3},
		{name: "past the end clamps", line: `ab`, byteOffset: 99, utf8: 2, utf16: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Column([]byte(tt.line), tt.byteOffset, UTF8); got != tt.utf8 {
				t.Errorf("UTF8 column = %d, want %d", got, tt.utf8)
			}
			if got := Column([]byte(tt.line), tt.byteOffset, UTF16); got != tt.utf16 {
				t.Errorf("UTF16 column = %d, want %d", got, tt.utf16)
			}
		})
	}
}
