package locate

import (
	"strings"
	"testing"
)

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
