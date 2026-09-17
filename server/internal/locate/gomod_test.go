package locate

import (
	"testing"
)

func TestGoModSpans(t *testing.T) {
	// Deliberately mixes a require block with a standalone require: the block
	// entry's line starts at the module path, the standalone one starts at the
	// `require` keyword, and the spans must come out the same either way.
	src := lines(
		`module example.com/fixture`,
		``,
		`go 1.21`,
		``,
		`require (`,
		"\tgithub.com/gin-gonic/gin v1.6.0",
		"\tgopkg.in/yaml.v2 v2.2.2 // indirect",
		`)`,
		``,
		`require golang.org/x/crypto v0.57.0`)

	got := GoMod([]byte(src), "/p/go.mod")

	tests := []struct {
		dep     string
		wantDec at
		wantVer at
	}{
		// A tab is one byte, so the module path starts at column 1.
		{
			dep:     "github.com/gin-gonic/gin",
			wantDec: at{line: 5, start: 1, end: 25},
			wantVer: at{line: 5, start: 26, end: 32},
		},
		{
			dep:     "gopkg.in/yaml.v2",
			wantDec: at{line: 6, start: 1, end: 17},
			wantVer: at{line: 6, start: 18, end: 24},
		},
		{
			dep:     "golang.org/x/crypto",
			wantDec: at{line: 9, start: 8, end: 27},
			wantVer: at{line: 9, start: 28, end: 35},
		},
	}

	for _, tt := range tests {
		t.Run(tt.dep, func(t *testing.T) {
			anchor, ok := got[tt.dep]
			if !ok {
				t.Fatalf("%q not located", tt.dep)
			}
			tt.wantDec.check(t, "declaration", anchor.Declaration.Range)
			if anchor.Version == nil {
				t.Fatal("no version span")
			}
			tt.wantVer.check(t, "version", anchor.Version.Range)
		})
	}
}

func TestGoModToolchainAnchorsOnItsVersion(t *testing.T) {
	// "stdlib" appears nowhere in the file, so the version in the go directive
	// is the only token worth underlining.
	src := lines(
		`module example.com/fixture`,
		``,
		`go 1.21`)

	anchor, ok := GoMod([]byte(src), "/p/go.mod")[GoModToolchain]
	if !ok {
		t.Fatal("the toolchain was not located")
	}
	at{line: 2, start: 3, end: 7}.check(t, "declaration", anchor.Declaration.Range)
	if anchor.Version == nil {
		t.Fatal("no version span")
	}
	at{line: 2, start: 3, end: 7}.check(t, "version", anchor.Version.Range)
}

func TestGoModModuleItselfIsNotADependency(t *testing.T) {
	// The module directive names this project, not something it depends on.
	got := GoMod([]byte(lines(`module example.com/fixture`, ``, `go 1.21`)), "/p/go.mod")
	if _, ok := got["example.com/fixture"]; ok {
		t.Error("the module's own path was located as a dependency")
	}
}

func TestMalformedGoModLocatesNothing(t *testing.T) {
	if got := GoMod([]byte("module\n\nrequire ((("), "/p/go.mod"); got != nil {
		t.Errorf("a malformed go.mod produced %v, want nothing", got)
	}
}
