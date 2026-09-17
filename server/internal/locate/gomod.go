package locate

import (
	"bytes"

	"golang.org/x/mod/modfile"

	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// GoModToolchain is the name the Go extractor reports the toolchain under.
//
// It is not a module and is written nowhere in go.mod, so its declaration
// anchors on the version in the `go` directive — the only thing on that line a
// reader can act on.
const GoModToolchain = "stdlib"

// GoMod returns the declaration and version spans for every module a go.mod
// requires, keyed by module path, plus the toolchain under GoModToolchain.
//
// A file that will not parse yields nothing rather than an error: the caller
// already holds a whole-line anchor that works.
func GoMod(src []byte, path string) map[string]model.Anchor {
	f, err := modfile.Parse(path, src, nil)
	if err != nil {
		return nil
	}

	lines := newLineIndex(src)
	out := make(map[string]model.Anchor)

	for _, r := range f.Require {
		if r.Syntax == nil {
			continue
		}
		if a, ok := spanOn(src, lines, path, r.Syntax, r.Mod.Path, r.Mod.Version); ok {
			out[r.Mod.Path] = a
		}
	}

	if f.Go != nil && f.Go.Syntax != nil {
		// Declaration and version are the same token here: "go 1.21" names no
		// package, so pointing at the keyword would underline nothing useful.
		if a, ok := spanOn(src, lines, path, f.Go.Syntax, f.Go.Version, f.Go.Version); ok {
			out[GoModToolchain] = a
		}
	}

	if len(out) == 0 {
		return nil
	}
	return out
}

// spanOn locates decl, and then version after it, within one line of the file.
//
// The tokens are searched for rather than offset from the line's start: a
// require inside a block starts at the module path, while a standalone one
// starts at the `require` keyword, and only searching handles both.
func spanOn(src []byte, lines *lineIndex, path string, line *modfile.Line, decl, version string) (model.Anchor, bool) {
	start, end := line.Span()
	if start.Byte < 0 || end.Byte > len(src) || start.Byte >= end.Byte {
		return model.Anchor{}, false
	}
	segment := src[start.Byte:end.Byte]

	declAt := bytes.Index(segment, []byte(decl))
	if decl == "" || declAt < 0 {
		return model.Anchor{}, false
	}
	declStart := start.Byte + declAt
	declEnd := declStart + len(decl)

	anchor := model.Anchor{
		Declaration: model.Site{Path: path, Range: lines.span(declStart, declEnd)},
	}

	switch version {
	case "":
	case decl:
		// The `go` directive, where the two are one token.
		anchor.Version = &model.Site{Path: path, Range: anchor.Declaration.Range}
	default:
		// Searched from after the declaration, so a version that also appears
		// inside the module path cannot be matched in the wrong place.
		if at := bytes.Index(segment[declAt+len(decl):], []byte(version)); at >= 0 {
			versionStart := declEnd + at
			anchor.Version = &model.Site{
				Path:  path,
				Range: lines.span(versionStart, versionStart+len(version)),
			}
		}
	}
	return anchor, true
}
