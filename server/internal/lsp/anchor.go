package lsp

import (
	"os"
	"path/filepath"
	"strings"
)

// summaryMarkers recognise the declaration every manifest of a given kind must
// contain, keyed by file name.
//
// Only manifests appear here. A lockfile has no comparable line — nothing in
// package-lock.json is both mandatory and meaningful to a reader — so those
// fall back to line 1, which is what they would have had anyway.
var summaryMarkers = map[string]func(trimmed string, depth int) bool{
	"go.mod": func(s string, _ int) bool { return strings.HasPrefix(s, "module ") },

	// Depth 1 is the object the file itself is: a "name" inside "author" or
	// "repository" is somebody else's.
	"package.json": func(s string, depth int) bool {
		return depth == 1 && strings.HasPrefix(s, `"name"`)
	},

	// TOML: `name = "thing"`, under [package] or [project]. The first such key
	// in either file is the package's own name.
	"Cargo.toml":     tomlName,
	"pyproject.toml": tomlName,
}

func tomlName(s string, _ int) bool {
	rest, ok := strings.CutPrefix(s, "name")
	return ok && strings.HasPrefix(strings.TrimSpace(rest), "=")
}

// summaryAnchorLine returns the one-based line the summary diagnostic belongs
// on, defaulting to 1 when there is nothing better.
//
// Line 1 of a manifest is usually a brace or a comment, so a summary pinned
// there reads as unattached to anything and moves the moment the file is
// reformatted. Anchoring on the declaration the file must contain — the module
// directive, the name field — keeps it on a line that means something and that
// a formatter will not relocate.
//
// Every failure falls back to line 1: a summary on the wrong line is a
// cosmetic problem, and refusing to publish one over it would not be.
func summaryAnchorLine(path string) int {
	marker, ok := summaryMarkers[filepath.Base(path)]
	if !ok {
		return 1
	}

	// Read whole rather than scan: only the four manifests above reach this and
	// all of them are small, which avoids both a line-length ceiling on a
	// minified file and a scan error there is nothing useful to do about.
	content, err := os.ReadFile(path)
	if err != nil {
		return 1
	}

	line, depth := 1, 0
	for text := range strings.Lines(string(content)) {
		trimmed := strings.TrimSpace(text)
		// Depth before the line, so a key on the same line as the brace that
		// opens its object is not counted as being inside it.
		if marker(trimmed, depth+opensBefore(trimmed)) {
			return line
		}
		depth += braceDelta(trimmed)
		line++
	}
	return 1
}

// opensBefore counts the objects a line opens before its first key, which is
// what puts `{"name": ...}` on a minified first line at depth 1.
func opensBefore(line string) int {
	opened := 0
	for _, r := range line {
		if r == '"' {
			break
		}
		if r == '{' {
			opened++
		}
	}
	return opened
}

// braceDelta is a deliberately naive nesting count: it does not exclude braces
// inside string values. A manifest whose values contain braces would anchor the
// summary somewhere arbitrary, which is the cost this file already accepts
// everywhere else.
func braceDelta(line string) int {
	return strings.Count(line, "{") - strings.Count(line, "}")
}
