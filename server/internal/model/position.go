package model

// Position is a location in a file.
//
// Both fields are ZERO-based, matching LSP, while extractors report one-based
// lines. Use PositionFromOneBasedLine so the conversion happens exactly once
// and cannot be applied twice.
//
// Column units follow the position encoding negotiated at initialize — UTF-8
// bytes when the client supports it, UTF-16 otherwise. Only the LSP layer cares.
type Position struct {
	Line   int
	Column int
}

// PositionFromOneBasedLine converts an extractor's line number to a zero-based
// Position. Lines below 1 clamp to the first line, since extractors report 0
// when they could not determine one.
func PositionFromOneBasedLine(line int) Position {
	if line < 1 {
		return Position{Line: 0, Column: 0}
	}
	return Position{Line: line - 1, Column: 0}
}

// Range is a half-open span: Start inclusive, End exclusive.
type Range struct {
	Start Position
	End   Position
}

// WholeLine returns a Range covering a full one-based line, ending at the start
// of the next — how LSP says "this entire line" without knowing its length.
// Used before locate narrows the span to the dependency name.
func WholeLine(oneBasedLine int) Range {
	start := PositionFromOneBasedLine(oneBasedLine)
	return Range{
		Start: start,
		End:   Position{Line: start.Line + 1, Column: 0},
	}
}

// Site is a range in a specific file. Path is always absolute: relative paths
// become URIs the client silently ignores.
type Site struct {
	Path  string
	Range Range
}

// Anchor describes where a dependency is declared and where its version is
// written.
//
// Two separate Sites because they can genuinely live in different files — a
// dependency in package.json with its resolved version in package-lock.json.
// Conflating them is the bug JetBrains shipped.
type Anchor struct {
	// Declaration is where the dependency is named. Diagnostics go here.
	Declaration Site

	// Version is where the version string is written, nil when it is not
	// textually present. A version-bump code action requires it.
	Version *Site
}
