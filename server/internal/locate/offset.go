package locate

import (
	"sort"

	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// Encoding is the unit a column is counted in, negotiated at initialize.
type Encoding int

const (
	// UTF8 counts bytes. This package emits columns in these units, because a
	// manifest is parsed as bytes and nothing has to be converted.
	UTF8 Encoding = iota

	// UTF16 counts UTF-16 code units. The protocol's default, and the fallback
	// for a client that does not offer anything better.
	UTF16
)

// lineIndex turns byte offsets into zero-based line and column positions.
type lineIndex struct {
	src    []byte
	starts []int // byte offset where each line begins
}

func newLineIndex(src []byte) *lineIndex {
	starts := []int{0}
	for i, b := range src {
		if b == '\n' {
			starts = append(starts, i+1)
		}
	}
	return &lineIndex{src: src, starts: starts}
}

// position converts a byte offset to a zero-based position in UTF-8 columns.
//
// A CRLF file needs no special handling: the carriage return sits at the end of
// a line, after everything this package points at.
func (li *lineIndex) position(offset int) model.Position {
	if offset < 0 {
		offset = 0
	}
	// starts[0] is 0 and offset is non-negative, so the predicate is false at
	// index 0 and Search returns at least 1. The line is therefore never
	// negative and needs no floor.
	line := sort.Search(len(li.starts), func(i int) bool { return li.starts[i] > offset }) - 1
	return model.Position{Line: line, Column: offset - li.starts[line]}
}

func (li *lineIndex) span(start, end int) model.Range {
	return model.Range{Start: li.position(start), End: li.position(end)}
}

// Column converts a byte offset within one line into a column in enc's units.
//
// The LSP layer owns the encoding, since it is the only part that saw the
// negotiation; this is the arithmetic it needs to apply the answer. A rune
// outside the basic multilingual plane is one byte sequence but two UTF-16
// code units, which is the whole reason the two disagree.
func Column(line []byte, byteOffset int, enc Encoding) int {
	if byteOffset > len(line) {
		byteOffset = len(line)
	}
	if byteOffset < 0 {
		byteOffset = 0
	}
	if enc == UTF8 {
		return byteOffset
	}

	units := 0
	for _, r := range string(line[:byteOffset]) {
		units++
		if r > 0xFFFF {
			units++
		}
	}
	return units
}
