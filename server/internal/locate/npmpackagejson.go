package locate

import (
	"bytes"
	"encoding/json"
	"io"
	"slices"

	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// sections are the package.json keys that declare dependencies, in the order
// their declarations are preferred.
//
// A package can appear in more than one — commonly "dependencies" and
// "devDependencies" during a migration — and the diagnostic must land on one
// of them. Production wins: it is the declaration that ships.
var sections = []string{
	"dependencies",
	"optionalDependencies",
	"peerDependencies",
	"devDependencies",
}

// PackageJSON returns the declaration and version spans for every dependency in
// a package.json, keyed by dependency name.
//
// A manifest that will not parse yields nothing rather than an error: the
// caller already has a whole-line anchor that works, and a half-written file
// being saved is an ordinary event rather than a failure.
func PackageJSON(src []byte, path string) map[string]model.Anchor {
	pairs, ok := scanSections(src)
	if !ok || len(pairs) == 0 {
		return nil
	}

	lines := newLineIndex(src)
	out := make(map[string]model.Anchor, len(pairs))
	for _, p := range pairs {
		if _, taken := out[p.name]; taken {
			// An earlier section already claimed this name, and sections are
			// visited in preference order.
			continue
		}
		anchor := model.Anchor{
			Declaration: model.Site{Path: path, Range: lines.span(p.nameStart, p.nameEnd)},
		}
		if p.versionStart >= 0 {
			anchor.Version = &model.Site{
				Path:  path,
				Range: lines.span(p.versionStart, p.versionEnd),
			}
		}
		out[p.name] = anchor
	}
	return out
}

// pair is one dependency declaration and the byte span of its two halves.
type pair struct {
	name                     string
	nameStart, nameEnd       int
	versionStart, versionEnd int
}

// scanSections walks the manifest and records every dependency declaration,
// visiting sections in preference order rather than file order.
//
// The boolean reports whether the document parsed. A false means the caller
// keeps the anchors it already has.
func scanSections(src []byte) ([]pair, bool) {
	found := map[string][]pair{}

	dec := json.NewDecoder(bytes.NewReader(src))
	var (
		depth   int
		section string
		key     bool // the next string token in this object is a key
		prev    int
	)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, false
		}
		end := int(dec.InputOffset())

		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				depth++
				key = true
			case '}':
				depth--
				key = depth == 1
				if depth <= 1 {
					section = ""
				}
			case '[':
				key = false
			case ']':
				key = depth >= 1
			}
		case string:
			start := quoteAt(src, prev)
			switch {
			case depth == 1 && key:
				// A top-level key: the section this value belongs to.
				section = t
			case depth == 2 && key && isSection(section):
				found[section] = append(found[section], pair{
					name:         t,
					nameStart:    start + 1,
					nameEnd:      end - 1,
					versionStart: -1,
				})
			case depth == 2 && !key && isSection(section):
				if n := len(found[section]); n > 0 {
					found[section][n-1].versionStart = start + 1
					found[section][n-1].versionEnd = end - 1
				}
			}
			if depth >= 1 {
				key = !key
			}
		default:
			// A number, bool or null value; the next token is a key again.
			if depth >= 1 {
				key = true
			}
		}
		prev = end
	}

	if depth != 0 {
		// The document ended inside an object: a file caught mid-save. Token
		// reports this as a clean EOF, so the unclosed depth is the only
		// evidence that what was read is a fragment rather than a manifest.
		return nil, false
	}

	var out []pair
	for _, name := range sections {
		out = append(out, found[name]...)
	}
	return out, true
}

func isSection(name string) bool {
	return slices.Contains(sections, name)
}

// quoteAt returns the offset of the first double quote at or after from.
//
// Only whitespace and structural punctuation separate one token from the next,
// so the first quote after the previous token's end opens this one. Working
// forwards rather than backwards from the closing quote avoids having to decide
// whether a quote was escaped.
func quoteAt(src []byte, from int) int {
	if i := bytes.IndexByte(src[from:], '"'); i >= 0 {
		return from + i
	}
	return from
}
