package locate

import (
	"strings"

	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// Requirements returns the declaration and version spans for every dependency
// in a requirements.txt, keyed by the normalised package name.
//
// The format has no parser worth the name: it is a line per requirement, with
// comments, environment markers, extras and continuations layered on. Only the
// parts that carry a position are read here, and anything unrecognised is
// skipped rather than guessed at — a missing span costs a tighter squiggle, a
// wrong one points at the wrong dependency.
func Requirements(src []byte, path string) map[string]model.Anchor {
	lines := newLineIndex(src)
	out := make(map[string]model.Anchor)

	offset := 0
	for raw := range strings.SplitSeq(string(src), "\n") {
		start := offset
		offset += len(raw) + 1 // the newline split removed

		req, ok := requirementOn(raw)
		if !ok {
			continue
		}

		name := NormalisePyPI(raw[req.nameStart:req.nameEnd])
		if _, taken := out[name]; taken {
			// A name repeated across lines keeps the first, matching the way
			// pip resolves a file top to bottom.
			continue
		}

		anchor := model.Anchor{
			Declaration: model.Site{
				Path:  path,
				Range: lines.span(start+req.nameStart, start+req.nameEnd),
			},
		}
		if req.versionStart >= 0 {
			anchor.Version = &model.Site{
				Path:  path,
				Range: lines.span(start+req.versionStart, start+req.versionEnd),
			}
		}
		out[name] = anchor
	}

	if len(out) == 0 {
		return nil
	}
	return out
}

// requirement is the span of one line's name and version, relative to the line.
type requirement struct {
	nameStart, nameEnd       int
	versionStart, versionEnd int
}

// requirementOn finds the name and version within a single line.
func requirementOn(line string) (requirement, bool) {
	// Everything from an unquoted '#' is a comment, and a line that is only a
	// comment has nothing to point at.
	if hash := strings.IndexByte(line, '#'); hash >= 0 {
		line = line[:hash]
	}
	// An environment marker ("; python_version < '3.9'") qualifies the
	// requirement without being part of it.
	if semi := strings.IndexByte(line, ';'); semi >= 0 {
		line = line[:semi]
	}

	nameStart := 0
	for nameStart < len(line) && isSpace(line[nameStart]) {
		nameStart++
	}
	if nameStart == len(line) {
		return requirement{}, false
	}
	// Options ("-r other.txt", "--index-url ...") and URL requirements are not
	// declarations of a named version, so there is nothing to anchor.
	if line[nameStart] == '-' {
		return requirement{}, false
	}

	nameEnd := nameStart
	for nameEnd < len(line) && isNameByte(line[nameEnd]) {
		nameEnd++
	}
	if nameEnd == nameStart {
		return requirement{}, false
	}

	req := requirement{nameStart: nameStart, nameEnd: nameEnd, versionStart: -1}

	// Skip extras ("requests[socks]") and any space before the specifier.
	rest := nameEnd
	if rest < len(line) && line[rest] == '[' {
		if close := strings.IndexByte(line[rest:], ']'); close >= 0 {
			rest += close + 1
		}
	}
	for rest < len(line) && isSpace(line[rest]) {
		rest++
	}

	// A version specifier starts with a comparison operator. Anything else —
	// "package @ url", a bare name — has no version written down.
	opEnd := rest
	for opEnd < len(line) && isOperatorByte(line[opEnd]) {
		opEnd++
	}
	if opEnd == rest {
		return req, true
	}

	versionStart := opEnd
	for versionStart < len(line) && isSpace(line[versionStart]) {
		versionStart++
	}
	versionEnd := len(line)
	for versionEnd > versionStart && isSpace(line[versionEnd-1]) {
		versionEnd--
	}
	if versionEnd > versionStart {
		req.versionStart, req.versionEnd = versionStart, versionEnd
	}
	return req, true
}

// NormalisePyPI applies PEP 503 name normalisation: lowercase, with runs of
// "-", "_" and "." collapsed to a single "-".
//
// Exported because the same spelling has to be recognised on both sides — the
// extractor reports a normalised name while the file may say "Flask_SQLAlchemy".
func NormalisePyPI(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	separator := false
	for i := range len(name) {
		c := name[i]
		if c == '-' || c == '_' || c == '.' {
			separator = true
			continue
		}
		if separator && b.Len() > 0 {
			b.WriteByte('-')
		}
		separator = false
		b.WriteByte(lower(c))
	}
	return b.String()
}

func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\r' }

// isNameByte reports whether c can appear in a PyPI distribution name.
func isNameByte(c byte) bool {
	return c >= 'a' && c <= 'z' ||
		c >= 'A' && c <= 'Z' ||
		c >= '0' && c <= '9' ||
		c == '-' || c == '_' || c == '.'
}

// isOperatorByte reports whether c is part of a PEP 440 comparison operator.
func isOperatorByte(c byte) bool {
	return c == '=' || c == '<' || c == '>' || c == '!' || c == '~'
}
