package locate

import (
	"strings"

	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// cargoSections are the tables that declare dependencies, in the order their
// declarations are preferred when a crate appears in more than one.
//
// Matched on the last dotted component, so a target-specific table such as
// [target.'cfg(unix)'.dependencies] is recognised too.
var cargoSections = []string{"dependencies", "build-dependencies", "dev-dependencies"}

// CargoToml returns the declaration and version spans for every dependency a
// Cargo.toml declares, keyed by crate name.
//
// Line-based rather than parsed: a TOML decoder gives values without telling
// you where they were written, and a position is the entire point here. Only
// the shapes that carry one are read, and anything else is left with the
// whole-line anchor the caller already has.
func CargoToml(src []byte, path string) map[string]model.Anchor {
	lines := newLineIndex(src)
	found := map[string][]cargoDep{}

	section := ""
	offset := 0
	for _, raw := range strings.Split(string(src), "\n") {
		start := offset
		offset += len(raw) + 1

		line := trimComment(raw)
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "[") {
			section = cargoSection(trimmed)
			continue
		}
		if section == "" {
			continue
		}
		if dep, ok := cargoDepOn(line); ok {
			dep.offset = start
			found[section] = append(found[section], dep)
		}
	}

	out := make(map[string]model.Anchor)
	for _, name := range cargoSections {
		for _, dep := range found[name] {
			if _, taken := out[dep.name]; taken {
				continue
			}
			anchor := model.Anchor{
				Declaration: model.Site{
					Path:  path,
					Range: lines.span(dep.offset+dep.nameStart, dep.offset+dep.nameEnd),
				},
			}
			if dep.versionStart >= 0 {
				anchor.Version = &model.Site{
					Path:  path,
					Range: lines.span(dep.offset+dep.versionStart, dep.offset+dep.versionEnd),
				}
			}
			out[dep.name] = anchor
		}
	}

	if len(out) == 0 {
		return nil
	}
	return out
}

// cargoDep is one declaration and where its parts sit relative to its line.
type cargoDep struct {
	name                     string
	offset                   int
	nameStart, nameEnd       int
	versionStart, versionEnd int
}

// cargoSection returns the dependency table a header names, or "".
func cargoSection(header string) string {
	name := strings.Trim(header, "[]")
	if dot := strings.LastIndexByte(name, '.'); dot >= 0 {
		name = name[dot+1:]
	}
	name = strings.TrimSpace(name)
	for _, section := range cargoSections {
		if name == section {
			return section
		}
	}
	return ""
}

// cargoDepOn reads one `crate = ...` line.
//
// Both spellings are handled: a bare `time = "0.1.44"` and an inline table
// `serde = { version = "1.0", features = [...] }`. A renamed dependency —
// `fast = { package = "real-crate" }` — is keyed by the crate actually
// depended on, since that is what an advisory names.
func cargoDepOn(line string) (cargoDep, bool) {
	eq := strings.IndexByte(line, '=')
	if eq < 0 {
		return cargoDep{}, false
	}

	nameStart := 0
	for nameStart < eq && isSpace(line[nameStart]) {
		nameStart++
	}
	nameEnd := eq
	for nameEnd > nameStart && isSpace(line[nameEnd-1]) {
		nameEnd--
	}
	if nameEnd <= nameStart {
		return cargoDep{}, false
	}
	key := strings.Trim(line[nameStart:nameEnd], `"'`)
	if key == "" || strings.ContainsAny(key, "[]{} ") {
		return cargoDep{}, false
	}

	dep := cargoDep{name: key, nameStart: nameStart, nameEnd: nameEnd, versionStart: -1}
	value := line[eq+1:]

	if start, end, ok := quotedAfter(value, "version"); ok {
		dep.versionStart, dep.versionEnd = eq+1+start, eq+1+end
	} else if start, end, ok := firstQuoted(value); ok && !strings.Contains(value, "{") {
		dep.versionStart, dep.versionEnd = eq+1+start, eq+1+end
	}
	if start, end, ok := quotedAfter(value, "package"); ok {
		dep.name = value[start:end]
	}
	return dep, true
}

// quotedAfter finds the quoted value of `key = "..."` within an inline table.
func quotedAfter(s, key string) (start, end int, ok bool) {
	at := strings.Index(s, key)
	for at >= 0 {
		rest := s[at+len(key):]
		trimmed := strings.TrimLeft(rest, " \t")
		if strings.HasPrefix(trimmed, "=") {
			offset := at + len(key) + (len(rest) - len(trimmed)) + 1
			if a, b, found := firstQuoted(s[offset:]); found {
				return offset + a, offset + b, true
			}
			return 0, 0, false
		}
		next := strings.Index(s[at+1:], key)
		if next < 0 {
			return 0, 0, false
		}
		at += next + 1
	}
	return 0, 0, false
}

// firstQuoted returns the contents of the first quoted string in s.
func firstQuoted(s string) (start, end int, ok bool) {
	open := strings.IndexAny(s, `"'`)
	if open < 0 {
		return 0, 0, false
	}
	quote := s[open]
	close := strings.IndexByte(s[open+1:], quote)
	if close < 0 {
		return 0, 0, false
	}
	return open + 1, open + 1 + close, true
}

// trimComment drops a trailing TOML comment, leaving one inside a string alone.
func trimComment(line string) string {
	inQuote := byte(0)
	for i := range len(line) {
		c := line[i]
		switch {
		case inQuote != 0:
			if c == inQuote {
				inQuote = 0
			}
		case c == '"' || c == '\'':
			inQuote = c
		case c == '#':
			return line[:i]
		}
	}
	return line
}
