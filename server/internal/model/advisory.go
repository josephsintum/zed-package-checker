package model

import "strings"

// maliciousIDPrefix marks advisories from the OpenSSF malicious-packages feed.
const maliciousIDPrefix = "MAL-"

// Severity is a coarse ranking. Ordered, so the maximum can be taken across a
// group of advisories.
type Severity int

// Severity levels, ascending. Unknown sorts lowest so an unscored advisory
// never outranks an assessed one.
const (
	SeverityUnknown Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// String returns the CVSS qualitative rating name.
func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "Low"
	case SeverityMedium:
		return "Medium"
	case SeverityHigh:
		return "High"
	case SeverityCritical:
		return "Critical"
	default:
		return "Unknown"
	}
}

// SeverityFromCVSS maps a base score to its CVSS v3.1 band.
//
// Zero maps to Unknown rather than "None": OSV advisories frequently carry no
// score, and the distinction buys us nothing. Out-of-range scores clamp rather
// than discard an otherwise valid advisory.
func SeverityFromCVSS(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0.0:
		return SeverityLow
	default:
		return SeverityUnknown
	}
}

// AffectedRange is a half-open version interval: at or after Introduced, before
// Fixed.
//
// Mirrors OSV rather than flattening to a single "fixed in", because an
// advisory can have disjoint ranges when a fix is backported — collapsing them
// wrongly flags versions on a patched older line.
type AffectedRange struct {
	// Introduced is the first affected version; "0" means from the beginning.
	Introduced string

	// Fixed is the first unaffected version, empty when no fix exists.
	Fixed string

	// LastAffected names the final bad version instead of the first good one.
	// At most one of Fixed and LastAffected is set.
	LastAffected string
}

// Affected records which versions of one package an advisory applies to.
type Affected struct {
	Package PackageKey

	// Ranges are version intervals, empty when Versions enumerates instead.
	Ranges []AffectedRange

	// Versions is an explicit list. A version here is affected regardless of
	// Ranges.
	Versions []string
}

// Advisory is a vulnerability or a report that a package is malicious.
type Advisory struct {
	// ID is the primary OSV identifier, e.g. "GHSA-p6mc-m468-83gw".
	ID string

	// Aliases are other identifiers, typically CVEs. EPSS and KEV are
	// CVE-keyed, so enrichment looks up through these.
	Aliases []string

	Summary string

	// Details is the full Markdown description, shown on hover.
	Details string

	// CVSSScore is the base score, zero when the advisory carries none.
	CVSSScore  float64
	CVSSVector string

	Affected   []Affected
	References []string
}

// Malicious reports whether the package is malicious rather than vulnerable.
// Derived from the ID so it cannot drift.
func (a Advisory) Malicious() bool {
	return strings.HasPrefix(a.ID, maliciousIDPrefix)
}

// Severity returns the qualitative severity. Malicious packages are always
// critical: "remove this now" does not scale with CVSS.
func (a Advisory) Severity() Severity {
	if a.Malicious() {
		return SeverityCritical
	}
	return SeverityFromCVSS(a.CVSSScore)
}

// URL returns the canonical OSV page, used as the diagnostic's
// codeDescription link.
func (a Advisory) URL() string {
	return "https://osv.dev/vulnerability/" + a.ID
}

// FixedVersionsFor returns the versions resolving this advisory for key.
//
// Advisory-local: picking one version that clears every advisory on a package
// needs ecosystem-aware ordering and belongs to the matcher.
func (a Advisory) FixedVersionsFor(key PackageKey) []string {
	var fixed []string
	for _, affected := range a.Affected {
		if affected.Package != key {
			continue
		}
		for _, r := range affected.Ranges {
			if r.Fixed != "" {
				fixed = append(fixed, r.Fixed)
			}
		}
	}
	return fixed
}
