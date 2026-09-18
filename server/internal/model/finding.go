package model

import (
	"slices"
	"time"
)

// Finding is one vulnerable or malicious package with everything needed to
// report it.
//
// Grouped per package rather than per advisory: one dependency often carries
// several advisories, and a squiggle each makes the line unreadable.
type Finding struct {
	Package Package

	// Advisories affecting this version. Always at least one.
	Advisories []Advisory

	// Evidence is where extraction found the package. Always set, and the
	// fallback anchor when Declared is nil.
	Evidence Site

	// Declared is the manifest line the user can edit, or nil if nothing
	// declares the package directly. For a transitive dependency it points at
	// the DIRECT dependency pulling it in, not at the package itself.
	Declared *Anchor

	// Paths are dependency chains from a direct dependency to this package,
	// exclusive of it. Empty means direct. All known routes are kept.
	Paths [][]PackageKey

	// Reachable records whether the vulnerable code is called. Nil means no
	// analysis ran — only an explicit false justifies lowering severity.
	Reachable *bool

	// FromRange means the version was inferred from a range ("^4.17.0" scanned
	// as "4.17.0"), so it may be a false positive if the installed version is
	// newer.
	FromRange bool

	// DepGroups as reported by extraction: "dev", "optional", "peer". Empty
	// means a production dependency.
	DepGroups []string

	// Fix is what to upgrade to, decided by the matcher where the index is
	// available. Nothing downstream of it has one.
	Fix Fix
}

// FixKind distinguishes the three answers to "what should I upgrade to".
//
// Three rather than a version-or-empty, because "nothing is published" and
// "things are published but none of them is enough" are different answers and a
// user acts differently on each.
type FixKind int

// Fix kinds.
const (
	// FixNone means no advisory on this package names a fixed version above
	// the installed one.
	FixNone FixKind = iota
	// FixPartial means fixes are published, but no single one clears every
	// advisory.
	FixPartial
	// FixClears means Version clears every advisory on the package.
	FixClears
)

// Fix is what a user should upgrade to.
type Fix struct {
	Kind FixKind

	// Version is set only when Kind is FixClears.
	Version string
}

// Direct reports whether the project declares the package itself.
func (f Finding) Direct() bool { return len(f.Paths) == 0 }

// Dev reports whether the package is only a development dependency, which
// lowers severity since it does not ship.
func (f Finding) Dev() bool {
	return slices.Contains(f.DepGroups, "dev")
}

// Malicious reports whether any advisory marks the package as malicious.
func (f Finding) Malicious() bool {
	return slices.ContainsFunc(f.Advisories, Advisory.Malicious)
}

// Severity returns the highest severity across the advisories.
func (f Finding) Severity() Severity {
	worst := SeverityUnknown
	for _, a := range f.Advisories {
		if s := a.Severity(); s > worst {
			worst = s
		}
	}
	return worst
}

// Worst returns the highest-severity advisory, which supplies the diagnostic's
// code and link. Ties keep the earlier one so output stays stable.
func (f Finding) Worst() Advisory {
	worst := f.Advisories[0]
	for _, a := range f.Advisories[1:] {
		if a.Severity() > worst.Severity() {
			worst = a
		}
	}
	return worst
}

// ShortestPath returns the fewest hops from a direct dependency, or nil when
// the dependency is direct.
func (f Finding) ShortestPath() []PackageKey {
	var shortest []PackageKey
	for _, p := range f.Paths {
		if shortest == nil || len(p) < len(shortest) {
			shortest = p
		}
	}
	return shortest
}

// AnchorSite returns where to report the diagnostic, preferring the actionable
// declaration over where the package was found.
func (f Finding) AnchorSite() Site {
	if f.Declared != nil {
		return f.Declared.Declaration
	}
	return f.Evidence
}

// Report is the result of scanning one workspace.
type Report struct {
	Root      string
	Findings  []Finding
	ScannedAt time.Time
}

// ByFile groups findings by the path they should be reported against.
//
// Only currently-affected files appear. Clearing stale diagnostics is the
// caller's job, since it alone knows what was published before.
func (r Report) ByFile() map[string][]Finding {
	byFile := make(map[string][]Finding)
	for _, f := range r.Findings {
		path := f.AnchorSite().Path
		byFile[path] = append(byFile[path], f)
	}
	return byFile
}
