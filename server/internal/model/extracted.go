package model

import "slices"

// EcosystemsOf returns the distinct ecosystems present, in a stable order.
//
// Sorted rather than first-seen. The result decides which archives are
// downloaded and loaded, and appears in log lines and progress entries; an
// order that depends on which manifest the walk reached first would make two
// runs over the same project disagree for no reason.
func EcosystemsOf(pkgs []ExtractedPackage) []Ecosystem {
	var out []Ecosystem
	for _, p := range pkgs {
		if !slices.Contains(out, p.Package.Ecosystem) {
			out = append(out, p.Package.Ecosystem)
		}
	}
	slices.Sort(out)
	return out
}

// ExtractedPackage is one dependency found in a project, before any advisory
// matching.
type ExtractedPackage struct {
	Package Package

	// Evidence is where the version was established — a lockfile entry when one
	// exists, otherwise the manifest.
	Evidence Site

	// Declared is the manifest line declaring this dependency, when one was
	// found. Diagnostics are reported here in preference to Evidence, because
	// a lockfile is generated and a manifest is what the user edits.
	Declared *Site

	// DepGroups as reported by extraction: "dev", "optional", "peer". Empty
	// means a production dependency.
	DepGroups []string

	// FromRange means the version was inferred from a constraint ("^4.17.0"
	// resolved to "4.17.0") rather than read from a lockfile, so it may not be
	// what is actually installed.
	FromRange bool
}
