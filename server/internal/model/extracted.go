package model

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
