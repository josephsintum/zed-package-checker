// Package model holds the vocabulary shared across the package checker:
// packages, advisories, source positions and findings.
//
// No dependencies outside the standard library, and no behaviour beyond pure
// functions over its own types. That is what keeps osv-scalibr and go.lsp.dev
// replaceable — both translate into these types at their boundary, so neither
// leaks into the middle of the program.
//
//   - Ecosystem, PackageKey, Package — what a dependency is.
//   - Position, Range, Site, Anchor — where it is written down.
//   - Severity, Advisory, Affected — what is wrong with it.
//   - Finding, Report — the two combined, ready to publish.
package model
