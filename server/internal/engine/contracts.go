// Package engine decides when to scan, runs the pipeline and hands results to
// whoever publishes them.
//
// The interfaces here are declared by the consumer, not by the packages that
// implement them: each implementation returns a concrete type and happens to
// satisfy the interface. That keeps dependencies pointing inward and lets the
// engine be tested against fakes, with no filesystem or network.
package engine

import (
	"context"

	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// Extractor finds the dependencies declared or locked in a project.
//
// Implemented by internal/extract over osv-scalibr. Reports what is present
// without judging it, and returns an empty slice rather than an error when a
// project has no manifests.
type Extractor interface {
	Extract(ctx context.Context, root string) ([]ExtractedPackage, error)
}

// ExtractedPackage is one dependency found in a project, before matching.
type ExtractedPackage struct {
	Package model.Package

	// Evidence is the file and line it was found at.
	Evidence model.Site

	DepGroups []string

	// FromRange means the version came from a range, not a lockfile.
	FromRange bool
}

// Matcher reports which advisories affect a set of packages.
//
// Implemented by internal/match against the local index. Ecosystem-specific
// version-range containment lives entirely behind this interface.
type Matcher interface {
	Match(ctx context.Context, pkgs []model.Package) (map[model.Package][]model.Advisory, error)
}

// Database owns the local copy of the advisory index.
//
// Implemented by internal/db. Refreshing happens in the background and must
// never block a scan: scanning against a database that is not ready yields no
// findings rather than an error, because "still downloading" is not a failure.
type Database interface {
	// Ready reports whether the index can be matched against.
	Ready(ecosystems []model.Ecosystem) bool

	// Ensure makes the index available, downloading if needed. Blocks, so
	// callers run it off the scan path.
	Ensure(ctx context.Context, ecosystems []model.Ecosystem) error
}

// Locator narrows a finding from a whole line to the exact span of the
// dependency name and version.
//
// Implemented by internal/locate. ok false is ordinary — a format may have no
// locator, in which case the whole-line range from extraction stands.
type Locator interface {
	Locate(path string, src []byte, key model.PackageKey) (anchor model.Anchor, ok bool)
}

// Attributor maps a transitive dependency back to the direct dependencies that
// pull it in. Implemented by internal/graph. Returns nil for a direct
// dependency.
type Attributor interface {
	PathsTo(key model.PackageKey) [][]model.PackageKey
}

// Publisher receives the findings for one file.
//
// Implemented by internal/lsp. Called with an empty slice to clear a file that
// previously had findings, so "no findings" is a message to deliver, not one to
// skip.
type Publisher interface {
	Publish(ctx context.Context, path string, findings []model.Finding) error
}
