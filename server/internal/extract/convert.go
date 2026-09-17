package extract

import (
	"path/filepath"
	"sort"

	"github.com/google/osv-scalibr/extractor"
	jsmeta "github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson/metadata"
	reqmeta "github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"

	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// convert maps scalibr packages into model types, dropping what is not a real
// dependency and reconciling manifest sightings against lockfile ones.
//
// Results are sorted so identical input produces identical output; diagnostics
// that reorder between scans are noise in a diff and in the editor.
func convert(pkgs []*extractor.Package) []model.ExtractedPackage {
	var sightings []model.ExtractedPackage

	for _, p := range pkgs {
		if p == nil || isSelf(p) {
			continue
		}
		// The gomod extractor reports the Go toolchain itself as "stdlib".
		// That is kept deliberately: OSV carries stdlib advisories, so a
		// vulnerable toolchain is a real finding the user can act on.
		ecosystem := model.EcosystemFromPURLType(p.PURLType)
		if ecosystem == "" || p.Name == "" || p.Version == "" {
			// An unsupported ecosystem is ordinary: a project may contain
			// manifests we do not match against. Skip rather than error.
			continue
		}

		path, line, ok := location(p)
		if !ok {
			continue
		}

		sightings = append(sightings, model.ExtractedPackage{
			Package: model.Package{
				PackageKey: model.PackageKey{Ecosystem: ecosystem, Name: p.Name},
				Version:    p.Version,
			},
			Evidence:  model.Site{Path: path, Range: model.WholeLine(line)},
			DepGroups: depGroups(p),
			FromRange: fromRange(p),
		})
	}

	out := reconcile(sightings)
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Package.Ecosystem != b.Package.Ecosystem {
			return a.Package.Ecosystem < b.Package.Ecosystem
		}
		if a.Package.Name != b.Package.Name {
			return a.Package.Name < b.Package.Name
		}
		if a.Package.Version != b.Package.Version {
			return a.Package.Version < b.Package.Version
		}
		// Two projects may hold the same package at the same version, so the
		// path is what makes this order total and the output reproducible.
		return a.Evidence.Path < b.Evidence.Path
	})
	return out
}

// reconcile resolves the same dependency being seen in several places.
//
// A package is routinely found twice, declared in a manifest and resolved in a
// lockfile. Those are not independent facts: the lockfile records what is
// actually installed, while the manifest version is inferred from a constraint
// and may name a version nobody has. So where a lockfile sighting exists, the
// manifest's inferred version is discarded rather than reported alongside it —
// otherwise "^4.17.0" against a lockfile pinning 4.17.21 yields two entries,
// one of them a version that does not exist in the project.
//
// The manifest's location survives as Declared, because that is the line the
// user can actually edit.
//
// All of this is scoped to one project directory. A lockfile says nothing
// about a manifest in a sibling project, and treating the two as one fact both
// suppressed the sibling's dependency outright and anchored versions on the
// wrong file — in a repository with two manifests naming the same package,
// which is the ordinary case rather than a corner one.
func reconcile(sightings []model.ExtractedPackage) []model.ExtractedPackage {
	// Keyed by name within a project: a lockfile legitimately holds several
	// versions of one package, and all of those are kept.
	locked := make(map[projectKey]bool)
	declared := make(map[projectKey]model.Site)
	for _, s := range sightings {
		if s.FromRange {
			if _, seen := declared[scopeOf(s)]; !seen {
				declared[scopeOf(s)] = s.Evidence
			}
			continue
		}
		locked[scopeOf(s)] = true
	}

	seen := make(map[projectPackage]int, len(sightings))
	out := make([]model.ExtractedPackage, 0, len(sightings))
	for _, s := range sightings {
		key := scopeOf(s)
		if s.FromRange && lockedAtOrAbove(locked, key) {
			// Superseded by a lockfile governing this project; its location is
			// still used below.
			continue
		}
		dedupe := projectPackage{dir: key.dir, pkg: s.Package}
		if i, dup := seen[dedupe]; dup {
			if len(out[i].DepGroups) == 0 {
				out[i].DepGroups = s.DepGroups
			}
			continue
		}
		if site, ok := declared[key]; ok && site != s.Evidence {
			s.Declared = &site
		}
		seen[dedupe] = len(out)
		out = append(out, s)
	}
	return out
}

// projectKey identifies a dependency by name within one project directory.
type projectKey struct {
	dir string
	pkg model.PackageKey
}

// projectPackage identifies an exact version within one project directory, so
// the same package at the same version in two projects stays two findings.
type projectPackage struct {
	dir string
	pkg model.Package
}

// lockedAtOrAbove reports whether this project, or any directory above it,
// pins the package in a lockfile.
//
// A workspace keeps one lockfile at the root and a manifest per member, so the
// pin that supersedes packages/app/package.json sits several directories up.
// Walking upwards finds it while still refusing to let a sibling project's
// lockfile reach across, which is the case this scoping exists for. Only
// directories that produced a sighting are in the map, so the walk cannot
// match anything outside the scan.
func lockedAtOrAbove(locked map[projectKey]bool, key projectKey) bool {
	dir := key.dir
	for {
		if locked[projectKey{dir: dir, pkg: key.pkg}] {
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}

// scopeOf locates a sighting's project. A manifest and the lockfile that
// resolves it sit in the same directory, which is what makes this the seam.
// Workspaces, where the lockfile is at the root and manifests are nested, need
// the dependency graph and arrive with it.
func scopeOf(s model.ExtractedPackage) projectKey {
	return projectKey{dir: filepath.Dir(s.Evidence.Path), pkg: s.Package.PackageKey}
}

// isSelf reports whether the package is the manifest's own identity rather than
// one of its dependencies.
//
// packagejson emits the project itself alongside its dependencies, attaching
// JavascriptPackageJSONMetadata to that entry and nothing to the dependencies.
// A project is not a dependency of itself, and reporting advisories against it
// would be wrong.
func isSelf(p *extractor.Package) bool {
	_, ok := p.Metadata.(*jsmeta.JavascriptPackageJSONMetadata)
	return ok
}

// fromRange reports whether the version was inferred from a constraint rather
// than read from a lockfile.
//
// Manifest extractors resolve a constraint to its lowest satisfying version,
// which may not be what is installed; lockfile extractors record exact
// versions. An exact pin in a manifest is not a range, so where the extractor
// tells us the comparator we use it.
func fromRange(p *extractor.Package) bool {
	// requirements.txt records the comparator, so "requests==2.19.1" can be
	// recognised as the exact pin it is.
	if m, ok := p.Metadata.(*reqmeta.Metadata); ok {
		switch m.VersionComparator {
		case "==", "===":
			return false
		default:
			return true
		}
	}

	for _, plugin := range p.Plugins {
		switch plugin {
		case "javascript/packagejson", "python/pyprojecttoml":
			// These record no comparator, so an exact pin is indistinguishable
			// from a range and is conservatively reported as a range. It only
			// matters for projects with no lockfile, since dedup prefers the
			// lockfile sighting otherwise. internal/locate can resolve this
			// properly once it parses manifests itself.
			return true
		}
	}
	return false
}

// depGroups returns the dependency groups, reported only by lockfile extractors.
func depGroups(p *extractor.Package) []string {
	if m, ok := p.Metadata.(*osv.DepGroupMetadata); ok {
		return m.DepGroupVals
	}
	return nil
}

// location returns the absolute path and one-based line a package was found at.
//
// Descriptor and File are both pointers and either can be nil for extractors
// that record no position, so every hop is checked.
func location(p *extractor.Package) (path string, line int, ok bool) {
	d := p.Location.Descriptor
	if d == nil || d.File == nil || d.File.Path == "" {
		return "", 0, false
	}
	return d.File.Path, d.File.LineNumber, true
}
