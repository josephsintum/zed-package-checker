package extract

import (
	"sort"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	jsmeta "github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson/metadata"
	reqmeta "github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"

	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// filesystemExtractor is the subset of scalibr's extractor interface every
// constructor returns, named so buildPlugins can treat them uniformly.
type filesystemExtractor = filesystem.Extractor

// adapt lets constructors with the same shape be stored in one slice.
func adapt(f func(*cpb.PluginConfig) (filesystem.Extractor, error)) func(*cpb.PluginConfig) (filesystemExtractor, error) {
	return func(c *cpb.PluginConfig) (filesystemExtractor, error) { return f(c) }
}

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
		return a.Package.Version < b.Package.Version
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
func reconcile(sightings []model.ExtractedPackage) []model.ExtractedPackage {
	// Keyed by name alone: a lockfile legitimately holds several versions of
	// one package, and all of those are kept.
	locked := make(map[model.PackageKey]bool)
	declared := make(map[model.PackageKey]model.Site)
	for _, s := range sightings {
		if s.FromRange {
			if _, seen := declared[s.Package.PackageKey]; !seen {
				declared[s.Package.PackageKey] = s.Evidence
			}
			continue
		}
		locked[s.Package.PackageKey] = true
	}

	seen := make(map[model.Package]int, len(sightings))
	out := make([]model.ExtractedPackage, 0, len(sightings))
	for _, s := range sightings {
		key := s.Package.PackageKey
		if s.FromRange && locked[key] {
			// Superseded by the lockfile; its location is still used below.
			continue
		}
		if i, dup := seen[s.Package]; dup {
			if len(out[i].DepGroups) == 0 {
				out[i].DepGroups = s.DepGroups
			}
			continue
		}
		if site, ok := declared[key]; ok && site != s.Evidence {
			s.Declared = &site
		}
		seen[s.Package] = len(out)
		out = append(out, s)
	}
	return out
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
