// Package match decides which advisories apply to a project's dependencies.
//
// Only the range arithmetic is ours. Version ordering — the genuinely subtle
// part, where prereleases and PEP 440 differ from semver — comes from
// osv-scalibr's semantic package, the same one osv-scanner uses.
//
// osv-scanner's own matcher is not reused because its database cache is
// filtered to the package names present when it first loaded, and later calls
// receive that stale set regardless of what the project now depends on. For a
// CLI that runs once this is correct and efficient; for a server that rescans
// after every `npm install` it would silently miss advisories for newly added
// dependencies. Reloading instead costs seconds and hundreds of megabytes per
// scan, so neither option upstream offers is usable here.
package match

import (
	"context"
	"log/slog"
	"sort"

	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// Index is the lookup the matcher needs, satisfied by db.Index.
//
// Declared here rather than imported so match does not depend on how the
// advisory database is stored, and can be tested against a map.
type Index interface {
	Lookup(key model.PackageKey) []model.Advisory
}

// Matcher pairs extracted packages with the advisories that affect them.
type Matcher struct {
	index Index
	log   *slog.Logger
}

// New builds a Matcher over an advisory index.
func New(log *slog.Logger, index Index) *Matcher {
	return &Matcher{index: index, log: log}
}

// Findings returns one finding per affected package, carrying every advisory
// that applies to it.
//
// Packages with no advisories produce nothing, which is the overwhelmingly
// common case. The order of the result follows the input, so identical projects
// produce identical diagnostics.
func (m *Matcher) Findings(ctx context.Context, pkgs []model.ExtractedPackage) ([]model.Finding, error) {
	findings := make([]model.Finding, 0, 8)

	for i, p := range pkgs {
		// Matching a large project is thousands of comparisons; a cancelled
		// scan should stop rather than finish work nobody will read.
		if i%256 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}

		advisories := m.applicable(p.Package)
		if len(advisories) == 0 {
			continue
		}

		findings = append(findings, model.Finding{
			Package:    p.Package,
			Advisories: advisories,
			Evidence:   p.Evidence,
			Declared:   declaredAnchor(p),
			FromRange:  p.FromRange,
			DepGroups:  p.DepGroups,
		})
	}
	return findings, nil
}

// declaredAnchor lifts extraction's declaration site into an Anchor.
//
// The version span is left nil: extraction knows which line declares a
// dependency but not where within it the version string sits. internal/locate
// fills that in, and until it does no version-bump action can be offered.
func declaredAnchor(p model.ExtractedPackage) *model.Anchor {
	if p.Declared == nil {
		return nil
	}
	return &model.Anchor{Declaration: *p.Declared}
}

// applicable returns the advisories affecting a specific version, sorted with
// the most severe first so the diagnostic leads with the worst news.
func (m *Matcher) applicable(pkg model.Package) []model.Advisory {
	candidates := m.index.Lookup(pkg.PackageKey)
	if len(candidates) == 0 {
		return nil
	}

	var hits []model.Advisory
	for _, a := range candidates {
		ok, err := affects(a, pkg)
		if err != nil {
			// An unparsable version is a property of one advisory or one
			// dependency, not a reason to abandon the scan. Reporting nothing
			// for the rest of the project would be a far worse outcome than
			// missing one comparison, so log and continue.
			m.log.Debug("skipping advisory with an incomparable version",
				"advisory", a.ID, "package", pkg.String(), "error", err)
			continue
		}
		if ok {
			hits = append(hits, a)
		}
	}

	// Stable order: severity first, then id, so output does not churn between
	// runs for advisories that score the same.
	sort.SliceStable(hits, func(i, j int) bool {
		si, sj := hits[i].Severity(), hits[j].Severity()
		if si != sj {
			return si > sj
		}
		return hits[i].ID < hits[j].ID
	})
	return hits
}
