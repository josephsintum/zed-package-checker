//go:build differential

// Differential test: run osv-scanner over the same fixtures and assert it finds
// exactly what we do.
//
// This is the safety net for doing range matching ourselves. Version ordering
// is shared with osv-scanner via osv-scalibr/semantic, but the range arithmetic
// around it is ours, and a divergence there produces confidently wrong answers
// rather than errors.
//
// Behind a build tag because it needs a populated advisory cache and pulls
// osv-scanner in as a dependency. Run it deliberately:
//
//	make test-differential
//
// It uses the real cache, so populate it first:
//
//	./dist/dbcheck npm Go PyPI
package match

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/google/osv-scanner/v2/pkg/osvscanner"

	"github.com/josephsintum/zed-package-checker/server/internal/db"
	"github.com/josephsintum/zed-package-checker/server/internal/extract"
	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// hit identifies one finding in a form both implementations can produce.
type hit struct {
	pkg      string // "ecosystem:name@version"
	advisory string // OSV id
}

func (h hit) String() string { return h.pkg + " " + h.advisory }

func fixtureDir(t *testing.T, name string) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "testdata", "fixtures", name))
	if err != nil {
		t.Fatalf("resolve fixture: %v", err)
	}
	return dir
}

// ourHits runs extraction, database loading and matching.
func ourHits(t *testing.T, root string) []hit {
	t.Helper()
	log := discardLogger()

	extractor, err := extract.New()
	if err != nil {
		t.Fatalf("extract.New: %v", err)
	}
	pkgs, err := extractor.Extract(context.Background(), root)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	ecosystems := model.EcosystemsOf(pkgs)

	database, err := db.New(log)
	if err != nil {
		t.Fatalf("db.New: %v", err)
	}
	idx, err := database.Load(context.Background(), ecosystems)
	if err != nil {
		if errors.Is(err, db.ErrNotReady) {
			t.Skipf("advisory cache not populated; run: ./dist/dbcheck %v", ecosystems)
		}
		t.Fatalf("Load: %v", err)
	}

	findings, err := New(log, idx).Findings(context.Background(), pkgs)
	if err != nil {
		t.Fatalf("Findings: %v", err)
	}

	var hits []hit
	for _, f := range findings {
		for _, a := range f.Advisories {
			hits = append(hits, hit{pkg: f.Package.String(), advisory: a.ID})
		}
	}
	return normalise(hits)
}

// theirHits runs osv-scanner over the same directory, offline, against the same
// cache our database populated.
func theirHits(t *testing.T, root string) []hit {
	t.Helper()

	database, err := db.New(discardLogger())
	if err != nil {
		t.Fatalf("db.New: %v", err)
	}
	osvscanner.SetLogger(slog.DiscardHandler)

	actions := osvscanner.ScannerActions{
		DirectoryPaths: []string{root},
		Recursive:      true,
		CompareOffline: true,
		// Our archives live at the path osv-scanner expects, so it reads the
		// same bytes we indexed rather than downloading its own copy.
		LocalDBPath:           database.Root(),
		PluginNetworkDisabled: true,
	}
	actions.ExperimentalScannerActions.TransitiveScanning.Disabled = true
	actions.ExperimentalScannerActions.ExcludePatterns = []string{"**/node_modules/**"}

	res, err := osvscanner.DoScan(actions)
	if err != nil &&
		!errors.Is(err, osvscanner.ErrVulnerabilitiesFound) &&
		!errors.Is(err, osvscanner.ErrNoPackagesFound) {
		t.Fatalf("osv-scanner DoScan: %v", err)
	}

	var hits []hit
	for _, source := range res.Results {
		for _, pv := range source.Packages {
			ecosystem := model.EcosystemFromPURLType(purlTypeFor(pv.Package.Ecosystem))
			if ecosystem == "" {
				ecosystem = model.Ecosystem(pv.Package.Ecosystem)
			}
			pkg := model.Package{
				PackageKey: model.PackageKey{Ecosystem: ecosystem, Name: pv.Package.Name},
				Version:    pv.Package.Version,
			}
			for _, v := range pv.Vulnerabilities {
				hits = append(hits, hit{pkg: pkg.String(), advisory: v.GetId()})
			}
		}
	}
	return normalise(hits)
}

// purlTypeFor maps osv-scanner's ecosystem strings back through our own
// translation, so both sides name packages identically.
func purlTypeFor(ecosystem string) string {
	switch ecosystem {
	case "npm":
		return "npm"
	case "Go":
		return "golang"
	case "PyPI":
		return "pypi"
	case "crates.io":
		return "cargo"
	default:
		return ""
	}
}

// normalise sorts and deduplicates, so ordering differences are not treated as
// disagreements.
func normalise(hits []hit) []hit {
	slices.SortFunc(hits, func(a, b hit) int { return strings.Compare(a.String(), b.String()) })
	return slices.CompactFunc(hits, func(a, b hit) bool { return a.String() == b.String() })
}

func TestMatchesOSVScanner(t *testing.T) {
	if _, err := os.Stat(fixtureDir(t, "npm-direct")); err != nil {
		t.Skip("fixtures missing")
	}

	for _, fixture := range []string{
		"npm-direct",
		"npm-nolock",
		"npm-range-vs-lock",
		"go-mod",
		"py-requirements",
	} {
		t.Run(fixture, func(t *testing.T) {
			root := fixtureDir(t, fixture)
			ours := ourHits(t, root)
			theirs := theirHits(t, root)

			assertAgreement(t, ours, theirs)
		})
	}
}

// compare asserts the two implementations agree, separating the two ways they
// can differ.
//
// Extraction scope differs deliberately: we enable the packagejson extractor so
// projects without a lockfile are covered, and we keep the Go toolchain's own
// advisories, neither of which osv-scanner does by default. Those produce
// findings for packages it never saw, and are reported rather than failed.
//
// What must never differ is the matching. For any package both sides extracted,
// the advisory sets have to be identical — that is the property this test
// exists to protect. And anything osv-scanner finds that we do not is a false
// negative, which in a security tool is the failure that matters most.
func assertAgreement(t *testing.T, ours, theirs []hit) {
	t.Helper()

	theirPkgs := packagesIn(theirs)

	var (
		missed    []hit // they found it, we did not
		disagreed []string
		extraPkgs = map[string]bool{}
	)

	for _, h := range theirs {
		if !containsHit(ours, h) {
			missed = append(missed, h)
		}
	}
	for _, h := range ours {
		if containsHit(theirs, h) {
			continue
		}
		if !theirPkgs[h.pkg] {
			// A package osv-scanner never extracted; scope, not matching.
			extraPkgs[h.pkg] = true
			continue
		}
		disagreed = append(disagreed, "we flagged "+h.String()+" but osv-scanner did not")
	}

	if len(missed) > 0 {
		for _, h := range missed {
			t.Errorf("FALSE NEGATIVE: osv-scanner found %s and we did not", h)
		}
	}
	for _, d := range disagreed {
		t.Errorf("matching disagreement: %s", d)
	}

	if len(extraPkgs) > 0 {
		names := make([]string, 0, len(extraPkgs))
		for p := range extraPkgs {
			names = append(names, p)
		}
		sort.Strings(names)
		t.Logf("extra packages we extract and osv-scanner does not (expected): %v", names)
	}
	t.Logf("%d findings agreed", agreedCount(ours, theirs))
}

func containsHit(hits []hit, want hit) bool {
	return slices.ContainsFunc(hits, func(h hit) bool { return h.String() == want.String() })
}

func packagesIn(hits []hit) map[string]bool {
	out := make(map[string]bool, len(hits))
	for _, h := range hits {
		out[h.pkg] = true
	}
	return out
}

func agreedCount(ours, theirs []hit) int {
	n := 0
	for _, h := range ours {
		if containsHit(theirs, h) {
			n++
		}
	}
	return n
}
