package match

import (
	"context"
	"log/slog"
	"testing"

	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// mapIndex is an advisory index backed by a map, so matching can be tested
// without a database.
type mapIndex map[model.PackageKey][]model.Advisory

func (m mapIndex) Lookup(key model.PackageKey) []model.Advisory { return m[key] }

func pkg(e model.Ecosystem, name, version string) model.Package {
	return model.Package{
		PackageKey: model.PackageKey{Ecosystem: e, Name: name},
		Version:    version,
	}
}

// advisory builds one covering key with the given ranges.
func advisory(id string, key model.PackageKey, ranges ...model.AffectedRange) model.Advisory {
	return model.Advisory{
		ID:       id,
		Affected: []model.Affected{{Package: key, Ranges: ranges}},
	}
}

func TestRangeBoundaries(t *testing.T) {
	npm := model.PackageKey{Ecosystem: model.EcosystemNPM, Name: "lodash"}

	// Ranges are half-open: affected at Introduced, not affected at Fixed.
	// These boundaries are exactly where an off-by-one produces confident
	// wrong answers rather than visible errors.
	tests := []struct {
		name    string
		ranges  []model.AffectedRange
		version string
		want    bool
	}{
		{
			name:    "below the introduced version",
			ranges:  []model.AffectedRange{{Introduced: "4.0.0", Fixed: "4.17.21"}},
			version: "3.9.9",
			want:    false,
		},
		{
			name:    "exactly the introduced version is affected",
			ranges:  []model.AffectedRange{{Introduced: "4.0.0", Fixed: "4.17.21"}},
			version: "4.0.0",
			want:    true,
		},
		{
			name:    "inside the range",
			ranges:  []model.AffectedRange{{Introduced: "4.0.0", Fixed: "4.17.21"}},
			version: "4.17.15",
			want:    true,
		},
		{
			name:    "exactly the fixed version is NOT affected",
			ranges:  []model.AffectedRange{{Introduced: "4.0.0", Fixed: "4.17.21"}},
			version: "4.17.21",
			want:    false,
		},
		{
			name:    "above the fixed version",
			ranges:  []model.AffectedRange{{Introduced: "4.0.0", Fixed: "4.17.21"}},
			version: "5.0.0",
			want:    false,
		},
		{
			name:    "the zero sentinel means affected from the beginning",
			ranges:  []model.AffectedRange{{Introduced: "0", Fixed: "4.17.21"}},
			version: "0.0.1",
			want:    true,
		},
		{
			name:    "no fix published means still affected",
			ranges:  []model.AffectedRange{{Introduced: "4.0.0"}},
			version: "99.0.0",
			want:    true,
		},
		{
			name:    "last_affected is inclusive, unlike fixed",
			ranges:  []model.AffectedRange{{Introduced: "0", LastAffected: "0.3.24"}},
			version: "0.3.24",
			want:    true,
		},
		{
			name:    "just past last_affected",
			ranges:  []model.AffectedRange{{Introduced: "0", LastAffected: "0.3.24"}},
			version: "0.3.25",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := advisory("GHSA-x", npm, tt.ranges...)
			got, err := affects(a, pkg(model.EcosystemNPM, "lodash", tt.version))
			if err != nil {
				t.Fatalf("affects: %v", err)
			}
			if got != tt.want {
				t.Errorf("version %s affected = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestBackportedFixesAreDisjoint(t *testing.T) {
	npm := model.PackageKey{Ecosystem: model.EcosystemNPM, Name: "p"}
	// A fix backported to an older line means 1.2.3 and 2.0.5 are both safe
	// while 1.5.0 — newer than one fix, older than the other — is not.
	a := advisory("GHSA-x", npm,
		model.AffectedRange{Introduced: "0", Fixed: "1.2.3"},
		model.AffectedRange{Introduced: "2.0.0", Fixed: "2.0.5"},
	)

	// A slice, so the versions stay in timeline order and a failure reports the
	// same cases in the same sequence on the next run.
	tests := []struct {
		version string
		want    bool
	}{
		{"1.0.0", true},  // inside the first range
		{"1.2.3", false}, // fixed on the old line
		{"1.5.0", false}, // past the old fix, before the second range opens
		{"2.0.0", true},  // inside the second range
		{"2.0.4", true},
		{"2.0.5", false}, // fixed on the new line
		{"3.0.0", false},
	}
	for _, tt := range tests {
		version, want := tt.version, tt.want
		t.Run(version, func(t *testing.T) {
			got, err := affects(a, pkg(model.EcosystemNPM, "p", version))
			if err != nil {
				t.Fatalf("affects: %v", err)
			}
			if got != want {
				t.Errorf("affected = %v, want %v", got, want)
			}
		})
	}
}

func TestPrereleaseOrdering(t *testing.T) {
	// Prereleases sort BEFORE their release across all four ecosystems, so a
	// prerelease of the fixed version is still affected. This is the detail
	// that silently produces wrong answers if the comparison is naive.
	tests := []struct {
		ecosystem model.Ecosystem
		fixed     string
		version   string
		want      bool
	}{
		{model.EcosystemNPM, "2.0.0", "2.0.0-beta.1", true},
		{model.EcosystemNPM, "2.0.0", "2.0.0", false},
		{model.EcosystemCrates, "2.0.0", "2.0.0-alpha", true},
		{model.EcosystemGo, "v2.0.0", "v2.0.0-rc1", true},
		{model.EcosystemGo, "v2.0.0", "v2.0.0", false},
		// PEP 440 spells prereleases differently again.
		{model.EcosystemPyPI, "2.0.0", "2.0.0rc1", true},
		{model.EcosystemPyPI, "2.0.0", "2.0.0", false},
		{model.EcosystemPyPI, "2.0.0", "1.9.9", true},
	}

	for _, tt := range tests {
		t.Run(string(tt.ecosystem)+"/"+tt.version, func(t *testing.T) {
			key := model.PackageKey{Ecosystem: tt.ecosystem, Name: "p"}
			a := advisory("GHSA-x", key, model.AffectedRange{Introduced: "0", Fixed: tt.fixed})
			got, err := affects(a, model.Package{PackageKey: key, Version: tt.version})
			if err != nil {
				t.Fatalf("affects: %v", err)
			}
			if got != tt.want {
				t.Errorf("%s %s against fixed %s: affected = %v, want %v",
					tt.ecosystem, tt.version, tt.fixed, got, tt.want)
			}
		})
	}
}

func TestExplicitVersionList(t *testing.T) {
	// OSV uses an explicit list for ecosystems with no reliable ordering; it is
	// authoritative for the versions it names, regardless of ranges.
	key := model.PackageKey{Ecosystem: model.EcosystemNPM, Name: "p"}
	a := model.Advisory{
		ID:       "GHSA-x",
		Affected: []model.Affected{{Package: key, Versions: []string{"1.0.0", "1.2.0"}}},
	}

	tests := []struct {
		version string
		want    bool
	}{
		{"1.0.0", true},
		{"1.2.0", true},
		{"1.1.0", false},
	}
	for _, tt := range tests {
		version, want := tt.version, tt.want
		t.Run(version, func(t *testing.T) {
			got, err := affects(a, model.Package{PackageKey: key, Version: version})
			if err != nil {
				t.Fatalf("affects: %v", err)
			}
			if got != want {
				t.Errorf("affected = %v, want %v", got, want)
			}
		})
	}
}

func TestAdvisoryForADifferentPackageIsIgnored(t *testing.T) {
	// An advisory can cover several packages; only the matching entry counts.
	lodash := model.PackageKey{Ecosystem: model.EcosystemNPM, Name: "lodash"}
	express := model.PackageKey{Ecosystem: model.EcosystemNPM, Name: "express"}

	a := model.Advisory{
		ID: "GHSA-x",
		Affected: []model.Affected{
			{Package: express, Ranges: []model.AffectedRange{{Introduced: "0"}}},
		},
	}
	got, err := affects(a, model.Package{PackageKey: lodash, Version: "1.0.0"})
	if err != nil {
		t.Fatalf("affects: %v", err)
	}
	if got {
		t.Error("an advisory for express matched lodash")
	}
}

func TestFindingsOnlyReportsAffectedPackages(t *testing.T) {
	lodash := model.PackageKey{Ecosystem: model.EcosystemNPM, Name: "lodash"}
	safe := model.PackageKey{Ecosystem: model.EcosystemNPM, Name: "safe-pkg"}

	idx := mapIndex{
		lodash: {advisory("GHSA-1", lodash, model.AffectedRange{Introduced: "0", Fixed: "4.17.21"})},
		safe:   {advisory("GHSA-2", safe, model.AffectedRange{Introduced: "9.0.0"})},
	}
	m := New(discardLogger(), idx)

	site := model.Site{Path: "/proj/package.json", Range: model.WholeLine(5)}
	pkgs := []model.ExtractedPackage{
		{Package: model.Package{PackageKey: lodash, Version: "4.17.15"}, Evidence: site},
		{Package: model.Package{PackageKey: safe, Version: "1.0.0"}, Evidence: site},
		{Package: pkg(model.EcosystemNPM, "unknown", "1.0.0"), Evidence: site},
	}

	findings, err := m.Findings(context.Background(), pkgs)
	if err != nil {
		t.Fatalf("Findings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	if findings[0].Package.Name != "lodash" {
		t.Errorf("reported %q, want lodash", findings[0].Package.Name)
	}
	if len(findings[0].Advisories) != 1 {
		t.Errorf("got %d advisories, want 1", len(findings[0].Advisories))
	}
}

func TestFindingsCarriesEvidenceAndDeclaration(t *testing.T) {
	// The manifest line is what the diagnostic anchors on, so it must survive
	// matching rather than being rediscovered later.
	key := model.PackageKey{Ecosystem: model.EcosystemNPM, Name: "lodash"}
	idx := mapIndex{key: {advisory("GHSA-1", key, model.AffectedRange{Introduced: "0"})}}

	declared := model.Site{Path: "/proj/package.json", Range: model.WholeLine(5)}
	evidence := model.Site{Path: "/proj/package-lock.json", Range: model.WholeLine(14)}

	findings, err := New(discardLogger(), idx).Findings(context.Background(),
		[]model.ExtractedPackage{{
			Package:   model.Package{PackageKey: key, Version: "4.17.15"},
			Evidence:  evidence,
			Declared:  &declared,
			FromRange: true,
			DepGroups: []string{"dev"},
		}})
	if err != nil {
		t.Fatalf("Findings: %v", err)
	}
	f := findings[0]

	if f.Evidence != evidence {
		t.Errorf("evidence = %+v, want %+v", f.Evidence, evidence)
	}
	if f.Declared == nil {
		t.Fatal("declaration was lost")
	}
	if f.Declared.Declaration != declared {
		t.Errorf("declaration = %+v, want %+v", f.Declared.Declaration, declared)
	}
	// The version span comes from internal/locate, not extraction.
	if f.Declared.Version != nil {
		t.Error("a version span appeared before locate ran")
	}
	if !f.FromRange {
		t.Error("FromRange was lost")
	}
	if !f.Dev() {
		t.Error("dependency groups were lost")
	}
	if f.AnchorSite() != declared {
		t.Errorf("AnchorSite = %+v, want the manifest declaration", f.AnchorSite())
	}
}

func TestAdvisoriesSortedBySeverity(t *testing.T) {
	key := model.PackageKey{Ecosystem: model.EcosystemNPM, Name: "p"}
	always := model.AffectedRange{Introduced: "0"}

	low := advisory("GHSA-low", key, always)
	low.CVSSScore = 2.0
	critical := advisory("GHSA-critical", key, always)
	critical.CVSSScore = 9.8
	medium := advisory("GHSA-medium", key, always)
	medium.CVSSScore = 5.0

	idx := mapIndex{key: {low, medium, critical}}
	findings, err := New(discardLogger(), idx).Findings(context.Background(),
		[]model.ExtractedPackage{{Package: model.Package{PackageKey: key, Version: "1.0.0"}}})
	if err != nil {
		t.Fatalf("Findings: %v", err)
	}

	got := []string{}
	for _, a := range findings[0].Advisories {
		got = append(got, a.ID)
	}
	want := []string{"GHSA-critical", "GHSA-medium", "GHSA-low"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
	if findings[0].Severity() != model.SeverityCritical {
		t.Errorf("finding severity = %v, want Critical", findings[0].Severity())
	}
}

func TestUnparsableVersionSkipsOneAdvisoryNotTheScan(t *testing.T) {
	// A version the ecosystem's rules cannot parse must not cost the user every
	// other finding in the project.
	key := model.PackageKey{Ecosystem: model.EcosystemNPM, Name: "p"}
	other := model.PackageKey{Ecosystem: model.EcosystemNPM, Name: "q"}

	idx := mapIndex{
		key:   {advisory("GHSA-bad", key, model.AffectedRange{Introduced: "0", Fixed: "not a version"})},
		other: {advisory("GHSA-good", other, model.AffectedRange{Introduced: "0"})},
	}
	findings, err := New(discardLogger(), idx).Findings(context.Background(),
		[]model.ExtractedPackage{
			{Package: model.Package{PackageKey: key, Version: "1.0.0"}},
			{Package: model.Package{PackageKey: other, Version: "1.0.0"}},
		})
	if err != nil {
		t.Fatalf("Findings should not fail over one bad version: %v", err)
	}
	if len(findings) != 1 || findings[0].Package.Name != "q" {
		t.Errorf("got %+v, want only the q finding", findings)
	}
}

func TestFindingsHonoursCancellation(t *testing.T) {
	key := model.PackageKey{Ecosystem: model.EcosystemNPM, Name: "p"}
	idx := mapIndex{key: {advisory("GHSA-1", key, model.AffectedRange{Introduced: "0"})}}

	pkgs := make([]model.ExtractedPackage, 1000)
	for i := range pkgs {
		pkgs[i] = model.ExtractedPackage{Package: model.Package{PackageKey: key, Version: "1.0.0"}}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New(discardLogger(), idx).Findings(ctx, pkgs); err == nil {
		t.Error("expected an error from a cancelled match")
	}
}

func TestEmptyInputs(t *testing.T) {
	m := New(discardLogger(), mapIndex{})

	findings, err := m.Findings(context.Background(), nil)
	if err != nil {
		t.Fatalf("Findings: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings from no packages, want 0", len(findings))
	}
}

// fixOf returns the Fix the matcher decides for one package against one index.
func fixOf(t *testing.T, index mapIndex, p model.Package) model.Fix {
	t.Helper()
	m := New(discardLogger(), index)
	findings, err := m.Findings(context.Background(), []model.ExtractedPackage{{
		Package:  p,
		Evidence: model.Site{Path: "/proj/package.json", Range: model.WholeLine(1)},
	}})
	if err != nil {
		t.Fatalf("Findings: %v", err)
	}
	if len(findings) == 0 {
		return model.Fix{Kind: model.FixNone}
	}
	return findings[0].Fix
}

func TestFixIsTheLowestVersionClearingEveryAdvisory(t *testing.T) {
	// Shaped on lodash@4.17.15: the worst advisory is fixed in 4.17.21, but
	// another is still open until 4.18.0.
	key := model.PackageKey{Ecosystem: model.EcosystemNPM, Name: "lodash"}
	index := mapIndex{key: {
		advisory("GHSA-worst", key, model.AffectedRange{Introduced: "0", Fixed: "4.17.21"}),
		advisory("GHSA-later", key, model.AffectedRange{Introduced: "0", Fixed: "4.18.0"}),
	}}

	got := fixOf(t, index, pkg(model.EcosystemNPM, "lodash", "4.17.15"))
	if got.Kind != model.FixClears || got.Version != "4.18.0" {
		t.Errorf("Fix = %+v, want Clears 4.18.0", got)
	}
}

func TestAFixAnotherAdvisoryStillAffectsIsRejected(t *testing.T) {
	// The reason the verification step exists. A is fixed in 1.5.0, but B
	// covers everything below 2.0.0 — so 1.5.0 is no fix at all.
	key := model.PackageKey{Ecosystem: model.EcosystemNPM, Name: "evil"}
	index := mapIndex{key: {
		advisory("GHSA-a", key, model.AffectedRange{Introduced: "1.0.0", Fixed: "1.5.0"}),
		advisory("GHSA-b", key, model.AffectedRange{Introduced: "0", Fixed: "2.0.0"}),
	}}

	got := fixOf(t, index, pkg(model.EcosystemNPM, "evil", "1.2.0"))
	if got.Kind != model.FixClears || got.Version != "2.0.0" {
		t.Errorf("Fix = %+v, want Clears 2.0.0 (1.5.0 is itself affected by GHSA-b)", got)
	}
}

func TestABackportedFixIsNeverOfferedAsADowngrade(t *testing.T) {
	// One advisory patched on two release lines at once. 1.2.3 is genuinely
	// unaffected, and genuinely useless to a project on 2.0.0.
	key := model.PackageKey{Ecosystem: model.EcosystemNPM, Name: "pkg"}
	index := mapIndex{key: {
		advisory("GHSA-1", key,
			model.AffectedRange{Introduced: "1.0.0", Fixed: "1.2.3"},
			model.AffectedRange{Introduced: "2.0.0", Fixed: "2.0.1"}),
	}}

	if got := fixOf(t, index, pkg(model.EcosystemNPM, "pkg", "2.0.0")); got.Version != "2.0.1" {
		t.Errorf("Fix = %+v, want Clears 2.0.1, not a downgrade", got)
	}
	// The lower line still gets the lower fix, which is right for it.
	if got := fixOf(t, index, pkg(model.EcosystemNPM, "pkg", "1.1.0")); got.Version != "1.2.3" {
		t.Errorf("Fix = %+v, want Clears 1.2.3", got)
	}
}

func TestDisjointReleaseLinesHaveNoSingleFix(t *testing.T) {
	key := model.PackageKey{Ecosystem: model.EcosystemNPM, Name: "pkg"}
	index := mapIndex{key: {
		advisory("GHSA-fixed", key, model.AffectedRange{Introduced: "0", Fixed: "2.0.0"}),
		advisory("GHSA-open", key, model.AffectedRange{Introduced: "1.0.0"}),
	}}

	if got := fixOf(t, index, pkg(model.EcosystemNPM, "pkg", "1.5.0")); got.Kind != model.FixPartial {
		t.Errorf("Fix = %+v, want Partial", got)
	}
}

func TestAnAdvisoryWithOnlyLastAffectedNamesNoFix(t *testing.T) {
	key := model.PackageKey{Ecosystem: model.EcosystemNPM, Name: "pkg"}
	index := mapIndex{key: {
		advisory("GHSA-1", key, model.AffectedRange{Introduced: "0", LastAffected: "2.0.0"}),
	}}

	if got := fixOf(t, index, pkg(model.EcosystemNPM, "pkg", "1.0.0")); got.Kind != model.FixNone {
		t.Errorf("Fix = %+v, want None", got)
	}
}

func TestCandidatesAreOrderedByTheEcosystemNotTheArchive(t *testing.T) {
	// Lexicographically "10.0.0" sorts below "9.0.0", so a string sort would
	// answer 9.0.0 and leave the other advisory unresolved.
	key := model.PackageKey{Ecosystem: model.EcosystemNPM, Name: "pkg"}
	index := mapIndex{key: {
		advisory("GHSA-a", key, model.AffectedRange{Introduced: "0", Fixed: "9.0.0"}),
		advisory("GHSA-b", key, model.AffectedRange{Introduced: "0", Fixed: "10.0.0"}),
	}}

	got := fixOf(t, index, pkg(model.EcosystemNPM, "pkg", "1.0.0"))
	if got.Version != "10.0.0" {
		t.Errorf("Fix = %+v, want Clears 10.0.0", got)
	}
}

func TestAffectedAtAgreesWithFindings(t *testing.T) {
	// The two must share one definition of affected, or a verified fix means
	// nothing.
	key := model.PackageKey{Ecosystem: model.EcosystemNPM, Name: "pkg"}
	index := mapIndex{key: {
		advisory("GHSA-1", key, model.AffectedRange{Introduced: "1.0.0", Fixed: "2.0.0"}),
	}}
	m := New(discardLogger(), index)

	for _, version := range []string{"0.9.0", "1.0.0", "1.9.9", "2.0.0", "3.0.0"} {
		findings, err := m.Findings(context.Background(), []model.ExtractedPackage{{
			Package:  pkg(model.EcosystemNPM, "pkg", version),
			Evidence: model.Site{Path: "/proj/package.json", Range: model.WholeLine(1)},
		}})
		if err != nil {
			t.Fatalf("Findings: %v", err)
		}
		if got, want := m.affectedAt(key, version), len(findings) > 0; got != want {
			t.Errorf("affectedAt(%q) = %v, Findings says %v", version, got, want)
		}
	}
}
