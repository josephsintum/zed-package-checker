package model

import (
	"reflect"
	"testing"
)

func TestSeverityFromCVSS(t *testing.T) {
	// Band boundaries are the interesting cases: CVSS v3.1 bands are
	// closed-below, so 7.0 is High and 6.9 is Medium.
	tests := []struct {
		name  string
		score float64
		want  Severity
	}{
		{"zero is unknown, not none", 0.0, SeverityUnknown},
		{"negative clamps to unknown", -1.0, SeverityUnknown},
		{"just above zero is low", 0.1, SeverityLow},
		{"upper bound of low", 3.9, SeverityLow},
		{"lower bound of medium", 4.0, SeverityMedium},
		{"upper bound of medium", 6.9, SeverityMedium},
		{"lower bound of high", 7.0, SeverityHigh},
		{"upper bound of high", 8.9, SeverityHigh},
		{"lower bound of critical", 9.0, SeverityCritical},
		{"maximum", 10.0, SeverityCritical},
		{"above maximum clamps to critical", 11.0, SeverityCritical},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SeverityFromCVSS(tt.score); got != tt.want {
				t.Errorf("SeverityFromCVSS(%v) = %v, want %v", tt.score, got, tt.want)
			}
		})
	}
}

func TestSeverityOrdering(t *testing.T) {
	// Findings take the maximum severity across advisories, which relies on the
	// constants being ordered.
	ordered := []Severity{
		SeverityUnknown, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical,
	}
	for i := 1; i < len(ordered); i++ {
		if ordered[i-1] >= ordered[i] {
			t.Errorf("%v is not less than %v", ordered[i-1], ordered[i])
		}
	}
}

func TestPositionFromOneBasedLine(t *testing.T) {
	tests := []struct {
		name     string
		oneBased int
		wantLine int
	}{
		{"first line becomes zero", 1, 0},
		{"tenth line becomes nine", 10, 9},
		{"zero clamps to first line", 0, 0},
		{"negative clamps to first line", -5, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PositionFromOneBasedLine(tt.oneBased)
			if got.Line != tt.wantLine {
				t.Errorf("line = %d, want %d", got.Line, tt.wantLine)
			}
			if got.Column != 0 {
				t.Errorf("column = %d, want 0", got.Column)
			}
		})
	}
}

func TestWholeLine(t *testing.T) {
	// Line 14 from an extractor must cover zero-based line 13, ending at the
	// start of line 14.
	got := WholeLine(14)
	want := Range{
		Start: Position{Line: 13, Column: 0},
		End:   Position{Line: 14, Column: 0},
	}
	if got != want {
		t.Errorf("WholeLine(14) = %+v, want %+v", got, want)
	}
}

func TestEcosystemFromPURLType(t *testing.T) {
	tests := []struct {
		purlType string
		want     Ecosystem
	}{
		{"npm", EcosystemNPM},
		{"golang", EcosystemGo},
		{"pypi", EcosystemPyPI},
		{"cargo", EcosystemCrates},
		{"maven", ""},   // real ecosystem, not yet supported
		{"", ""},        // missing type
		{"NPM", ""},     // case matters; extraction reports lower case
		{"unknown", ""}, // anything else
	}
	for _, tt := range tests {
		t.Run(tt.purlType, func(t *testing.T) {
			if got := EcosystemFromPURLType(tt.purlType); got != tt.want {
				t.Errorf("EcosystemFromPURLType(%q) = %q, want %q", tt.purlType, got, tt.want)
			}
		})
	}
}

func TestAdvisoryMalicious(t *testing.T) {
	tests := []struct {
		id           string
		wantMalicous bool
		wantSeverity Severity
	}{
		{"MAL-2024-1234", true, SeverityCritical},
		{"GHSA-p6mc-m468-83gw", false, SeverityUnknown},
		{"CVE-2020-8203", false, SeverityUnknown},
		{"MALFORMED-1", false, SeverityUnknown}, // prefix must be exactly "MAL-"
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			a := Advisory{ID: tt.id}
			if got := a.Malicious(); got != tt.wantMalicous {
				t.Errorf("Malicious() = %v, want %v", got, tt.wantMalicous)
			}
			if got := a.Severity(); got != tt.wantSeverity {
				t.Errorf("Severity() = %v, want %v", got, tt.wantSeverity)
			}
		})
	}
}

func TestAdvisoryMaliciousReadsTheAliases(t *testing.T) {
	// How OSV files the npm compromises: a GHSA ID, with the canonical MAL-
	// identifier reachable only through the aliases.
	tests := []struct {
		name    string
		aliases []string
		want    bool
	}{
		{"canonical id in the aliases", []string{"MAL-2026-1380"}, true},
		{"alongside a CVE", []string{"CVE-2024-1", "MAL-2024-5"}, true},
		{"no MAL- anywhere", []string{"CVE-2024-1", "GHSA-y"}, false},
		{"prefix is exact on an alias too", []string{"MALFORMED-1"}, false},
		{"no aliases at all", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := Advisory{ID: "GHSA-9ppg-jx86-fqw7", Aliases: tt.aliases}
			if got := a.Malicious(); got != tt.want {
				t.Errorf("Malicious() = %v, want %v", got, tt.want)
			}
			if tt.want && a.Severity() != SeverityCritical {
				t.Errorf("Severity() = %v, want %v", a.Severity(), SeverityCritical)
			}
		})
	}
}

func TestAdvisoryMaliciousOutranksScore(t *testing.T) {
	// A malicious package with a low or absent score is still critical.
	a := Advisory{ID: "MAL-2024-1", CVSSScore: 0.1}
	if got := a.Severity(); got != SeverityCritical {
		t.Errorf("Severity() = %v, want %v", got, SeverityCritical)
	}
}

func TestAdvisoryFixedVersionsFor(t *testing.T) {
	lodash := PackageKey{Ecosystem: EcosystemNPM, Name: "lodash"}
	other := PackageKey{Ecosystem: EcosystemNPM, Name: "express"}

	a := Advisory{
		ID: "GHSA-test",
		Affected: []Affected{
			{
				Package: lodash,
				Ranges: []AffectedRange{
					{Introduced: "0", Fixed: "4.17.21"},
					{Introduced: "5.0.0", Fixed: "5.0.2"}, // backported fix
					{Introduced: "6.0.0"},                 // no fix published
				},
			},
			{
				Package: other,
				Ranges:  []AffectedRange{{Introduced: "0", Fixed: "1.0.0"}},
			},
		},
	}

	got := a.FixedVersionsFor(lodash)
	want := []string{"4.17.21", "5.0.2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("FixedVersionsFor(lodash) = %v, want %v", got, want)
	}

	if got := a.FixedVersionsFor(PackageKey{Ecosystem: EcosystemGo, Name: "nope"}); got != nil {
		t.Errorf("FixedVersionsFor(unrelated) = %v, want nil", got)
	}
}

// finding builds a Finding with the given advisories for brevity in tests.
func finding(advisories ...Advisory) Finding {
	return Finding{
		Package:    Package{PackageKey: PackageKey{Ecosystem: EcosystemNPM, Name: "lodash"}, Version: "4.17.15"},
		Advisories: advisories,
		Evidence:   Site{Path: "/proj/package-lock.json", Range: WholeLine(14)},
	}
}

func TestFindingSeverityAndWorst(t *testing.T) {
	low := Advisory{ID: "GHSA-low", CVSSScore: 2.0}
	high := Advisory{ID: "GHSA-high", CVSSScore: 8.1}
	medium := Advisory{ID: "GHSA-medium", CVSSScore: 5.3}

	f := finding(low, high, medium)
	if got := f.Severity(); got != SeverityHigh {
		t.Errorf("Severity() = %v, want %v", got, SeverityHigh)
	}
	if got := f.Worst().ID; got != "GHSA-high" {
		t.Errorf("Worst() = %q, want GHSA-high", got)
	}
}

func TestFindingWorstPrefersEarlierOnTie(t *testing.T) {
	// Stable output matters: the same scan must not reorder diagnostics.
	first := Advisory{ID: "GHSA-first", CVSSScore: 7.5}
	second := Advisory{ID: "GHSA-second", CVSSScore: 7.5}
	if got := finding(first, second).Worst().ID; got != "GHSA-first" {
		t.Errorf("Worst() = %q, want GHSA-first", got)
	}
}

func TestFindingDirectAndPaths(t *testing.T) {
	express := PackageKey{Ecosystem: EcosystemNPM, Name: "express"}
	bodyParser := PackageKey{Ecosystem: EcosystemNPM, Name: "body-parser"}

	direct := finding(Advisory{ID: "GHSA-1"})
	if !direct.Direct() {
		t.Error("finding with no paths should be direct")
	}
	if got := direct.ShortestPath(); got != nil {
		t.Errorf("ShortestPath() = %v, want nil", got)
	}

	transitive := finding(Advisory{ID: "GHSA-1"})
	transitive.Paths = [][]PackageKey{
		{express, bodyParser},
		{express},
	}
	if transitive.Direct() {
		t.Error("finding with paths should not be direct")
	}
	if got := transitive.ShortestPath(); !reflect.DeepEqual(got, []PackageKey{express}) {
		t.Errorf("ShortestPath() = %v, want [express]", got)
	}
}

func TestFindingDev(t *testing.T) {
	f := finding(Advisory{ID: "GHSA-1"})
	if f.Dev() {
		t.Error("no dep groups should not be dev")
	}
	f.DepGroups = []string{"optional"}
	if f.Dev() {
		t.Error("optional is not dev")
	}
	f.DepGroups = []string{"dev", "optional"}
	if !f.Dev() {
		t.Error("dev group should be reported as dev")
	}
}

func TestFindingAnchorSiteFallsBackToEvidence(t *testing.T) {
	f := finding(Advisory{ID: "GHSA-1"})

	// No declaration known: report against the lockfile line.
	if got := f.AnchorSite().Path; got != "/proj/package-lock.json" {
		t.Errorf("AnchorSite() = %q, want the evidence path", got)
	}

	// Declaration known: report against the manifest the user can edit.
	f.Declared = &Anchor{
		Declaration: Site{Path: "/proj/package.json", Range: WholeLine(5)},
	}
	if got := f.AnchorSite().Path; got != "/proj/package.json" {
		t.Errorf("AnchorSite() = %q, want the declaration path", got)
	}
}

func TestReportByFile(t *testing.T) {
	manifest := Site{Path: "/proj/package.json", Range: WholeLine(5)}

	declared := finding(Advisory{ID: "GHSA-1"})
	declared.Declared = &Anchor{Declaration: manifest}

	alsoDeclared := finding(Advisory{ID: "GHSA-2"})
	alsoDeclared.Declared = &Anchor{Declaration: manifest}

	undeclared := finding(Advisory{ID: "GHSA-3"}) // anchors on its evidence

	r := Report{Root: "/proj", Findings: []Finding{declared, alsoDeclared, undeclared}}
	byFile := r.ByFile()

	if len(byFile) != 2 {
		t.Fatalf("got %d files, want 2: %v", len(byFile), byFile)
	}
	if got := len(byFile["/proj/package.json"]); got != 2 {
		t.Errorf("package.json has %d findings, want 2", got)
	}
	if got := len(byFile["/proj/package-lock.json"]); got != 1 {
		t.Errorf("package-lock.json has %d findings, want 1", got)
	}
}

func TestReportByFileEmpty(t *testing.T) {
	// An empty report yields an empty map, not nil, so callers can range over it
	// without a guard.
	byFile := Report{Root: "/proj"}.ByFile()
	if byFile == nil {
		t.Fatal("ByFile() = nil, want an empty map")
	}
	if len(byFile) != 0 {
		t.Errorf("got %d entries, want 0", len(byFile))
	}
}

func TestPackageStringers(t *testing.T) {
	key := PackageKey{Ecosystem: EcosystemNPM, Name: "@babel/core"}
	if got, want := key.String(), "npm:@babel/core"; got != want {
		t.Errorf("PackageKey.String() = %q, want %q", got, want)
	}
	pkg := Package{PackageKey: key, Version: "7.0.0"}
	if got, want := pkg.String(), "npm:@babel/core@7.0.0"; got != want {
		t.Errorf("Package.String() = %q, want %q", got, want)
	}
}
