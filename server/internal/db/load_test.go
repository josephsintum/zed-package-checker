package db

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// advisoryJSON renders an OSV advisory for embedding in a test archive.
func advisoryJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal advisory: %v", err)
	}
	return string(raw)
}

// decode parses one advisory the way the loader does.
func decode(t *testing.T, body string, e model.Ecosystem) (model.Advisory, bool) {
	t.Helper()
	var raw osvAdvisory
	if err := json.Unmarshal([]byte(body), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return raw.toModel(e)
}

func TestToModelSkipsWithdrawn(t *testing.T) {
	// Withdrawn advisories are retracted, not fixed. About 4% of an archive,
	// and reporting one is a pure false positive.
	body := `{
		"id": "GHSA-withdrawn",
		"withdrawn": "2023-01-01T00:00:00Z",
		"affected": [{"package": {"ecosystem": "npm", "name": "lodash"}}]
	}`
	if _, ok := decode(t, body, model.EcosystemNPM); ok {
		t.Error("a withdrawn advisory was indexed")
	}
}

func TestToModelKeepsOnlyTheRequestedEcosystem(t *testing.T) {
	// One advisory routinely covers several ecosystems. Carrying the others
	// would inflate every index with entries no lookup can reach.
	body := `{
		"id": "GHSA-multi",
		"affected": [
			{"package": {"ecosystem": "npm", "name": "lodash"}},
			{"package": {"ecosystem": "PyPI", "name": "requests"}},
			{"package": {"ecosystem": "Go", "name": "example.com/x"}}
		]
	}`

	got, ok := decode(t, body, model.EcosystemNPM)
	if !ok {
		t.Fatal("advisory was not indexed")
	}
	if len(got.Affected) != 1 {
		t.Fatalf("kept %d affected entries, want 1", len(got.Affected))
	}
	if got.Affected[0].Package.Name != "lodash" {
		t.Errorf("kept %q, want lodash", got.Affected[0].Package.Name)
	}

	// And an advisory touching nothing in this ecosystem is dropped entirely.
	if _, ok := decode(t, body, model.EcosystemCrates); ok {
		t.Error("an advisory affecting no crates.io package was indexed")
	}
}

func TestToModelPairsRangeEvents(t *testing.T) {
	// OSV ranges are event timelines, not intervals: a fix belongs to the
	// introduction preceding it. Getting this wrong silently mis-matches
	// versions, which is the worst kind of bug here.
	tests := []struct {
		name   string
		events string
		want   []model.AffectedRange
	}{
		{
			name:   "introduced and fixed",
			events: `[{"introduced": "0"}, {"fixed": "4.17.21"}]`,
			want:   []model.AffectedRange{{Introduced: "0", Fixed: "4.17.21"}},
		},
		{
			name:   "last_affected instead of fixed",
			events: `[{"introduced": "0"}, {"last_affected": "0.3.24"}]`,
			want:   []model.AffectedRange{{Introduced: "0", LastAffected: "0.3.24"}},
		},
		{
			name:   "introduced with no fix is still affected",
			events: `[{"introduced": "6.0.0"}]`,
			want:   []model.AffectedRange{{Introduced: "6.0.0"}},
		},
		{
			name: "backported fixes make disjoint ranges",
			events: `[{"introduced": "0"}, {"fixed": "1.2.3"},
			          {"introduced": "2.0.0"}, {"fixed": "2.0.5"}]`,
			want: []model.AffectedRange{
				{Introduced: "0", Fixed: "1.2.3"},
				{Introduced: "2.0.0", Fixed: "2.0.5"},
			},
		},
		{
			name: "an unclosed range after a closed one survives",
			events: `[{"introduced": "0"}, {"fixed": "1.2.3"},
			          {"introduced": "2.0.0"}]`,
			want: []model.AffectedRange{
				{Introduced: "0", Fixed: "1.2.3"},
				{Introduced: "2.0.0"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := `{"id":"GHSA-x","affected":[{"package":{"ecosystem":"npm","name":"p"},
				"ranges":[{"type":"SEMVER","events":` + tt.events + `}]}]}`
			got, ok := decode(t, body, model.EcosystemNPM)
			if !ok {
				t.Fatal("advisory was not indexed")
			}
			ranges := got.Affected[0].Ranges
			if len(ranges) != len(tt.want) {
				t.Fatalf("got %d ranges, want %d: %+v", len(ranges), len(tt.want), ranges)
			}
			for i := range ranges {
				if ranges[i] != tt.want[i] {
					t.Errorf("range %d = %+v, want %+v", i, ranges[i], tt.want[i])
				}
			}
		})
	}
}

func TestToModelCVSS(t *testing.T) {
	const v3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" // 9.8
	const v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

	tests := []struct {
		name      string
		severity  string
		wantScore float64
		wantEmpty bool
	}{
		{
			name:      "no severity is not an error",
			severity:  `[]`,
			wantEmpty: true,
		},
		{
			name:      "cvss v3 is parsed",
			severity:  `[{"type":"CVSS_V3","score":"` + v3 + `"}]`,
			wantScore: 9.8,
		},
		{
			name:      "cvss v4 is used when it is all there is",
			severity:  `[{"type":"CVSS_V4","score":"` + v4 + `"}]`,
			wantScore: 9.3,
		},
		{
			// Most tools display v3, so showing a different number than the
			// advisory page for the same issue would invite mistrust.
			name:      "v3 is preferred when both are present",
			severity:  `[{"type":"CVSS_V4","score":"` + v4 + `"},{"type":"CVSS_V3","score":"` + v3 + `"}]`,
			wantScore: 9.8,
		},
		{
			name:      "a malformed vector is ignored rather than fatal",
			severity:  `[{"type":"CVSS_V3","score":"not-a-vector"}]`,
			wantEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := `{"id":"GHSA-x","severity":` + tt.severity + `,
				"affected":[{"package":{"ecosystem":"npm","name":"p"}}]}`
			got, ok := decode(t, body, model.EcosystemNPM)
			if !ok {
				t.Fatal("advisory was not indexed")
			}
			if tt.wantEmpty {
				if got.CVSSScore != 0 || got.CVSSVector != "" {
					t.Errorf("got score %v vector %q, want neither", got.CVSSScore, got.CVSSVector)
				}
				return
			}
			if got.CVSSScore != tt.wantScore {
				t.Errorf("score = %v, want %v", got.CVSSScore, tt.wantScore)
			}
			if got.CVSSVector == "" {
				t.Error("vector was not retained alongside the score")
			}
		})
	}
}

func TestToModelLeavesDetailsOutOfTheIndex(t *testing.T) {
	// Details is over half the memory of a large index while being needed only
	// for advisories a project actually matches; DB.Details reads it on demand.
	body := `{"id":"GHSA-x","summary":"short","details":"a long prose description",
		"affected":[{"package":{"ecosystem":"npm","name":"p"}}]}`
	got, ok := decode(t, body, model.EcosystemNPM)
	if !ok {
		t.Fatal("advisory was not indexed")
	}
	if got.Details != "" {
		t.Errorf("details were retained: %q", got.Details)
	}
	if got.Summary != "short" {
		t.Errorf("summary = %q, want it kept for the diagnostic message", got.Summary)
	}
}

// seedArchive downloads nothing: it writes an archive directly, so loader tests
// stay hermetic.
func seedArchive(t *testing.T, d *DB, e model.Ecosystem, advisories map[string]string) {
	t.Helper()
	body := fakeArchive(t, advisories)
	if err := writeFileAtomic(d.archivePath(e), body, 0o644); err != nil {
		t.Fatalf("seed archive: %v", err)
	}
}

func TestLoadBuildsAnIndex(t *testing.T) {
	srv := newArchiveServer(t, nil)
	d := newTestDB(t, srv)

	seedArchive(t, d, model.EcosystemNPM, map[string]string{
		"GHSA-1.json": advisoryJSON(t, map[string]any{
			"id":      "GHSA-1",
			"summary": "bad thing",
			"affected": []any{map[string]any{
				"package": map[string]any{"ecosystem": "npm", "name": "lodash"},
				"ranges": []any{map[string]any{"type": "SEMVER", "events": []any{
					map[string]any{"introduced": "0"},
					map[string]any{"fixed": "4.17.21"},
				}}},
			}},
		}),
		"GHSA-2.json": advisoryJSON(t, map[string]any{
			"id": "GHSA-2",
			"affected": []any{map[string]any{
				"package": map[string]any{"ecosystem": "npm", "name": "express"},
			}},
		}),
		"GHSA-gone.json": advisoryJSON(t, map[string]any{
			"id":        "GHSA-gone",
			"withdrawn": "2023-01-01T00:00:00Z",
			"affected": []any{map[string]any{
				"package": map[string]any{"ecosystem": "npm", "name": "lodash"},
			}},
		}),
		"not-json.txt": "ignored",
	})

	idx, err := d.Load(context.Background(), []model.Ecosystem{model.EcosystemNPM})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if got := idx.Advisories(); got != 2 {
		t.Errorf("indexed %d advisories, want 2 (the withdrawn one excluded)", got)
	}
	if got := idx.Packages(); got != 2 {
		t.Errorf("indexed %d packages, want 2", got)
	}

	lodash := idx.Lookup(model.PackageKey{Ecosystem: model.EcosystemNPM, Name: "lodash"})
	if len(lodash) != 1 {
		t.Fatalf("lodash has %d advisories, want 1", len(lodash))
	}
	if lodash[0].ID != "GHSA-1" {
		t.Errorf("lodash advisory = %q, want GHSA-1", lodash[0].ID)
	}

	if got := idx.Lookup(model.PackageKey{Ecosystem: model.EcosystemNPM, Name: "absent"}); got != nil {
		t.Errorf("lookup of an unaffected package returned %v, want nil", got)
	}
	if !idx.Covers([]model.Ecosystem{model.EcosystemNPM}) {
		t.Error("index does not report covering npm")
	}
	if idx.Covers([]model.Ecosystem{model.EcosystemGo}) {
		t.Error("index claims to cover Go, which was never loaded")
	}
}

func TestLoadWithoutAnArchiveIsNotReady(t *testing.T) {
	// "Not downloaded yet" must never be indistinguishable from "nothing is
	// vulnerable", which would be a silent false negative.
	srv := newArchiveServer(t, nil)
	d := newTestDB(t, srv)

	_, err := d.Load(context.Background(), []model.Ecosystem{model.EcosystemNPM})
	if !errors.Is(err, ErrNotReady) {
		t.Errorf("Load without an archive returned %v, want ErrNotReady", err)
	}
}

func TestLoadRejectsAnArchiveNothingCanBeDecodedFrom(t *testing.T) {
	// A zip that opens but whose entries are all garbage passes the zip
	// validation heal() does, so nothing upstream catches it. Loading it as a
	// successful empty index would report every project clean.
	srv := newArchiveServer(t, nil)
	d := newTestDB(t, srv)

	seedArchive(t, d, model.EcosystemNPM, map[string]string{
		"GHSA-1.json": "{ this is not json",
		"GHSA-2.json": "]]]",
	})

	_, err := d.Load(context.Background(), []model.Ecosystem{model.EcosystemNPM})
	if !errors.Is(err, ErrNotReady) {
		t.Errorf("Load of an undecodable archive returned %v, want ErrNotReady", err)
	}
}

func TestLoadKeepsGoingWhenOneAdvisoryIsUnreadable(t *testing.T) {
	// The opposite of the above: some entries decode, so the archive is intact
	// and the readable advisories are still worth having.
	srv := newArchiveServer(t, nil)
	d := newTestDB(t, srv)

	seedArchive(t, d, model.EcosystemNPM, map[string]string{
		"GHSA-broken.json": "{ not json",
		"GHSA-ok.json": advisoryJSON(t, map[string]any{
			"id": "GHSA-ok",
			"affected": []any{map[string]any{
				"package": map[string]any{"ecosystem": "npm", "name": "lodash"},
			}},
		}),
	})

	idx, err := d.Load(context.Background(), []model.Ecosystem{model.EcosystemNPM})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := idx.Advisories(); got != 1 {
		t.Errorf("indexed %d advisories, want 1 (the readable one)", got)
	}
}

func TestLoadAcceptsAnArchiveThatDecodesButIndexesNothing(t *testing.T) {
	// Withdrawn advisories are about 4% of a real archive. An archive of
	// nothing but withdrawn entries decodes cleanly and indexes nothing, and
	// that is not corruption — it must not be confused with the case above.
	srv := newArchiveServer(t, nil)
	d := newTestDB(t, srv)

	seedArchive(t, d, model.EcosystemNPM, map[string]string{
		"GHSA-withdrawn.json": advisoryJSON(t, map[string]any{
			"id":        "GHSA-withdrawn",
			"withdrawn": "2023-01-01T00:00:00Z",
			"affected": []any{map[string]any{
				"package": map[string]any{"ecosystem": "npm", "name": "lodash"},
			}},
		}),
	})

	idx, err := d.Load(context.Background(), []model.Ecosystem{model.EcosystemNPM})
	if err != nil {
		t.Fatalf("Load of an all-withdrawn archive: %v", err)
	}
	if got := idx.Advisories(); got != 0 {
		t.Errorf("indexed %d advisories, want 0", got)
	}
}

func TestLoadHonoursCancellation(t *testing.T) {
	srv := newArchiveServer(t, nil)
	d := newTestDB(t, srv)

	entries := make(map[string]string, 1000)
	for i := range 1000 {
		id := "GHSA-" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)) + string(rune('0'+i%10))
		entries[id+".json"] = advisoryJSON(t, map[string]any{
			"id": id,
			"affected": []any{map[string]any{
				"package": map[string]any{"ecosystem": "npm", "name": "p"},
			}},
		})
	}
	seedArchive(t, d, model.EcosystemNPM, entries)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.Load(ctx, []model.Ecosystem{model.EcosystemNPM}); err == nil {
		t.Error("expected an error from a cancelled load")
	}
}

func TestDetailsReadsFromTheArchive(t *testing.T) {
	srv := newArchiveServer(t, nil)
	d := newTestDB(t, srv)

	seedArchive(t, d, model.EcosystemNPM, map[string]string{
		"GHSA-1.json": advisoryJSON(t, map[string]any{
			"id":      "GHSA-1",
			"details": "the full prose description",
			"affected": []any{map[string]any{
				"package": map[string]any{"ecosystem": "npm", "name": "lodash"},
			}},
		}),
	})

	got, err := d.Details(model.EcosystemNPM, "GHSA-1")
	if err != nil {
		t.Fatalf("Details: %v", err)
	}
	if want := "the full prose description"; got != want {
		t.Errorf("Details = %q, want %q", got, want)
	}

	if _, err := d.Details(model.EcosystemNPM, "GHSA-absent"); err == nil {
		t.Error("expected an error for an unknown advisory")
	}
}

func TestNilIndexIsSafe(t *testing.T) {
	// A scan can run before the first load completes.
	var idx *Index
	if got := idx.Lookup(model.PackageKey{}); got != nil {
		t.Errorf("Lookup on a nil index = %v, want nil", got)
	}
	if idx.Covers([]model.Ecosystem{model.EcosystemNPM}) {
		t.Error("a nil index claims coverage")
	}
	if idx.Advisories() != 0 || idx.Packages() != 0 {
		t.Error("a nil index reports non-zero counts")
	}
}
