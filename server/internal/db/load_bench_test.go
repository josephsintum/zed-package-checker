package db

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// benchAdvisories is large enough for the per-entry costs to dominate the
// fixed ones, and small enough that the benchmark is worth running often. npm
// ships 228,368; the shape of the work is the same.
const benchAdvisories = 5000

// benchArchivePath writes an archive of synthetic advisories and returns it.
//
// Built once per benchmark rather than per iteration: generating it costs more
// than loading it, and it is not what is being measured.
func benchArchivePath(b *testing.B) string {
	b.Helper()

	entries := make(map[string]string, benchAdvisories)
	for i := range benchAdvisories {
		id := fmt.Sprintf("GHSA-%06d", i)
		entries[id+".json"] = advisoryJSON(b, map[string]any{
			"id":      id,
			"summary": "a synthetic advisory for benchmarking",
			"details": "Prose the index deliberately discards. " +
				"Real advisories average 662 bytes of it, which is why the " +
				"field is not decoded; a benchmark without it would measure " +
				"an archive that does not exist.",
			"severity": []any{map[string]any{
				"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			}},
			"affected": []any{map[string]any{
				"package": map[string]any{"ecosystem": "npm", "name": fmt.Sprintf("pkg-%d", i%1000)},
				"ranges": []any{map[string]any{"type": "SEMVER", "events": []any{
					map[string]any{"introduced": "0"},
					map[string]any{"fixed": "1.2.3"},
				}}},
			}},
			"references": []any{map[string]any{"url": "https://example.test/" + id}},
		})
	}

	path := filepath.Join(b.TempDir(), "all.zip")
	if err := os.WriteFile(path, fakeArchive(b, entries), 0o644); err != nil {
		b.Fatalf("write archive: %v", err)
	}
	return path
}

// BenchmarkLoadArchive covers the whole load: inflate, decode and index.
//
// Report allocations as well as time. The loader's cost has moved more than
// once — inflate dominated until a faster one was registered, then decoding,
// and the allocation rate is what makes the collector overshoot — so a change
// that trades one for another should be visible here rather than inferred.
func BenchmarkLoadArchive(b *testing.B) {
	path := benchArchivePath(b)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		idx := &Index{byPackage: make(map[model.PackageKey][]model.Advisory)}
		if _, _, err := loadArchive(ctx, path, model.EcosystemNPM, idx); err != nil {
			b.Fatalf("loadArchive: %v", err)
		}
	}
}

// BenchmarkDecodeAdvisory isolates parsing from inflating and indexing.
//
// The two answer different questions: one is about the JSON implementation,
// the other about the DEFLATE one. Measuring only the total made it possible
// to attribute a win to the wrong half.
func BenchmarkDecodeAdvisory(b *testing.B) {
	raw := []byte(advisoryJSON(b, map[string]any{
		"id":      "GHSA-0001",
		"summary": "a synthetic advisory for benchmarking",
		"details": "Prose the index deliberately discards.",
		"affected": []any{map[string]any{
			"package": map[string]any{"ecosystem": "npm", "name": "lodash"},
			"ranges": []any{map[string]any{"type": "SEMVER", "events": []any{
				map[string]any{"introduced": "0"},
				map[string]any{"fixed": "4.17.21"},
			}}},
		}},
	}))

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		var advisory osvAdvisory
		if err := json.Unmarshal(raw, &advisory); err != nil {
			b.Fatalf("decode: %v", err)
		}
		if _, ok := advisory.toModel(model.EcosystemNPM); !ok {
			b.Fatal("advisory did not convert")
		}
	}
}
