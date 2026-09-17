package db

import (
	"strings"

	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"

	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// osvAdvisory is the subset of the OSV schema the checker reads.
//
// Deliberately partial: an advisory's JSON averages several kilobytes, most of
// it prose, credits and provenance that never reaches a diagnostic. Decoding
// only these fields is what keeps a parsed database small enough to hold in
// memory, and a field left out here is skipped by the decoder rather than
// allocated and discarded.
type osvAdvisory struct {
	ID        string   `json:"id"`
	Withdrawn string   `json:"withdrawn"`
	Aliases   []string `json:"aliases"`
	Summary   string   `json:"summary"`

	Severity   []osvSeverity  `json:"severity"`
	Affected   []osvAffected  `json:"affected"`
	References []osvReference `json:"references"`
}

// osvSeverity is one rating. An advisory may carry several, in more than one
// CVSS version.
type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// osvAffected is one package an advisory affects, within one ecosystem.
type osvAffected struct {
	Package  osvPackage `json:"package"`
	Ranges   []osvRange `json:"ranges"`
	Versions []string   `json:"versions"`
}

// osvPackage names an affected package in its registry's own spelling.
type osvPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// osvRange is one version timeline for a package.
type osvRange struct {
	Events []osvEvent `json:"events"`
}

// osvEvent is a single point on that timeline. A range is a sequence of these
// rather than a pair of bounds, which is the shape flattenRanges resolves.
type osvEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
}

// osvReference is a link carried by an advisory.
type osvReference struct {
	URL string `json:"url"`
}

// toModel converts a decoded advisory, keeping only the entries affecting the
// ecosystem being loaded.
//
// Returns ok false when the advisory should not be indexed at all: withdrawn,
// or affecting nothing in this ecosystem. An advisory routinely covers several
// ecosystems, and carrying the irrelevant entries would inflate every index
// with data no lookup can reach.
func (a *osvAdvisory) toModel(want model.Ecosystem) (model.Advisory, bool) {
	// Withdrawn advisories are retracted, not fixed. Roughly 4% of a typical
	// archive, and reporting one is a pure false positive.
	if a.Withdrawn != "" || a.ID == "" {
		return model.Advisory{}, false
	}

	var affected []model.Affected
	for _, entry := range a.Affected {
		if model.Ecosystem(entry.Package.Ecosystem) != want || entry.Package.Name == "" {
			continue
		}
		affected = append(affected, model.Affected{
			Package:  model.PackageKey{Ecosystem: want, Name: entry.Package.Name},
			Ranges:   flattenRanges(entry.Ranges),
			Versions: entry.Versions,
		})
	}

	if len(affected) == 0 {
		return model.Advisory{}, false
	}

	score, vector := a.cvss()
	refs := make([]string, 0, len(a.References))
	for _, r := range a.References {
		if r.URL != "" {
			refs = append(refs, r.URL)
		}
	}

	return model.Advisory{
		ID:      a.ID,
		Aliases: a.Aliases,
		Summary: a.Summary,
		// Details is left empty, and is not a field above either: declaring it
		// cost 1,947 bytes of allocation per advisory for a string this drops,
		// about 445 MB across npm's archive. DB.Details reads it from the
		// archive on demand instead.
		CVSSScore:  score,
		CVSSVector: vector,
		Affected:   affected,
		References: refs,
	}, true
}

// flattenRanges turns OSV's event timelines into explicit ranges.
//
// A range is a sequence of events along one version timeline rather than a pair
// of bounds: an "introduced" opens a window, and the next "fixed" or
// "last_affected" closes it. An introduction that is never closed means still
// affected, and stays open-ended.
//
// This is the subtlest transformation in the program and the one most able to
// be confidently wrong — pairing an event with the wrong introduction makes an
// advisory match versions it does not affect. It is stated here on its own
// rather than nested inside the filtering toModel does, so that
// TestToModelPairsRangeEvents has something to point at.
func flattenRanges(ranges []osvRange) []model.AffectedRange {
	var out []model.AffectedRange
	for _, r := range ranges {
		var current model.AffectedRange
		open := false

		for _, ev := range r.Events {
			switch {
			case ev.Introduced != "":
				if open {
					out = append(out, current)
				}
				current = model.AffectedRange{Introduced: ev.Introduced}
				open = true
			case ev.Fixed != "":
				current.Fixed = ev.Fixed
				out = append(out, current)
				open = false
			case ev.LastAffected != "":
				current.LastAffected = ev.LastAffected
				out = append(out, current)
				open = false
			}
		}
		if open {
			out = append(out, current)
		}
	}
	return out
}

// cvss returns a base score and the vector it came from.
//
// OSV carries the vector string, not a number, so the score is computed. Both
// CVSS v3 and v4 appear, often on the same advisory; v3.1 is preferred because
// it is what almost every other tool displays, and showing a different number
// than the GitHub advisory page for the same issue invites mistrust. Around a
// third of advisories carry no severity at all, which is not an error.
func (a *osvAdvisory) cvss() (score float64, vector string) {
	var v4 string
	for _, s := range a.Severity {
		switch {
		case strings.EqualFold(s.Type, "CVSS_V3"):
			if c, err := gocvss31.ParseVector(s.Score); err == nil {
				return c.BaseScore(), s.Score
			}
		case strings.EqualFold(s.Type, "CVSS_V4"):
			if v4 == "" {
				v4 = s.Score
			}
		}
	}
	if v4 != "" {
		if c, err := gocvss40.ParseVector(v4); err == nil {
			return c.Score(), v4
		}
	}
	return 0, ""
}
