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
// memory.
type osvAdvisory struct {
	ID        string   `json:"id"`
	Withdrawn string   `json:"withdrawn"`
	Aliases   []string `json:"aliases"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`

	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`

	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced   string `json:"introduced"`
				Fixed        string `json:"fixed"`
				LastAffected string `json:"last_affected"`
			} `json:"events"`
		} `json:"ranges"`
		Versions []string `json:"versions"`
	} `json:"affected"`

	References []struct {
		URL string `json:"url"`
	} `json:"references"`
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
		key := model.PackageKey{Ecosystem: want, Name: entry.Package.Name}

		var ranges []model.AffectedRange
		for _, r := range entry.Ranges {
			// A range is a sequence of events along one timeline, so a fix or
			// last-affected marker belongs to the introduction preceding it.
			var current model.AffectedRange
			open := false
			for _, ev := range r.Events {
				switch {
				case ev.Introduced != "":
					if open {
						ranges = append(ranges, current)
					}
					current = model.AffectedRange{Introduced: ev.Introduced}
					open = true
				case ev.Fixed != "":
					current.Fixed = ev.Fixed
					ranges = append(ranges, current)
					open = false
				case ev.LastAffected != "":
					current.LastAffected = ev.LastAffected
					ranges = append(ranges, current)
					open = false
				}
			}
			// An introduction with no fix means still affected.
			if open {
				ranges = append(ranges, current)
			}
		}

		affected = append(affected, model.Affected{
			Package:  key,
			Ranges:   ranges,
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
		// Details is deliberately left empty. It is full markdown prose,
		// averaging 662 bytes, and across npm's 228k advisories accounts for
		// 151 MB of a 257 MB index — more than half, to render hover text for
		// the two or three advisories a project actually matches. DB.Details
		// reads it from the archive on demand instead.
		CVSSScore:  score,
		CVSSVector: vector,
		Affected:   affected,
		References: refs,
	}, true
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
