package match

import (
	"fmt"
	"slices"

	"github.com/google/osv-scalibr/semantic"

	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// introducedFromTheBeginning is OSV's sentinel for "affected since the first
// release", used when no introducing version is known. It is not a version
// string and must not be compared as one.
const introducedFromTheBeginning = "0"

// affects reports whether version falls inside any of the advisory's ranges or
// explicit version lists for key.
//
// Version ordering is ecosystem-specific and this is the only place that
// matters: npm semver, PEP 440, Go's scheme and Cargo each sort prereleases
// differently, and getting it wrong produces confident wrong answers rather
// than visible errors.
func affects(a model.Advisory, pkg model.Package) (bool, error) {
	for _, entry := range a.Affected {
		if entry.Package != pkg.PackageKey {
			continue
		}

		// An explicit version list is authoritative for the versions it names,
		// and OSV uses it for ecosystems with no reliable ordering.
		if slices.Contains(entry.Versions, pkg.Version) {
			return true, nil
		}

		for _, r := range entry.Ranges {
			in, err := inRange(r, pkg)
			if err != nil {
				return false, err
			}
			if in {
				return true, nil
			}
		}
	}
	return false, nil
}

// inRange reports whether a version falls within one affected range.
//
// Ranges are half-open: affected at or after Introduced, and before Fixed. A
// version exactly equal to Fixed is NOT affected — that is the whole point of
// publishing a fix — while a version exactly equal to Introduced is.
func inRange(r model.AffectedRange, pkg model.Package) (bool, error) {
	if r.Introduced != "" && r.Introduced != introducedFromTheBeginning {
		cmp, err := compare(pkg, r.Introduced)
		if err != nil {
			return false, err
		}
		if cmp < 0 {
			return false, nil
		}
	}

	switch {
	case r.Fixed != "":
		cmp, err := compare(pkg, r.Fixed)
		if err != nil {
			return false, err
		}
		return cmp < 0, nil

	case r.LastAffected != "":
		// LastAffected names the final bad version rather than the first good
		// one, so the comparison is inclusive.
		cmp, err := compare(pkg, r.LastAffected)
		if err != nil {
			return false, err
		}
		return cmp <= 0, nil

	default:
		// Introduced with no upper bound: affected, and no fix exists yet.
		return true, nil
	}
}

// compare orders a package's version against another version string from the
// same ecosystem, returning -1, 0 or +1.
func compare(pkg model.Package, other string) (int, error) {
	v, err := semantic.Parse(pkg.Version, pkg.Ecosystem.String())
	if err != nil {
		return 0, fmt.Errorf("parse %s version %q: %w", pkg.Ecosystem, pkg.Version, err)
	}
	cmp, err := v.CompareStr(other)
	if err != nil {
		return 0, fmt.Errorf("compare %s against %q: %w", pkg, other, err)
	}
	return cmp, nil
}
