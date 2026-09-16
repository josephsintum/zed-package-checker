package db

import (
	"time"

	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// Index is a parsed advisory database, held in memory and keyed by package.
//
// Built once per process and rebuilt only when the archives change, never per
// scan. Parsing on every scan is what made the naive approach cost seconds and
// hundreds of megabytes; a lookup here is a map access.
//
// Immutable once built, so it can be read concurrently without locking. A
// refresh produces a new Index rather than mutating this one.
type Index struct {
	byPackage  map[model.PackageKey][]model.Advisory
	ecosystems []model.Ecosystem
	builtAt    time.Time
	advisories int
}

// Lookup returns the advisories affecting a package, in the order the archive
// listed them. The result must not be modified.
//
// Returns nil for a package with no advisories, which is the overwhelmingly
// common case and deliberately allocation-free.
func (i *Index) Lookup(key model.PackageKey) []model.Advisory {
	if i == nil {
		return nil
	}
	return i.byPackage[key]
}

// Ecosystems reports which ecosystems this index was built from. A lookup for
// any other ecosystem finds nothing, which would otherwise look like "no
// advisories" rather than "not loaded".
func (i *Index) Ecosystems() []model.Ecosystem {
	if i == nil {
		return nil
	}
	return i.ecosystems
}

// Covers reports whether the index was built from every listed ecosystem.
func (i *Index) Covers(ecosystems []model.Ecosystem) bool {
	if i == nil {
		return false
	}
	have := make(map[model.Ecosystem]bool, len(i.ecosystems))
	for _, e := range i.ecosystems {
		have[e] = true
	}
	for _, e := range ecosystems {
		if !have[e] {
			return false
		}
	}
	return true
}

// Advisories returns how many advisories were indexed, and Packages how many
// distinct packages they affect. Used for logging and for the memory
// measurements the loading design rests on.
func (i *Index) Advisories() int {
	if i == nil {
		return 0
	}
	return i.advisories
}

// Packages returns the number of distinct affected packages.
func (i *Index) Packages() int {
	if i == nil {
		return 0
	}
	return len(i.byPackage)
}

// BuiltAt is when the index was parsed.
func (i *Index) BuiltAt() time.Time {
	if i == nil {
		return time.Time{}
	}
	return i.builtAt
}
