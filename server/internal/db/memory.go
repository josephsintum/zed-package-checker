package db

import "github.com/josephsintum/zed-package-checker/server/internal/model"

// retainedBytes is what one ecosystem's parsed index holds once loaded.
//
// Measured with `dbcheck -runs 1 -load <ecosystem>`, which reports HeapAlloc
// after a forced GC. These move slowly — npm grew roughly 4% over the months
// this was built — so they are a sizing hint rather than a contract, and
// MemoryLimitFor multiplies them generously.
var retainedBytes = map[model.Ecosystem]int64{
	model.EcosystemNPM:    110 << 20,
	model.EcosystemPyPI:   59 << 20,
	model.EcosystemGo:     11 << 20,
	model.EcosystemCrates: 3 << 20,
}

// limitFloor is the smallest limit worth setting.
//
// Below this the limit would bind on a project whose index is already tiny,
// making the collector work harder for no reason: a Go-only project retains
// 11 MB and was never the problem.
const limitFloor = 128 << 20

// limitHeadroom covers what a load allocates transiently on top of what it
// keeps. Decoding fans out across every core, so the garbage in flight is a
// multiple of the result, not a constant.
const limitHeadroom = 3

// MemoryLimitFor returns a soft heap limit for loading these ecosystems.
//
// Parallel decoding raises the allocation rate enough that Go's collector
// overshoots badly: loading npm settles at 110 MB retained but peaks at 467 MB,
// with 16% of CPU spent collecting. A soft limit costs about 8% of load time
// and returns the footprint to roughly what it was before the loader went
// parallel; GOGC does the same job but trades away twice the throughput.
//
//	npm              1,032 ms   469 MiB peak
//	npm, GOGC=50     1,867 ms   305 MiB
//	npm, 350 MiB     1,117 ms   351 MiB
//
// Derived rather than fixed because the right ceiling depends on what is being
// loaded: 350 MiB suits npm alone and would thrash a project on all four.
func MemoryLimitFor(ecosystems []model.Ecosystem) int64 {
	var retained int64
	for _, e := range ecosystems {
		retained += retainedBytes[e]
	}

	limit := retained * limitHeadroom
	if limit < limitFloor {
		return limitFloor
	}
	return limit
}
