// Package engine decides when to scan and what to publish.
//
// It owns scheduling and diagnostic state, not analysis: everything about
// finding vulnerabilities sits behind Scanner, so the concurrency here can be
// tested against fakes with no filesystem, network or editor involved.
//
// All mutable state lives in a single goroutine. Nothing in this package takes
// a lock, because nothing is shared.
package engine

import (
	"context"

	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// Scanner produces the findings for a project.
//
// One seam covering extraction, the advisory database and matching. The engine
// does not care how a report is produced, only when to ask for one, and a
// single interface keeps the concurrency tests free of every dependency those
// stages carry.
//
// Implementations must honour cancellation: a scan whose results are no longer
// wanted is abandoned mid-flight.
type Scanner interface {
	Scan(ctx context.Context, root string) (model.Report, error)
}

// Publisher delivers the findings for one file to the editor.
//
// Called with an empty slice to clear a file that previously had findings, so
// implementations must treat "no findings" as a message to send rather than one
// to skip. Not sending it leaves stale diagnostics on screen.
type Publisher interface {
	Publish(ctx context.Context, path string, findings []model.Finding) error
}

// Reason records what triggered a scan, for logging.
type Reason string

// Scan triggers.
const (
	ReasonStartup      Reason = "startup"
	ReasonFileChanged  Reason = "file changed"
	ReasonFileSaved    Reason = "file saved"
	ReasonDatabaseSync Reason = "database updated"
	ReasonManual       Reason = "requested"
)
