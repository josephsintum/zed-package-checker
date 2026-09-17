package lsp

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"go.lsp.dev/protocol"

	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// DownloadProgress reports advisory database downloads to the editor as
// $/progress, satisfying db.Progress.
//
// npm's archive is 205 MB and the first scan of a JS project cannot report
// anything until it lands. Without this the editor shows nothing for minutes,
// which reads as a broken extension rather than a busy one.
//
// One token per ecosystem: a project with both npm and PyPI dependencies
// downloads both, and a shared token would make two sets of numbers fight over
// one progress entry.
type DownloadProgress struct {
	log *slog.Logger

	mu     sync.Mutex
	tokens map[model.Ecosystem]protocol.ProgressToken
}

// createTimeout bounds the one blocking request this makes of the client.
const createTimeout = 5 * time.Second

// NewDownloadProgress builds a reporter. Safe for concurrent use.
func NewDownloadProgress(log *slog.Logger) *DownloadProgress {
	return &DownloadProgress{
		log:    log,
		tokens: make(map[model.Ecosystem]protocol.ProgressToken),
	}
}

// Start asks the client for a progress token and opens the entry.
//
// A client that refuses the token simply gets no notifications; the download
// is unaffected and proceeds silently.
func (p *DownloadProgress) Start(ctx context.Context, e model.Ecosystem, total int64) {
	client, ok := protocol.ClientFromContext(ctx)
	if !ok {
		return
	}

	// This is a request, not a notification: it blocks until the client
	// answers. A client that advertises nothing and simply never replies would
	// otherwise hold the download — and every ecosystem queued behind it — for
	// the whole warm timeout. Progress is worth a moment, never a stall.
	createCtx, cancel := context.WithTimeout(ctx, createTimeout)
	defer cancel()

	token := protocol.String("package-checker/db/" + e.String())
	err := client.WorkDoneProgressCreate(createCtx, &protocol.WorkDoneProgressCreateParams{Token: token})
	if err != nil {
		p.log.Debug("client refused a progress token",
			"ecosystem", e.String(), "error", err)
		return
	}

	p.mu.Lock()
	p.tokens[e] = token
	p.mu.Unlock()

	p.notify(ctx, client, token, protocol.WorkDoneProgressBegin{
		Kind:       "begin",
		Title:      fmt.Sprintf("Downloading %s advisories", e),
		Message:    new(describeSize(0, total)),
		Percentage: percentage(0, total),
	})
}

// Advance updates the entry. Already rate-limited by the caller.
func (p *DownloadProgress) Advance(ctx context.Context, e model.Ecosystem, downloaded, total int64) {
	client, token, ok := p.entry(ctx, e)
	if !ok {
		return
	}
	p.notify(ctx, client, token, protocol.WorkDoneProgressReport{
		Kind:       "report",
		Message:    new(describeSize(downloaded, total)),
		Percentage: percentage(downloaded, total),
	})
}

// Done closes the entry, reporting the outcome.
//
// The token is dropped whether the download succeeded or not: a failed one is
// retried with a fresh token rather than reusing a closed entry.
func (p *DownloadProgress) Done(ctx context.Context, e model.Ecosystem, err error) {
	client, token, ok := p.take(ctx, e)
	if !ok {
		return
	}

	message := fmt.Sprintf("%s advisories ready", e)
	if err != nil {
		message = fmt.Sprintf("%s advisories unavailable: %v", e, err)
	}
	p.notify(ctx, client, token, protocol.WorkDoneProgressEnd{
		Kind:    "end",
		Message: &message,
	})
}

// take is entry, and forgets the token as it goes.
//
// Reading and deleting under one lock is what makes an entry close exactly
// once: separate acquisitions leave a window in which two callers both see the
// token and both send an end for it.
func (p *DownloadProgress) take(ctx context.Context, e model.Ecosystem) (protocol.Client, protocol.ProgressToken, bool) {
	client, ok := protocol.ClientFromContext(ctx)
	if !ok {
		return nil, nil, false
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	token, started := p.tokens[e]
	if !started {
		return nil, nil, false
	}
	delete(p.tokens, e)
	return client, token, true
}

// entry returns the client and the live token for an ecosystem, if both exist.
func (p *DownloadProgress) entry(ctx context.Context, e model.Ecosystem) (protocol.Client, protocol.ProgressToken, bool) {
	client, ok := protocol.ClientFromContext(ctx)
	if !ok {
		return nil, nil, false
	}
	p.mu.Lock()
	token, started := p.tokens[e]
	p.mu.Unlock()
	if !started {
		return nil, nil, false
	}
	return client, token, true
}

// notify sends one $/progress. A failure is logged and dropped: losing a
// progress update is not a reason to disturb the download.
func (p *DownloadProgress) notify(ctx context.Context, client protocol.Client, token protocol.ProgressToken, value any) {
	err := client.Progress(ctx, &protocol.ProgressParams{Token: token, Value: encodeData(value)})
	if err != nil {
		p.log.Debug("progress notification failed", "error", err)
	}
}

// percentage is nil when the total is unknown, which tells the client to show
// an indeterminate bar rather than a number that is wrong.
func percentage(downloaded, total int64) *uint32 {
	if total <= 0 {
		return nil
	}
	pct := min(downloaded*100/total, 100)
	return new(uint32(pct))
}

// describeSize renders "12.4 MB of 205.0 MB", or just the running count when
// the server sent no Content-Length.
func describeSize(downloaded, total int64) string {
	if total <= 0 {
		return megabytes(downloaded)
	}
	return megabytes(downloaded) + " of " + megabytes(total)
}

func megabytes(n int64) string {
	return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
}
