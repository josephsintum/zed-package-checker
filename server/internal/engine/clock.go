package engine

import "time"

// timer is the subset of time.Timer the debounce needs.
//
// Abstracted so tests can fire the debounce on demand rather than sleeping.
// Timing tests that sleep are slow when they pass and flaky when they fail,
// which is the wrong trade for the one piece of this system where ordering is
// the whole point.
type timer interface {
	// C delivers a value when the timer expires.
	C() <-chan time.Time

	// Reset restarts the timer, discarding any pending expiry.
	Reset(d time.Duration)

	// Stop halts the timer. Safe to call when already stopped.
	Stop()
}

// realTimer wraps time.Timer.
type realTimer struct{ t *time.Timer }

// newRealTimer returns a timer that is not running.
//
// The debounce is armed by Reset when a request arrives, never at construction:
// a timer left running here would schedule a scan nobody asked for.
func newRealTimer(d time.Duration) timer {
	t := time.NewTimer(d)
	t.Stop()
	return &realTimer{t: t}
}

func (r *realTimer) C() <-chan time.Time { return r.t.C }

// Reset restarts the timer.
//
// The Stop is redundant under the timer semantics this module compiles with,
// but it is kept: GODEBUG=asynctimerchan=1 restores the old behaviour, where
// dropping it would let a stale expiry through.
func (r *realTimer) Reset(d time.Duration) {
	r.Stop()
	r.t.Reset(d)
}

// Stop halts the timer.
//
// Nothing is drained afterwards. Since Go 1.23 a timer channel is unbuffered
// and Stop discards any pending send, so the receive this used to attempt
// could never run — the module's go directive puts it well past that line.
func (r *realTimer) Stop() {
	r.t.Stop()
}
