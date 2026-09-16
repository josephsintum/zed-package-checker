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

func newRealTimer(d time.Duration) timer {
	t := time.NewTimer(d)
	if !t.Stop() {
		<-t.C
	}
	return &realTimer{t: t}
}

func (r *realTimer) C() <-chan time.Time { return r.t.C }

func (r *realTimer) Reset(d time.Duration) {
	r.Stop()
	r.t.Reset(d)
}

// Stop halts the timer and drains a value that fired before the stop took
// effect, so a later Reset cannot deliver a stale expiry.
func (r *realTimer) Stop() {
	if !r.t.Stop() {
		select {
		case <-r.t.C:
		default:
		}
	}
}
