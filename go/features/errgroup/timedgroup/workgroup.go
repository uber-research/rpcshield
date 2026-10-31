// Package sync is a minimal test fixture modeling a common production errgroup-wrapper shape
// (a WorkGroup with Go()/Wait()/AnyTimedOut()) that rpcshield's errgroup enricher discovers
// structurally, independent of this package's import path.
package sync

import (
	"sync"
	"time"
)

// Completion is invoked after a Go'd function returns, reporting whether it timed out.
type Completion func(timedOut bool)

// WorkGroup is a zero-value-usable errgroup wrapper. The real implementation also enforces
// per-task timeouts; that behavior isn't needed for this fixture.
type WorkGroup struct {
	wg       sync.WaitGroup
	mu       sync.Mutex
	err      error
	timedOut bool
}

// Go runs f in a new goroutine, tracked by the group, invoking completion when it finishes.
func (r *WorkGroup) Go(f func() error, completion Completion, timeout time.Duration) {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		done := make(chan error, 1)
		go func() { done <- f() }()

		select {
		case err := <-done:
			if err != nil {
				r.mu.Lock()
				if r.err == nil {
					r.err = err
				}
				r.mu.Unlock()
			}
			if completion != nil {
				completion(false)
			}
		case <-time.After(timeout):
			r.mu.Lock()
			r.timedOut = true
			r.mu.Unlock()
			if completion != nil {
				completion(true)
			}
		}
	}()
}

// Wait blocks until all goroutines started via Go have completed, then returns
// the first non-nil error (if any).
func (r *WorkGroup) Wait() error {
	r.wg.Wait()
	return r.err
}

// AnyTimedOut reports whether any Go'd function exceeded its timeout.
func (r *WorkGroup) AnyTimedOut() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.timedOut
}
