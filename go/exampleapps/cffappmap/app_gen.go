//go:build !cff

package main

import (
	"context"
	"fmt"
	"runtime/debug"
	"time"

	"go.uber.org/cff"
)

// Sink represents a downstream/outbound call site whose reachability we're testing.
func Sink(value int) error {
	return nil
}

// AFunctionWithUniqueName is the checked-in ground truth for what the CURRENT internal `cff`
// codegen tool actually emits for a ctx-less, key/value-first cff.Map task closure -- captured
// (module/package names aside) via:
//
//	bazel build --output_groups=go_generated_srcs //.../internal/tests/mapctxless:cff
//
// Same hybrid shape as cffappctxlessslice: the original call site is rewritten to call a
// separately synthesized, uniquely-named top-level generic function
// (_cffParallel..._<line>_<col>), whose second argument is a call to another synthesized generic
// function (_cffMap..._<line>_<col>) that takes the user's RAW original closure directly.
func AFunctionWithUniqueName(ctx context.Context, m map[string]int) error {
	return _cffParallelcffappmap_18_9(
		ctx,
		_cffMapcffappmap_20_3[func(key string, value int) error, map[string]int](func(key string, value int) error {
			return Sink(value)
		}, m),
	)
}

func _cffParallelcffappmap_18_9[
	ct1 comparable,
	t2 any,
](
	ctx context.Context,
	mMapSeed func() (func(ct1, t2) error, map[ct1]t2),
) (err error) {
	mTaskFn, mMap := mMapSeed()
	_, _ = mTaskFn, mMap

	parallelEmitter := cff.NopParallelEmitter()
	startTime := time.Now()
	defer func() { parallelEmitter.ParallelDone(ctx, time.Since(startTime)) }()

	schedEmitter := cff.NopEmitter().SchedulerInit(&cff.SchedulerInfo{
		Name:      "",
		Directive: cff.ParallelDirective,
		File:      "go.uber.org/cff/internal/tests/mapctxless/mapctxless.go",
		Line:      18,
		Column:    9,
	})
	sched := cff.NewScheduler(cff.SchedulerParams{
		Emitter: schedEmitter,
	})

	var tasks []*struct {
		emitter cff.TaskEmitter
		fn      func(context.Context) error
		ran     cff.AtomicBool
	}
	defer func() {
		for _, t := range tasks {
			if !t.ran.Load() {
				t.emitter.TaskSkipped(ctx, err)
			}
		}
	}()

	for key, val := range mMap {
		key := key
		val := val
		mapTask0 := new(struct {
			emitter cff.TaskEmitter
			fn      func(context.Context) error
			ran     cff.AtomicBool
		})
		mapTask0.fn = func(ctx context.Context) (err error) {
			defer func() {
				recovered := recover()
				if recovered != nil {
					err = &cff.PanicError{
						Value:      recovered,
						Stacktrace: debug.Stack(),
					}
				}
			}()
			err = mTaskFn(key, val)
			return
		}
		tasks = append(tasks, mapTask0)
		sched.Enqueue(ctx, cff.Job{
			Run: mapTask0.fn,
		})
	}

	if err := sched.Wait(ctx); err != nil {
		parallelEmitter.ParallelError(ctx, err)
		return err
	}
	parallelEmitter.ParallelSuccess(ctx)
	return nil
}

func _cffMapcffappmap_20_3[
	t3 any,
	t4 any,
](
	mTaskFn t3,
	mMap t4,
) func() (t3, t4) {
	return func() (t3, t4) {
		return mTaskFn, mMap
	}
}

func main() {
	ctx := context.Background()
	if err := AFunctionWithUniqueName(ctx, map[string]int{"a": 1}); err != nil {
		fmt.Println("Error:", err)
	}
}
