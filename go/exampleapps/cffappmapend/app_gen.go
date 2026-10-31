//go:build !cff

package main

import (
	"context"
	"fmt"
	"runtime/debug"
	"time"

	"go.uber.org/cff"
)

// Sink represents a downstream/outbound call site whose reachability we're testing, reached only
// from the MapEnd closure (not the main Map task closure).
func Sink(n int) error {
	return nil
}

// AFunctionWithUniqueName is the checked-in ground truth for what the CURRENT internal `cff`
// codegen tool actually emits for a cff.MapEnd construct -- captured (module/package names aside)
// via:
//
//	bazel build --output_groups=go_generated_srcs //.../internal/tests/mapendctx:cff
//
// Same shape as cffappsliceend, for cff.Map instead of cff.Slice: the MapEnd closure is wrapped
// via _cffMapEndcffappmapend_..., nested as the THIRD argument to _cffMapcffappmapend_...'s
// wrapper call.
func AFunctionWithUniqueName(ctx context.Context, m map[string]int) error {
	return _cffParallelcffappmapend_18_9(
		ctx,
		_cffMapcffappmapend_20_3[func(key string, value int) error, map[string]int](func(key string, value int) error {
			return nil
		}, m,
			_cffMapEndcffappmapend_1745492981(func(ctx context.Context) error {
				return Sink(len(m))
			}),
		),
	)
}

func _cffParallelcffappmapend_18_9[
	ct1 comparable,
	t2 any,
](
	ctx context.Context,
	mMapSeed func() (func(ct1, t2) error, map[ct1]t2, func(ctx context.Context) error),
) (err error) {
	mTaskFn, mMap, mEndFn := mMapSeed()
	_, _, _ = mTaskFn, mMap, mEndFn

	parallelEmitter := cff.NopParallelEmitter()
	startTime := time.Now()
	defer func() { parallelEmitter.ParallelDone(ctx, time.Since(startTime)) }()

	schedEmitter := cff.NopEmitter().SchedulerInit(&cff.SchedulerInfo{
		Name:      "",
		Directive: cff.ParallelDirective,
		File:      "go.uber.org/cff/internal/tests/mapendctx/mapendctx.go",
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

	mapTask0Jobs := make([]*cff.ScheduledJob, 0, len(mMap))
	mapTask0Emitter := cff.NopTaskEmitter()
	for key, val := range mMap {
		key := key
		val := val
		mapTask0 := new(struct {
			emitter cff.TaskEmitter
			fn      func(context.Context) error
			ran     cff.AtomicBool
		})
		mapTask0.fn = func(ctx context.Context) (err error) {
			taskEmitter := mapTask0Emitter
			startTime := time.Now()
			defer func() {
				taskEmitter.TaskDone(ctx, time.Since(startTime))
			}()
			defer func() {
				recovered := recover()
				if recovered != nil {
					taskEmitter.TaskPanic(ctx, recovered)
					err = &cff.PanicError{
						Value:      recovered,
						Stacktrace: debug.Stack(),
					}
				}
			}()
			err = mTaskFn(key, val)
			if err != nil {
				taskEmitter.TaskError(ctx, err)
				return
			}
			taskEmitter.TaskSuccess(ctx)
			return
		}
		tasks = append(tasks, mapTask0)
		mapTask0Jobs = append(mapTask0Jobs, sched.Enqueue(ctx, cff.Job{
			Run: mapTask0.fn,
		}))
	}

	sched.Enqueue(ctx, cff.Job{
		Dependencies: mapTask0Jobs,
		Run: func(ctx context.Context) (err error) {
			taskEmitter := mapTask0Emitter
			startTime := time.Now()
			defer func() {
				taskEmitter.TaskDone(ctx, time.Since(startTime))
			}()
			defer func() {
				recovered := recover()
				if recovered != nil {
					taskEmitter.TaskPanic(ctx, recovered)
					err = &cff.PanicError{
						Value:      recovered,
						Stacktrace: debug.Stack(),
					}
				}
			}()
			err = mEndFn(ctx)
			if err != nil {
				taskEmitter.TaskError(ctx, err)
				return
			}
			taskEmitter.TaskSuccess(ctx)
			return
		},
	})

	if err := sched.Wait(ctx); err != nil {
		parallelEmitter.ParallelError(ctx, err)
		return err
	}
	parallelEmitter.ParallelSuccess(ctx)
	return nil
}

func _cffMapcffappmapend_20_3[
	t3 any,
	t4 any,
	t5 any,
](
	mTaskFn t3,
	mMap t4,
	mEndFnThunk func() t5,
) func() (t3, t4, t5) {
	mEndFn := mEndFnThunk()
	_ = mEndFn
	return func() (t3, t4, t5) {
		return mTaskFn, mMap, mEndFn
	}
}

func _cffMapEndcffappmapend_1745492981[
	t5 any,
](
	mEndFn t5,
) func() t5 {
	return func() t5 {
		return mEndFn
	}
}

func main() {
	ctx := context.Background()
	if err := AFunctionWithUniqueName(ctx, map[string]int{"a": 1}); err != nil {
		fmt.Println("Error:", err)
	}
}
