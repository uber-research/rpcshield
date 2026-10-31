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
// from the SliceEnd closure (not the main Slice task closure).
func Sink(n int) error {
	return nil
}

// AFunctionWithUniqueName is the checked-in ground truth for what the CURRENT internal `cff`
// codegen tool actually emits for a cff.SliceEnd construct -- captured (module/package names
// aside) via:
//
//	bazel build --output_groups=go_generated_srcs //.../internal/tests/sliceendctx:cff
//
// The SliceEnd closure is wrapped via _cffSliceEndcffappsliceend_..., nested as the THIRD
// argument to _cffSlicecffappsliceend_...'s wrapper call -- processCFFTaskCall must explicitly
// recover it via findCFFEndFuncArg since getCFFTaskCallsites' operand walk never descends into
// the outer wrapper call's own arguments.
func AFunctionWithUniqueName(ctx context.Context, items []int) error {
	return _cffParallelcffappsliceend_18_9(
		ctx,
		_cffSlicecffappsliceend_20_3[func(item int) error, []int](func(item int) error {
			return nil
		}, items,
			_cffSliceEndcffappsliceend_1745492981(func(ctx context.Context) error {
				return Sink(len(items))
			}),
		),
	)
}

func _cffParallelcffappsliceend_18_9[
	t1 any,
](
	ctx context.Context,
	mSliceSeed func() (func(t1) error, []t1, func(ctx context.Context) error),
) (err error) {
	mTaskFn, mItems, mEndFn := mSliceSeed()
	_, _, _ = mTaskFn, mItems, mEndFn

	parallelEmitter := cff.NopParallelEmitter()
	startTime := time.Now()
	defer func() { parallelEmitter.ParallelDone(ctx, time.Since(startTime)) }()

	schedEmitter := cff.NopEmitter().SchedulerInit(&cff.SchedulerInfo{
		Name:      "",
		Directive: cff.ParallelDirective,
		File:      "go.uber.org/cff/internal/tests/sliceendctx/sliceendctx.go",
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

	sliceTask0Slice := mItems
	sliceTask0Jobs := make([]*cff.ScheduledJob, len(sliceTask0Slice))
	sliceTask0Emitter := cff.NopTaskEmitter()
	for idx, val := range sliceTask0Slice {
		idx := idx
		val := val
		sliceTask0 := new(struct {
			emitter cff.TaskEmitter
			fn      func(context.Context) error
			ran     cff.AtomicBool
		})
		sliceTask0.fn = func(ctx context.Context) (err error) {
			taskEmitter := sliceTask0Emitter
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
			err = mTaskFn(val)
			if err != nil {
				taskEmitter.TaskError(ctx, err)
				return
			}
			taskEmitter.TaskSuccess(ctx)
			return
		}
		tasks = append(tasks, sliceTask0)
		sliceTask0Jobs[idx] = sched.Enqueue(ctx, cff.Job{
			Run: sliceTask0.fn,
		})
	}

	sched.Enqueue(ctx, cff.Job{
		Dependencies: sliceTask0Jobs,
		Run: func(ctx context.Context) (err error) {
			taskEmitter := sliceTask0Emitter
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

func _cffSlicecffappsliceend_20_3[
	t2 any,
	t3 any,
	t4 any,
](
	mTaskFn t2,
	mItems t3,
	mEndFnThunk func() t4,
) func() (t2, t3, t4) {
	mEndFn := mEndFnThunk()
	_ = mEndFn
	return func() (t2, t3, t4) {
		return mTaskFn, mItems, mEndFn
	}
}

func _cffSliceEndcffappsliceend_1745492981[
	t4 any,
](
	mEndFn t4,
) func() t4 {
	return func() t4 {
		return mEndFn
	}
}

func main() {
	ctx := context.Background()
	if err := AFunctionWithUniqueName(ctx, []int{0, 1, 2, 3}); err != nil {
		fmt.Println("Error:", err)
	}
}
