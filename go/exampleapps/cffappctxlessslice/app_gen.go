//go:build !cff

package main

import (
	"context"
	"fmt"
	"runtime/debug"
	"time"

	"go.uber.org/cff"
)

// Sink represents a downstream/outbound call site whose reachability we're testing. It must NOT
// be reachable in the analyzed graph if the cffContextCallingFilter-drop hypothesis is correct.
func Sink(item int) error {
	return nil
}

// AFunctionWithUniqueName is the checked-in ground truth for what the CURRENT (as of this
// investigation) internal `cff` codegen tool actually emits for a ctx-less, index-first
// cff.Slice task closure -- captured verbatim (module/package names aside) via:
//
//	bazel build --output_groups=go_generated_srcs //.../internal/tests/ctxlessslice:cff
//
// This is a HYBRID shape, distinct from both shapes cffenricher.go's comments describe:
//   - unlike the older internal-fork shape, the scheduling boilerplate is not inlined into the
//     original function; instead the original call site is rewritten to call a separately
//     synthesized, uniquely-named top-level generic function (_cffParallel..._<line>_<col>).
//   - unlike the current OSS inline-codegen shape (whose Enqueue-registered task closure is
//     always ctx-first regardless of the user's real closure -- see the *ssa.MakeClosure handling
//     this fixture is NOT exercising), here the synthesized _cffSlice..._<line>_<col> helper takes
//     the user's RAW original closure directly as a generic argument, so it is this raw,
//     non-ctx-first closure that processCFFTaskCall's fn.Args[0] extraction hands to
//     cffContextCallingFilter -- which then rejects it for not taking a context.Context first.
func AFunctionWithUniqueName(ctx context.Context, items []int) error {
	return _cffParallelcffappctxlessslice_18_9(
		ctx,
		_cffSlicecffappctxlessslice_20_3[func(idx int, item int) error, []int](func(idx int, item int) error {
			return Sink(item)
		}, items),
	)
}

func _cffParallelcffappctxlessslice_18_9[
	t1 any,
](
	ctx context.Context,
	mSliceSeed func() (func(int, t1) error, []t1),
) (err error) {
	mTaskFn, mItems := mSliceSeed()
	_, _ = mTaskFn, mItems

	parallelEmitter := cff.NopParallelEmitter()
	startTime := time.Now()
	defer func() { parallelEmitter.ParallelDone(ctx, time.Since(startTime)) }()

	schedEmitter := cff.NopEmitter().SchedulerInit(&cff.SchedulerInfo{
		Name:      "",
		Directive: cff.ParallelDirective,
		File:      "go.uber.org/cff/internal/tests/ctxlessslice/ctxlessslice.go",
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
			err = mTaskFn(idx, val)
			if err != nil {
				taskEmitter.TaskError(ctx, err)
				return
			}
			taskEmitter.TaskSuccess(ctx)
			return
		}
		tasks = append(tasks, sliceTask0)
		sched.Enqueue(ctx, cff.Job{
			Run: sliceTask0.fn,
		})
	}

	if err := sched.Wait(ctx); err != nil {
		parallelEmitter.ParallelError(ctx, err)
		return err
	}
	parallelEmitter.ParallelSuccess(ctx)
	return nil
}

func _cffSlicecffappctxlessslice_20_3[
	t2 any,
	t3 any,
](
	mTaskFn t2,
	mItems t3,
) func() (t2, t3) {
	return func() (t2, t3) {
		return mTaskFn, mItems
	}
}

func main() {
	ctx := context.Background()
	if err := AFunctionWithUniqueName(ctx, []int{0, 1, 2, 3}); err != nil {
		fmt.Println("Error:", err)
	}
}
