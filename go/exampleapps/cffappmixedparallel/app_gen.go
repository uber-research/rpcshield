//go:build !cff

package main

import (
	"context"
	"fmt"
	"runtime/debug"
	"time"

	"go.uber.org/cff"
)

// SinkOne, SinkTwo, SinkThree represent distinct downstream/outbound call sites whose
// reachability we're testing -- one per task in the mixed cff.Parallel below, so we can tell
// whether findCFFTaskFuncs correctly recovers ALL of them without cross-contamination.
func SinkOne() error {
	return nil
}

func SinkTwo(item int) error {
	return nil
}

func SinkThree() error {
	return nil
}

type receiver struct{}

// BoundMethodTask is used as a bound-method value (receiver.BoundMethodTask) passed directly as a
// cff.Task argument, rather than a literal func literal -- exercising the *ssa.MakeClosure "bound
// method" wrapper shape under the hybrid codegen's generic-wrapping pattern.
func (receiver) BoundMethodTask(ctx context.Context) error {
	return SinkThree()
}

// AFunctionWithUniqueName is the checked-in ground truth (module/package/symbol names adapted, see
// exampleapps/cffappctxlessslice/app_gen.go's doc comment for provenance methodology) for what
// the CURRENT internal `cff` codegen tool emits for a single cff.Parallel with THREE mixed
// task/slice arguments -- a plain cff.Task, a cff.Slice, and a cff.Task passed as a bound method
// value. Captured via:
//
//	bazel build --output_groups=go_generated_srcs //.../internal/tests/mixedparallel:cff
//
// Each of the three arguments gets its own top-level synthesized generic "seed" function
// (_cffTask..., _cffSlice..., _cffTask... again -- reusing the same generic instantiation since
// both cff.Task arguments share the same underlying signature func(context.Context) error), whose
// sole job is to hand the raw closure/bound-method value back out through a thunk that
// _cffParallel...'s body immediately calls to unwrap.
func AFunctionWithUniqueName(ctx context.Context, items []int) error {
	r := receiver{}
	return _cffParallelcffappmixedparallel_41_9(
		ctx,
		_cffTaskcffappmixedparallel_1745492981[func(ctx context.Context) error](func(ctx context.Context) error {
			return SinkOne()
		}),
		_cffSlicecffappmixedparallel_46_3[func(i int, item int) error, []int](func(i int, item int) error {
			return SinkTwo(item)
		}, items),
		_cffTaskcffappmixedparallel_1745492981[func(ctx context.Context) error](r.BoundMethodTask),
	)
}

// AFunctionWithUniqueNameTwoSlices is the checked-in ground truth for a single cff.Parallel with
// TWO cff.Slice arguments over slices of the SAME element type ([]int) -- two structurally
// identical _cffSliceXXX generic instantiations, each closing over a distinct closure/items pair.
func AFunctionWithUniqueNameTwoSlices(ctx context.Context, itemsA []int, itemsB []int) error {
	return _cffParallelcffappmixedparallel_59_9(
		ctx,
		_cffSlicecffappmixedparallel_61_3[func(i int, item int) error, []int](func(i int, item int) error {
			return SinkOne()
		}, itemsA),
		_cffSlicecffappmixedparallel_64_3[func(i int, item int) error, []int](func(i int, item int) error {
			return SinkTwo(item)
		}, itemsB),
	)
}

func _cffParallelcffappmixedparallel_41_9[
	t1 any,
](
	ctx context.Context,
	mTask0Seed func() func(context.Context) error,
	mSlice1Seed func() (func(int, t1) error, []t1),
	mTask2Seed func() func(context.Context) error,
) (err error) {
	mTask0 := mTask0Seed()
	_ = mTask0
	mSlice1Fn, mSlice1Items := mSlice1Seed()
	_, _ = mSlice1Fn, mSlice1Items
	mTask2 := mTask2Seed()
	_ = mTask2

	parallelEmitter := cff.NopParallelEmitter()
	startTime := time.Now()
	defer func() { parallelEmitter.ParallelDone(ctx, time.Since(startTime)) }()

	schedEmitter := cff.NopEmitter().SchedulerInit(&cff.SchedulerInfo{
		Name:      "",
		Directive: cff.ParallelDirective,
		File:      "go.uber.org/cff/internal/tests/mixedparallel/mixedparallel.go",
		Line:      41,
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

	task0 := new(struct {
		emitter cff.TaskEmitter
		fn      func(context.Context) error
		ran     cff.AtomicBool
	})
	task0.emitter = cff.NopTaskEmitter()
	task0.fn = func(ctx context.Context) (err error) {
		taskEmitter := task0.emitter
		startTime := time.Now()
		defer func() { taskEmitter.TaskDone(ctx, time.Since(startTime)) }()
		defer func() {
			recovered := recover()
			if recovered != nil {
				taskEmitter.TaskPanic(ctx, recovered)
				err = &cff.PanicError{Value: recovered, Stacktrace: debug.Stack()}
			}
		}()
		err = mTask0(ctx)
		if err != nil {
			taskEmitter.TaskError(ctx, err)
			return
		}
		taskEmitter.TaskSuccess(ctx)
		return
	}
	tasks = append(tasks, task0)
	sched.Enqueue(ctx, cff.Job{Run: task0.fn})

	task2 := new(struct {
		emitter cff.TaskEmitter
		fn      func(context.Context) error
		ran     cff.AtomicBool
	})
	task2.emitter = cff.NopTaskEmitter()
	task2.fn = func(ctx context.Context) (err error) {
		taskEmitter := task2.emitter
		startTime := time.Now()
		defer func() { taskEmitter.TaskDone(ctx, time.Since(startTime)) }()
		defer func() {
			recovered := recover()
			if recovered != nil {
				taskEmitter.TaskPanic(ctx, recovered)
				err = &cff.PanicError{Value: recovered, Stacktrace: debug.Stack()}
			}
		}()
		err = mTask2(ctx)
		if err != nil {
			taskEmitter.TaskError(ctx, err)
			return
		}
		taskEmitter.TaskSuccess(ctx)
		return
	}
	tasks = append(tasks, task2)
	sched.Enqueue(ctx, cff.Job{Run: task2.fn})

	sliceTask1Slice := mSlice1Items
	sliceTask1Emitter := cff.NopTaskEmitter()
	for idx, val := range sliceTask1Slice {
		idx := idx
		val := val
		sliceTask1 := new(struct {
			emitter cff.TaskEmitter
			fn      func(context.Context) error
			ran     cff.AtomicBool
		})
		sliceTask1.fn = func(ctx context.Context) (err error) {
			taskEmitter := sliceTask1Emitter
			startTime := time.Now()
			defer func() { taskEmitter.TaskDone(ctx, time.Since(startTime)) }()
			defer func() {
				recovered := recover()
				if recovered != nil {
					taskEmitter.TaskPanic(ctx, recovered)
					err = &cff.PanicError{Value: recovered, Stacktrace: debug.Stack()}
				}
			}()
			err = mSlice1Fn(idx, val)
			if err != nil {
				taskEmitter.TaskError(ctx, err)
				return
			}
			taskEmitter.TaskSuccess(ctx)
			return
		}
		sched.Enqueue(ctx, cff.Job{Run: sliceTask1.fn})
	}

	if err := sched.Wait(ctx); err != nil {
		parallelEmitter.ParallelError(ctx, err)
		return err
	}
	parallelEmitter.ParallelSuccess(ctx)
	return nil
}

func _cffTaskcffappmixedparallel_1745492981[
	t2 any,
](
	mTaskFn t2,
) func() t2 {
	return func() t2 {
		return mTaskFn
	}
}

func _cffSlicecffappmixedparallel_46_3[
	t3 any,
	t4 any,
](
	mTaskFn t3,
	mItems t4,
) func() (t3, t4) {
	return func() (t3, t4) {
		return mTaskFn, mItems
	}
}

func _cffParallelcffappmixedparallel_59_9[
	t1 any,
](
	ctx context.Context,
	mSlice3Seed func() (func(int, t1) error, []t1),
	mSlice4Seed func() (func(int, t1) error, []t1),
) (err error) {
	mSlice3Fn, mSlice3Items := mSlice3Seed()
	_, _ = mSlice3Fn, mSlice3Items
	mSlice4Fn, mSlice4Items := mSlice4Seed()
	_, _ = mSlice4Fn, mSlice4Items

	parallelEmitter := cff.NopParallelEmitter()
	startTime := time.Now()
	defer func() { parallelEmitter.ParallelDone(ctx, time.Since(startTime)) }()

	schedEmitter := cff.NopEmitter().SchedulerInit(&cff.SchedulerInfo{
		Name:      "",
		Directive: cff.ParallelDirective,
		File:      "go.uber.org/cff/internal/tests/mixedparallel/mixedparallel.go",
		Line:      59,
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

	sliceTask3Slice := mSlice3Items
	sliceTask3Emitter := cff.NopTaskEmitter()
	for idx, val := range sliceTask3Slice {
		idx := idx
		val := val
		sliceTask3 := new(struct {
			emitter cff.TaskEmitter
			fn      func(context.Context) error
			ran     cff.AtomicBool
		})
		sliceTask3.fn = func(ctx context.Context) (err error) {
			taskEmitter := sliceTask3Emitter
			startTime := time.Now()
			defer func() { taskEmitter.TaskDone(ctx, time.Since(startTime)) }()
			defer func() {
				recovered := recover()
				if recovered != nil {
					taskEmitter.TaskPanic(ctx, recovered)
					err = &cff.PanicError{Value: recovered, Stacktrace: debug.Stack()}
				}
			}()
			err = mSlice3Fn(idx, val)
			if err != nil {
				taskEmitter.TaskError(ctx, err)
				return
			}
			taskEmitter.TaskSuccess(ctx)
			return
		}
		sched.Enqueue(ctx, cff.Job{Run: sliceTask3.fn})
	}

	sliceTask4Slice := mSlice4Items
	sliceTask4Emitter := cff.NopTaskEmitter()
	for idx, val := range sliceTask4Slice {
		idx := idx
		val := val
		sliceTask4 := new(struct {
			emitter cff.TaskEmitter
			fn      func(context.Context) error
			ran     cff.AtomicBool
		})
		sliceTask4.fn = func(ctx context.Context) (err error) {
			taskEmitter := sliceTask4Emitter
			startTime := time.Now()
			defer func() { taskEmitter.TaskDone(ctx, time.Since(startTime)) }()
			defer func() {
				recovered := recover()
				if recovered != nil {
					taskEmitter.TaskPanic(ctx, recovered)
					err = &cff.PanicError{Value: recovered, Stacktrace: debug.Stack()}
				}
			}()
			err = mSlice4Fn(idx, val)
			if err != nil {
				taskEmitter.TaskError(ctx, err)
				return
			}
			taskEmitter.TaskSuccess(ctx)
			return
		}
		sched.Enqueue(ctx, cff.Job{Run: sliceTask4.fn})
	}

	if err := sched.Wait(ctx); err != nil {
		parallelEmitter.ParallelError(ctx, err)
		return err
	}
	parallelEmitter.ParallelSuccess(ctx)
	return nil
}

func _cffSlicecffappmixedparallel_61_3[
	t3 any,
	t4 any,
](
	mTaskFn t3,
	mItems t4,
) func() (t3, t4) {
	return func() (t3, t4) {
		return mTaskFn, mItems
	}
}

func _cffSlicecffappmixedparallel_64_3[
	t3 any,
	t4 any,
](
	mTaskFn t3,
	mItems t4,
) func() (t3, t4) {
	return func() (t3, t4) {
		return mTaskFn, mItems
	}
}

func main() {
	ctx := context.Background()
	if err := AFunctionWithUniqueName(ctx, []int{0, 1, 2, 3}); err != nil {
		fmt.Println("Error:", err)
	}
	if err := AFunctionWithUniqueNameTwoSlices(ctx, []int{0, 1}, []int{2, 3}); err != nil {
		fmt.Println("Error:", err)
	}
}
