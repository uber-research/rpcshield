package main

import (
	"context"
	"time"

	"github.com/uber-research/rpcshield/go/exampleapps/errgroup/viainterface"
	ce "github.com/uber-research/rpcshield/go/features/errgroup/ce"
	ls "github.com/uber-research/rpcshield/go/features/errgroup/locationstore"
	op "github.com/uber-research/rpcshield/go/features/errgroup/orderplatform"
	throttledEG "github.com/uber-research/rpcshield/go/features/errgroup/throttled"
	timedgroup "github.com/uber-research/rpcshield/go/features/errgroup/timedgroup"
	tpp "github.com/uber-research/rpcshield/go/features/errgroup/tpp"
	u4beg "github.com/uber-research/rpcshield/go/features/errgroup/u4b"
	"github.com/uber-research/rpcshield/go/features/errgroup/workgroup"
	"github.com/uber-research/rpcshield/go/features/safego/safegroup"
	"golang.org/x/sync/errgroup"
)

// AUniqueNameOneEg is a function.
//
//go:noinline
func AUniqueNameOneEg(ctx context.Context, name string) error {
	eg := errgroup.Group{}
	eg.Go(func() error {
		return nil
	})
	eg.Go(func() error {
		return nil
	})
	eg.Go(func() error {
		return nil
	})
	if err := eg.Wait(); err != nil {
		return err
	}
	return nil
}

//go:noinline
func staticFunc() error {
	return nil
}

// AUniqueNameOneEgStatic is a function.
//
//go:noinline
func AUniqueNameOneEgStatic(ctx context.Context, name string) error {
	eg := errgroup.Group{}
	eg.Go(staticFunc)
	eg.Go(staticFunc)
	if err := eg.Wait(); err != nil {
		return err
	}
	return nil
}

// AUniqueNameOneEgNonStatic is a function.
//
//go:noinline
func AUniqueNameOneEgNonStatic(f func() error) error {
	eg := errgroup.Group{}
	eg.Go(f)
	eg.Go(staticFunc)
	if err := eg.Wait(); err != nil {
		return err
	}
	return nil
}

// AUniqueNameMissingWait is a function.
func AUniqueNameMissingWait(f func() error) error {
	eg := errgroup.Group{}
	eg.Go(func() error { return nil })
	eg.Go(staticFunc)
	return nil
}

// AUniqueNameMissingGo is a function.
func AUniqueNameMissingGo() error {
	eg := errgroup.Group{}
	if err := eg.Wait(); err != nil {
		return err
	}
	return nil
}

// AUniqueNameBranching is a function.
func AUniqueNameBranching(v bool) error {
	eg := errgroup.Group{}
	if v {
		eg.Go(func() error {
			return nil
		})
	} else {
		eg.Go(func() error {
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return err
	}
	return nil
}

// AUniqueNamePhi is a function.
func AUniqueNamePhi(v bool) error {
	eg := &errgroup.Group{}
	if v {
		eg = &errgroup.Group{}
		eg.Go(func() error {
			return nil
		})
	} else {
		eg = &errgroup.Group{}
		eg.Go(func() error {
			return nil
		})
		eg.Go(func() error {
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return err
	}
	return nil
}

// AUniqueNameOverwrite is a function.
func AUniqueNameOverwrite(v bool) error {
	eg := errgroup.Group{}
	if v {
		eg = errgroup.Group{}
		eg.Go(func() error {
			return nil
		})
	} else {
		eg = errgroup.Group{}
		eg.Go(func() error {
			return nil
		})
		eg.Go(func() error {
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return err
	}
	return nil
}

// AUniqueNameTwoEg is a function.
func AUniqueNameTwoEg(ctx context.Context, name string) error {
	eg := errgroup.Group{}
	eg2, _ := errgroup.WithContext(ctx)
	eg.SetLimit(1)
	eg.TryGo(func() error {
		return nil
	})
	eg2.Go(func() error {
		return nil
	})
	eg2.SetLimit(1)
	eg2.TryGo(func() error {
		return nil
	})

	if err := eg.Wait(); err != nil {
		return err
	}
	if err := eg2.Wait(); err != nil {
		return err
	}
	return nil
}

// AUniqueNameReturnEscape is a function.
func AUniqueNameReturnEscape() *errgroup.Group {
	eg := errgroup.Group{}
	eg.Go(func() error {
		return nil
	})
	eg.Wait()
	return &eg
}

// AUniqueNameChanEscape is a function.
func AUniqueNameChanEscape() {
	ch := make(chan *errgroup.Group)
	eg := &errgroup.Group{}
	ch <- eg
	eg.Go(func() error {
		return nil
	})
	eg.Wait()
}

// AUniqueNameMapEscape is a function.
func AUniqueNameMapEscape() {
	m := map[string]*errgroup.Group{}
	eg := errgroup.Group{}
	m["key"] = &eg
	eg.Go(func() error {
		return nil
	})
	eg.Wait()
}

// AUniqueNameSafeGroup is a function.
func AUniqueNameSafeGroup() {
	var eg safegroup.Group
	eg.Go(func() error {
		return nil
	})
	eg.Wait()
}

// AUniqueNameWorkGroup is a function.
func AUniqueNameWorkGroup() {
	var eg workgroup.Group
	eg.Go(func(ctx context.Context) error {
		return nil
	})
	eg.Wait()
}

// AUniqueNameCEWorkGroup2 is a function.
func AUniqueNameCEWorkGroup2() {
	var eg ce.Group
	eg.Go(func() error {
		return nil
	})
	eg.Wait()
}

// AUniqueNameOPWorkGroup is a function.
func AUniqueNameOPWorkGroup() {
	var eg op.Group
	eg.Go(func() error {
		return nil
	})
	eg.Wait()
}

// AUniqueNameThrottledEG is a function.
func AUniqueNameThrottledEG() {
	var eg throttledEG.ThrottledErrGroup
	eg.Go(func() error {
		return nil
	})
	eg.Wait()
}

// AUniqueNameTPPSafeErrGroup is a function.
func AUniqueNameTPPSafeErrGroup() {
	var eg tpp.SafeErrGroup
	eg.Go(func() error {
		return nil
	})
	eg.Wait()
}

// AUniqueNameU4BEG is a function.
func AUniqueNameU4BEG() {
	var eg u4beg.PanicSafeErrGroup
	eg.Go(func() error {
		return nil
	})
	eg.Wait()
}

// AUniqueNameTimedGroup is a function.
func AUniqueNameTimedGroup() {
	var eg timedgroup.WorkGroup
	eg.Go(func() error {
		return nil
	}, func(_ bool) {}, time.Second*10)
	eg.Wait()
}

// AUniqueNameLocationStore is a function.
func AUniqueNameLocationStore() {
	var eg ls.Group
	eg.Go(func() error {
		return nil
	})
	eg.Wait()
}

// AUniqueNameViaInterface is a function.
func AUniqueNameViaInterface() {
	eg := viainterface.GetVIAInterface()
	eg.Go(func() error {
		return nil
	})
	eg.Wait()
}

func main() {
	ctx := context.Background()
	AUniqueNameOneEg(ctx, "name")
	AUniqueNameOneEgStatic(ctx, "hi")
	AUniqueNameOneEgNonStatic(func() error { return nil })
	AUniqueNameMissingWait(func() error { return nil })
	AUniqueNameMissingGo()
	AUniqueNameBranching(false)
	AUniqueNamePhi(false)
	AUniqueNameOverwrite(false)
	AUniqueNameTwoEg(ctx, "hi")
	AUniqueNameReturnEscape()
	AUniqueNameChanEscape()
	AUniqueNameMapEscape()
	// SafeGroup: a Group{Go,Wait} wrapper over golang.org/x/sync/errgroup
	AUniqueNameSafeGroup()
	// WorkGroup: a Group{Go,Wait} shim taking a context-aware F
	AUniqueNameWorkGroup()
	// CEWorkGroup: a Group{Go,Wait} wrapper over golang.org/x/sync/errgroup
	AUniqueNameCEWorkGroup2()
	// OPWorkGroup: a Group{FireAndForget,Go,Wait,SetLimit} wrapper over golang.org/x/sync/errgroup
	AUniqueNameOPWorkGroup()
	// ThrottledEG: a ThrottledErrGroup{Go,Wait} wrapper over golang.org/x/sync/errgroup
	AUniqueNameThrottledEG()
	// SafeErrGroup: a SafeErrGroup{Go,Wait} wrapper over golang.org/x/sync/errgroup
	AUniqueNameTPPSafeErrGroup()
	// U4BEG: a PanicSafeErrGroup{Go,Wait} wrapper over golang.org/x/sync/errgroup
	AUniqueNameU4BEG()
	// TimedGroup: a hand-rolled WorkGroup{Go,Wait,AnyTimedOut} (no errgroup dependency)
	AUniqueNameTimedGroup()
	// NOt supported: LocationStore has WaitContext/AllErrors methods outside the enricher's
	// allowed method set, so it is intentionally not detected as errgroup-like.
	AUniqueNameLocationStore()
	// ViaInterface from "github.com/uber-research/rpcshield/go/exampleapps/errgroup/viainterface"
	AUniqueNameViaInterface()
}
