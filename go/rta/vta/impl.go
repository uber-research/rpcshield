// Package vta provides a Variable Type Analysis call graph flavor that
// satisfies the same rta.RTA contract as the RTA flavors, so it can be
// selected and benchmarked through the existing flavor machinery in
// rpcshield/graph.
//
// VTA is flow-based rather than type-based: an interface call resolves only
// to implementations that actually flow to that receiver, instead of to every
// implementation instantiated anywhere in the program. That removes a large
// class of infeasible edges that RTA cannot.
//
// The analysis is seeded with prta_kumo_nonblocking rather than CHA. The seed
// serves two purposes: its reachable set bounds the functions VTA visits, and
// its call graph bounds the callees VTA may report (see vta.CallGraph). A CHA
// seed would be a looser bound and, unlike RTA, models no reflection.
package vta

import (
	rtalib "github.com/uber-research/rpcshield/go/rta"
	"github.com/uber-research/rpcshield/go/rta/prta_kumo_nonblocking"
	vtacore "github.com/uber-research/rpcshield/go/vta"
	"golang.org/x/tools/go/callgraph"
	rtapkg "golang.org/x/tools/go/callgraph/rta"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/types/typeutil"
)

// Result implements rtalib.Result for VTA.
type Result struct {
	rtalib.BaseMetrics
	callGraph *callgraph.Graph
	seed      rtalib.Result
}

// GetCallGraph returns the VTA-refined call graph.
func (r *Result) GetCallGraph() *callgraph.Graph {
	return r.callGraph
}

// GetReachable returns the seed's reachable set.
//
// VTA refines call edges, not reachability: it never adds a function the seed
// did not already reach, and it does not recompute the fixpoint that would be
// needed to soundly narrow the set. Reporting the seed's set is therefore a
// sound overapproximation. rpcshield/graph consumes only GetCallGraph, so
// this exists to satisfy the interface and to keep flavor comparisons honest.
func (r *Result) GetReachable() map[*ssa.Function]struct{ AddrTaken bool } {
	return r.seed.GetReachable()
}

// GetRuntimeTypes returns the seed's runtime types. VTA tracks types per node
// rather than in one global pool, so there is no equivalent global set to
// report; the seed's is a sound overapproximation. See GetReachable.
func (r *Result) GetRuntimeTypes() typeutil.Map {
	return r.seed.GetRuntimeTypes()
}

// Materialize converts the result to the standard rta.Result so that the
// existing comparison helpers in rpcshield/graph work unchanged.
func (r *Result) Materialize() *rtapkg.Result {
	return &rtapkg.Result{
		CallGraph:    r.GetCallGraph(),
		Reachable:    r.GetReachable(),
		RuntimeTypes: r.GetRuntimeTypes(),
	}
}

// VTA is a Variable Type Analysis call graph implementation.
type VTA struct {
	opts []vtacore.Option
}

var _ rtalib.RTA = (*VTA)(nil)

// New creates a VTA instance. opts are forwarded to vta.CallGraph; with none,
// the analysis is sound with respect to reflection (see vta.CallGraph).
func New(opts ...vtacore.Option) *VTA {
	return &VTA{opts: opts}
}

// Analyze runs the seed RTA and then refines its call graph with VTA.
//
// buildCallGraph is accepted for interface compatibility but is effectively
// always on: VTA is defined in terms of the seed's call graph, so there is no
// cheaper reachability-only mode to offer.
func (a *VTA) Analyze(roots []*ssa.Function, buildCallGraph bool, opts ...rtalib.AnalyzeOption) rtalib.Result {
	if len(roots) == 0 {
		return nil
	}

	seed := prta_kumo_nonblocking.New().Analyze(roots, true, opts...)
	if seed == nil {
		return nil
	}
	seedGraph := seed.GetCallGraph()
	if seedGraph == nil {
		return nil
	}

	reachable := seed.GetReachable()
	funcs := make(map[*ssa.Function]bool, len(reachable))
	for fn := range reachable {
		funcs[fn] = true
	}

	cg := vtacore.CallGraph(funcs, seedGraph, a.opts...)

	// VTA produces a rootless graph. Downstream consumers walk from the
	// entry point, so carry the seed's root over.
	if seedGraph.Root != nil {
		cg.Root = cg.CreateNode(seedGraph.Root.Func)
	}

	return &Result{callGraph: cg, seed: seed}
}
