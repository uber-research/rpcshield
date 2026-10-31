// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package vta computes the call graph of a Go program using the Variable
// Type Analysis (VTA) algorithm originally described in "Practical Virtual
// Method Call Resolution for Java," Vijay Sundaresan, Laurie Hendren,
// Chrislain Razafimahefa, Raja Vallée-Rai, Patrick Lam, Etienne Gagnon, and
// Charles Godin.
//
// Note: this package is in experimental phase and its interface is
// subject to change.
// TODO(zpavlinovic): reiterate on documentation.
//
// The VTA algorithm overapproximates the set of types (and function literals)
// a variable can take during runtime by building a global type propagation
// graph and propagating types (and function literals) through the graph.
//
// A type propagation is a directed, labeled graph. A node can represent
// one of the following:
//   - A field of a struct type.
//   - A local (SSA) variable of a method/function.
//   - All pointers to a non-interface type.
//   - The return value of a method.
//   - All elements in an array.
//   - All elements in a slice.
//   - All elements in a map.
//   - All elements in a channel.
//   - A global variable.
//
// In addition, the implementation used in this package introduces
// a few Go specific kinds of nodes:
//   - (De)references of nested pointers to interfaces are modeled
//     as a unique nestedPtrInterface node in the type propagation graph.
//   - Each function literal is represented as a function node whose
//     internal value is the (SSA) representation of the function. This
//     is done to precisely infer flow of higher-order functions.
//
// Edges in the graph represent flow of types (and function literals) through
// the program. That is, the model 1) typing constraints that are induced by
// assignment statements or function and method calls and 2) higher-order flow
// of functions in the program.
//
// The labeling function maps each node to a set of types and functions that
// can intuitively reach the program construct the node represents. Initially,
// every node is assigned a type corresponding to the program construct it
// represents. Function nodes are also assigned the function they represent.
// The labeling function then propagates types and function through the graph.
//
// The result of VTA is a type propagation graph in which each node is labeled
// with a conservative overapproximation of the set of types (and functions)
// it may have. This information is then used to construct the call graph.
// For each unresolved call site, vta uses the set of types and functions
// reaching the node representing the call site to create a set of callees.
//
// # Fork
//
// This package is a fork of golang.org/x/tools/go/callgraph/vta at v0.45.0,
// the x/tools version pinned in third_party/golang.org/x/tools/repos.bzl.
// Upstream VTA models no reflection at all, which makes it unusable on Uber
// services: they are wired by dependency injection (fx/dig), so the concrete
// implementation of an injected interface reaches its field only by way of
// reflect.Value, and stock VTA resolves such call sites to nothing. The
// deltas from upstream are:
//
//   - initial.go: the CHA fallback for a nil seed is removed; a seed is
//     required.
//   - reflect.go (new): everything reflection-related. reflect.Value is made
//     a flow-carrying type, the reflect API is summarized rather than
//     analyzed, an "unknown" label marks blind spots, and call sites with
//     incomplete information fall back to the seed's callees.
//   - vta.go, utils.go, propagation.go, graph.go: small, individually marked
//     hooks into the above. Every one is tagged with a "Fork note" comment.
//
// Keeping the additions in reflect.go keeps the diff against upstream small
// enough to re-apply on the next x/tools bump.
package vta

// TODO(zpavlinovic): update VTA for how it handles generic function bodies and instantiation wrappers.

import (
	"go/types"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// CallGraph uses the VTA algorithm to compute a call graph for all functions
// f:true in funcs. VTA refines the results of the initial call graph and uses
// it to establish interprocedural type flow.
//
// initial is required and must be sound: VTA intersects its own results with
// initial's, so any edge missing from initial can never appear in the output.
// rpcshield seeds it with a reflection-aware RTA graph. Unlike upstream,
// passing nil is a programming error (upstream would build a CHA graph).
//
// The resulting graph does not have a root node.
//
// CallGraph does not make any assumptions on initial types global variables
// and function/method inputs can have.
//
// By default the result is sound with respect to reflection at every site
// whose receiver's propagated label set carries a ⊤ ("unknown") label —
// seeded at unmodeled reflect APIs, body-less functions, unsafe.Pointer
// conversions to a flow-carrying type, and struct fields that are read but
// never written in the reachable set (see reflect.go). At those sites the
// seed's callees are used, so their edge set is a superset of the seed's. At
// every other site VTA returns its own answer, which is a subset of the
// seed's by construction — including the case where that answer is empty:
// on the modeled SSA universe no concrete type ever reached the receiver,
// and the correct answer is no callees. Pass WithStrict to disable the
// fallback entirely and measure VTA's unaided precision. Pass
// WithFallbackObserver to enumerate every site where the fallback fired.
func CallGraph(funcs map[*ssa.Function]bool, initial *callgraph.Graph, opts ...Option) *callgraph.Graph {
	if initial == nil {
		panic("vta.CallGraph: initial call graph is required")
	}
	cfg := newConfig(opts)
	callees := makeCalleesFunc(initial)
	vtaG, canon, addrTaken := typePropGraph(funcs, callees)
	types := propagate(vtaG, canon)

	c := &constructor{types: types, callees: callees, cache: make(methodCache), cfg: cfg, addrTaken: addrTaken}
	return c.construct(funcs)
}

// Option configures the reflection-aware extensions of this fork.
type Option func(*config)

// config holds the settings an Option can change.
type config struct {
	// strict disables the seed fallback described on CallGraph. Only useful
	// for measuring how much of VTA's edge reduction is genuine precision
	// versus the soundness fallback; unsound for production use.
	strict bool

	// observer, when non-nil, is invoked from resolves and resolvesReflect
	// on each fallback firing. Exposed via WithFallbackObserver so callers
	// can enumerate every site where VTA deferred to the seed.
	observer FallbackObserver
}

func newConfig(opts []Option) config {
	var c config
	for _, o := range opts {
		o(&c)
	}
	return c
}

// WithStrict disables the seed fallback, yielding pure VTA results. The
// resulting call graph may have false negatives in the presence of reflection.
func WithStrict() Option {
	return func(c *config) { c.strict = true }
}

// FallbackReason names the discriminator branch that caused resolves or
// resolvesReflect to fall back to the seed's candidates. Exposed via
// WithFallbackObserver so callers can enumerate every site where VTA deferred
// to the seed rather than trust its own answer.
type FallbackReason int

const (
	// ReasonInterfaceTaintEmpty: an interface or higher-order call site
	// where the receiver's label set was empty and carried a ⊤ label,
	// meaning VTA is structurally blind about what reached the site.
	ReasonInterfaceTaintEmpty FallbackReason = iota + 1

	// ReasonInterfaceTaintPartial: the receiver had some concrete labels
	// but also carried ⊤, so the set is known-incomplete.
	ReasonInterfaceTaintPartial

	// ReasonReflectTaintEmpty: a reflective dispatch (Value.Call /
	// Value.CallSlice) where the receiver had no function labels and at
	// least one non-function or ⊤ label.
	ReasonReflectTaintEmpty

	// ReasonReflectTaintPartial: some function labels reached the reflective
	// receiver alongside a ⊤ or non-function label.
	ReasonReflectTaintPartial
)

func (r FallbackReason) String() string {
	switch r {
	case ReasonInterfaceTaintEmpty:
		return "InterfaceTaintEmpty"
	case ReasonInterfaceTaintPartial:
		return "InterfaceTaintPartial"
	case ReasonReflectTaintEmpty:
		return "ReflectTaintEmpty"
	case ReasonReflectTaintPartial:
		return "ReflectTaintPartial"
	default:
		return "FallbackReason(unknown)"
	}
}

// FallbackObserver is called from resolves and resolvesReflect on each
// fallback firing, with the call site and the reason it triggered. The
// observer runs on the hot path; keep the callback cheap (counter
// increments, log writes, etc.).
type FallbackObserver func(call ssa.CallInstruction, reason FallbackReason)

// WithFallbackObserver registers a callback invoked whenever a call site
// falls back to the seed's candidates. When unset (nil), the observer check
// is one branch on the hot path and nothing else.
func WithFallbackObserver(fn FallbackObserver) Option {
	return func(c *config) { c.observer = fn }
}

// constructor type linearly traverses the input program
// and constructs a callgraph based on the results of the
// VTA type propagation phase.
type constructor struct {
	types   propTypeMap
	cache   methodCache
	callees calleesFunc
	cfg     config

	// addrTaken is the set of functions used as values, and so the candidate
	// set for a reflective call whose receiver VTA could not pin down (fork
	// note; see reflect.go).
	addrTaken map[*ssa.Function]bool
}

func (c *constructor) construct(funcs map[*ssa.Function]bool) *callgraph.Graph {
	cg := &callgraph.Graph{Nodes: make(map[*ssa.Function]*callgraph.Node)}
	for f, in := range funcs {
		if in {
			c.constrct(cg, f)
		}
	}
	return cg
}

func (c *constructor) constrct(g *callgraph.Graph, f *ssa.Function) {
	caller := g.CreateNode(f)
	for _, call := range calls(f) {
		for _, c := range c.resolves(call) {
			callgraph.AddEdge(caller, call, g.CreateNode(c))
		}
	}
}

// resolves computes the set of functions to which VTA resolves `c`. The resolved
// functions are intersected with functions to which `c.initial` resolves `c`.
//
// Fork note: two additions, both in service of "no false negatives" (see the
// package doc and reflect.go). Reflective dispatch is resolved from the
// labels on the receiver, and a site whose receiver carries a ⊤ label falls
// back to the seed's candidates rather than reporting a possibly-incomplete
// answer. An empty answer with no ⊤ anywhere upstream is *not* a fallback
// trigger: it is proof on the modeled SSA universe that no concrete type ever
// reached the receiver, and returning empty is the correct answer. This
// depends on ⊤ being seeded at every structural blind spot (unmodeled reflect
// APIs, body-less functions, unsafe.Pointer conversions to a flow-carrying
// type, and struct fields read-but-never-written in the reachable set — see
// reflect.go).
func (c *constructor) resolves(call ssa.CallInstruction) []*ssa.Function {
	cc := call.Common()

	// (reflect.Value).Call is an ordinary static call on a concrete struct,
	// so this must precede the static-callee fast path below.
	if isReflectDispatch(call) {
		return c.resolvesReflect(call)
	}

	if cc.StaticCallee() != nil {
		return []*ssa.Function{cc.StaticCallee()}
	}

	// Skip builtins as they are not *ssa.Function.
	if _, ok := cc.Value.(*ssa.Builtin); ok {
		return nil
	}

	// Cover the case of dynamic higher-order and interface calls.
	var res []*ssa.Function
	resolved, unsure := resolve(call, c.types, c.cache)
	for f := range siteCallees(call, c.callees) {
		if _, ok := resolved[f]; ok {
			res = append(res, f)
		}
	}

	// In strict mode never fall back. Otherwise fall back only on taint (⊤ in
	// the receiver's label set): an untainted answer, empty or not, is what
	// VTA actually saw and is the final answer. See the package doc note on
	// blind-spot ⊤ seeding for why untainted empty means infeasible.
	if c.cfg.strict || !unsure {
		return res
	}
	if c.cfg.observer != nil {
		reason := ReasonInterfaceTaintEmpty
		if len(res) > 0 {
			reason = ReasonInterfaceTaintPartial
		}
		c.cfg.observer(call, reason)
	}
	return c.seedCallees(call)
}

// resolvesReflect computes the callees of a reflective call from the function
// labels that reached its receiver. If the receiver carries anything the
// analysis could not identify as a specific function, every function used as
// a value is a candidate — which is the answer RTA gives for all of them.
func (c *constructor) resolvesReflect(call ssa.CallInstruction) []*ssa.Function {
	args := call.Common().Args
	if len(args) == 0 {
		return nil
	}

	var res []*ssa.Function
	unsure := false
	for p := range c.types.propTypes(local{val: args[0]}) {
		if p.f == nil {
			// An unknown label, or a non-function value reflected upon (for
			// instance a method value obtained by name). Neither identifies a
			// callee.
			unsure = true
			continue
		}
		res = append(res, p.f)
	}

	// Same taint-only rule as resolves: an untainted empty answer means no
	// function label ever reached this receiver on the modeled universe, and
	// that is the final answer. Only tainted receivers defer to addrTaken.
	if c.cfg.strict || !unsure {
		return res
	}
	if c.cfg.observer != nil {
		reason := ReasonReflectTaintEmpty
		if len(res) > 0 {
			reason = ReasonReflectTaintPartial
		}
		c.cfg.observer(call, reason)
	}
	candidates := make([]*ssa.Function, 0, len(c.addrTaken))
	for f := range c.addrTaken {
		candidates = append(candidates, f)
	}
	return candidates
}

// seedCallees returns the callees the seed call graph gives for `call`.
func (c *constructor) seedCallees(call ssa.CallInstruction) []*ssa.Function {
	var res []*ssa.Function
	for f := range siteCallees(call, c.callees) {
		res = append(res, f)
	}
	return res
}

// resolve returns a set of functions `c` resolves to based on the
// type propagation results in `types`.
//
// Fork note: also reports whether the receiver carried an unknown label,
// meaning the returned set may be incomplete.
func resolve(c ssa.CallInstruction, types propTypeMap, cache methodCache) (map[*ssa.Function]empty, bool) {
	fns := make(map[*ssa.Function]empty)
	unknown := false
	n := local{val: c.Common().Value}
	for p := range types.propTypes(n) {
		if isUnknown(p) {
			unknown = true
			continue
		}
		for _, f := range propFunc(p, c, cache) {
			fns[f] = empty{}
		}
	}
	return fns, unknown
}

// propFunc returns the functions modeled with the propagation type `p`
// assigned to call site `c`. If no such function exists, nil is returned.
func propFunc(p propType, c ssa.CallInstruction, cache methodCache) []*ssa.Function {
	if p.f != nil {
		return []*ssa.Function{p.f}
	}

	if c.Common().Method == nil {
		return nil
	}

	return cache.methods(p.typ, c.Common().Method.Name(), c.Parent().Prog)
}

// methodCache serves as a type -> method name -> methods
// cache when computing methods of a type using the
// ssa.Program.MethodSets and ssa.Program.MethodValue
// APIs. The cache is used to speed up querying of
// methods of a type as the mentioned APIs are expensive.
type methodCache map[types.Type]map[string][]*ssa.Function

// methods returns methods of a type `t` named `name`. First consults
// `mc` and otherwise queries `prog` for the method. If no such method
// exists, nil is returned.
func (mc methodCache) methods(t types.Type, name string, prog *ssa.Program) []*ssa.Function {
	if ms, ok := mc[t]; ok {
		return ms[name]
	}

	ms := make(map[string][]*ssa.Function)
	mset := prog.MethodSets.MethodSet(t)
	for i, n := 0, mset.Len(); i < n; i++ {
		// f can be nil when t is an interface or some
		// other type without any runtime methods.
		if f := prog.MethodValue(mset.At(i)); f != nil {
			ms[f.Name()] = append(ms[f.Name()], f)
		}
	}
	mc[t] = ms
	return ms[name]
}
