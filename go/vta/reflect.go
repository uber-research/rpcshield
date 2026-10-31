// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vta

import (
	"fmt"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/ssa"
)

// This file holds everything this fork adds to upstream VTA in order to model
// reflection, and with it dependency injection. Upstream VTA models neither,
// which makes it unusable on services wired by fx/dig: the concrete
// implementation of an injected interface reaches its field only by way of
// reflect.Value, so a stock VTA resolves those call sites to nothing at all.
//
// The model has three parts.
//
// 1. reflect.Value carries flow. Every VTA edge is gated on hasInFlow, which
// admits only interfaces, function types, and nested pointers to those.
// reflect.Value is a struct, so upstream cannot propagate anything through
// one. Admitting it (carriesReflectValue) is what reconnects the chain, and
// it costs no new machinery: stores, field reads, phis, slice elements and
// interprocedural argument/result edges then carry reflected payloads through
// dig's plumbing exactly as they carry interface values elsewhere.
//
// 2. The reflect package is summarized, not analyzed. Its implementation is
// unsafe.Pointer arithmetic that VTA cannot follow soundly, so its function
// bodies are skipped (see builder.fun) and calls into it are given
// hand-written flows instead (see builder.reflectCall). APIs that carry a
// payload from one value to another get a direct edge, which keeps a
// reflected value's identity precise. Anything else routes through a single
// reflectPool node standing for "the reflection subsystem", which is linked
// to the parameters and results of every function used as a value. That is a
// coarse but sound overapproximation, and no coarser than what RTA does for
// the whole program.
//
// 3. Blind spots are labelled rather than ignored. Values emerging from an
// unmodeled reflect API get an explicit "unknown" label (topType), which
// propagates like any other and forces the call sites it reaches to fall back
// to the seed's callees (see constructor.resolves). Precision is only safe
// where we know we saw everything.
//
// Nothing here is specific to fx: it models reflection, so dig, glue, yarpc
// dispatch and generated mocks are all covered by the same code.

// reflectPkgPath is the import path of the package this file models.
const reflectPkgPath = "reflect"

// topType is the type of the "unknown" label: a value about which the
// analysis has given up. It is a synthetic named type so that it can never
// collide with a type from the program under analysis. It has no methods, so
// propFunc yields nothing for it and it can only ever be observed through
// isUnknown.
var topType types.Type = func() types.Type {
	pkg := types.NewPackage("github.com/uber-research/rpcshield/go/vta", "vta")
	obj := types.NewTypeName(token.NoPos, pkg, "unknown", nil)
	return types.NewNamed(obj, types.NewStruct(nil, nil), nil)
}()

// isUnknown reports whether p is the unknown label.
func isUnknown(p propType) bool {
	return p.f == nil && p.typ == topType
}

// unknown is the node that seeds the unknown label. Its type is topType, so
// the ordinary initial-type machinery in propagation.go labels it without
// needing a special case there.
type unknown struct{}

func (unknown) Type() types.Type { return topType }

func (unknown) String() string { return "Unknown" }

// reflectPool is the reflection subsystem's holding slot for values of one
// type. It is keyed by type because that is how reflective containers
// actually behave: dig stores each provided value under its type and hands a
// constructor the value whose type matches the parameter it is filling. A
// single untyped pool would be sound but would merge every injected value in
// the program into one set, which costs exactly the precision VTA exists to
// provide.
//
// Its type is the slot's key, not a value it holds, so it is excluded from
// hasInitialTypes: labels reach it only by flowing in.
type reflectPool struct {
	typ types.Type
}

func (r reflectPool) Type() types.Type { return r.typ }

func (r reflectPool) String() string { return fmt.Sprintf("ReflectPool(%v)", r.typ) }

// isReflectValue reports whether t is reflect.Value.
func isReflectValue(t types.Type) bool {
	n, ok := types.Unalias(t).(*types.Named)
	if !ok {
		return false
	}
	obj := n.Obj()
	return obj.Name() == "Value" && obj.Pkg() != nil && obj.Pkg().Path() == reflectPkgPath
}

// carriesReflectValue reports whether a node of type t should be allowed to
// carry propagated labels because it is, or nests a pointer to, a
// reflect.Value. This is the hook that hasInFlow consults; see part 1 of the
// file comment.
func carriesReflectValue(t types.Type) bool {
	if t == nil {
		return false
	}
	if isReflectValue(t) {
		return true
	}
	// Mirrors interfaceUnderPtr: unwrap arbitrarily nested pointers.
	seen := make(map[types.Type]bool)
	for {
		if seen[t] {
			return false
		}
		seen[t] = true
		p, ok := t.Underlying().(*types.Pointer)
		if !ok {
			return false
		}
		if isReflectValue(p.Elem()) {
			return true
		}
		t = p.Elem()
	}
}

// inReflectPackage reports whether f is defined in package reflect. Such
// functions are summarized rather than analyzed.
func inReflectPackage(f *ssa.Function) bool {
	// Methods on reflect types have f.Pkg == nil when they are wrappers, so
	// consult the receiver's package as well.
	if f.Pkg != nil && f.Pkg.Pkg != nil {
		return f.Pkg.Pkg.Path() == reflectPkgPath
	}
	if obj := f.Object(); obj != nil && obj.Pkg() != nil {
		return obj.Pkg().Path() == reflectPkgPath
	}
	return false
}

// reflectSummary describes how a call into package reflect moves labels.
type reflectSummary struct {
	// toResult, when true, adds an edge from the summarized source operand
	// to the call's result, preserving the payload's identity.
	toResult bool
	// toReceiver, when true, adds an edge from the call's non-receiver
	// arguments back to the receiver, modeling a mutation.
	toReceiver bool
	// dispatch, when true, marks the site as a reflective call: the
	// receiver's function labels are its callees (see resolves).
	dispatch bool
}

// reflectSummaries maps a reflect function or method name to its summary.
// Names are matched on the callee's name alone, which is unambiguous because
// only package reflect reaches here.
//
// Anything in package reflect that is absent from this table is a blind spot:
// its arguments still enter the pool and its result is labelled unknown, so
// missing an entry costs precision but never soundness.
var reflectSummaries = map[string]reflectSummary{
	// Entering the reflect world, and moving within it. Field and index
	// selection deliberately ignore which field or index was selected: that
	// precision is not worth the complexity, and the containing value's
	// label set is a sound answer for any component of it.
	"ValueOf":      {toResult: true},
	"Indirect":     {toResult: true},
	"Elem":         {toResult: true},
	"Field":        {toResult: true},
	"FieldByName":  {toResult: true},
	"FieldByIndex": {toResult: true},
	"Index":        {toResult: true},
	"MapIndex":     {toResult: true},
	"Addr":         {toResult: true},
	"Convert":      {toResult: true},
	"Method":       {toResult: true},
	"MethodByName": {toResult: true},

	// Leaving the reflect world. This is the injection point: the value dig
	// hands back to the code that asked for it.
	"Interface": {toResult: true},

	// Mutation: the argument's labels become reachable through the receiver.
	"Set":         {toReceiver: true},
	"SetMapIndex": {toReceiver: true},
	"Send":        {toReceiver: true},

	// Reflective dispatch. The receiver holds the function being called; its
	// results come back through the pool.
	"Call":      {dispatch: true},
	"CallSlice": {dispatch: true},
}

// isReflectDispatch reports whether c is a reflective call, i.e. one whose
// callees are determined by the labels on its receiver rather than by the
// call graph. Consulted by resolves before the static-callee fast path,
// because (reflect.Value).Call is itself a static call.
func isReflectDispatch(c ssa.CallInstruction) bool {
	callee := c.Common().StaticCallee()
	if callee == nil || !inReflectPackage(callee) {
		return false
	}
	return reflectSummaries[callee.Name()].dispatch
}

// reflectCall applies the summary for a call into package reflect, and
// reports whether it did. When it returns true the caller must not add the
// ordinary argument and result flows: the summary replaces them.
func (b *builder) reflectCall(c ssa.CallInstruction) bool {
	callee := c.Common().StaticCallee()
	if callee == nil || !inReflectPackage(callee) {
		return false
	}
	b.usesReflect = true

	args := c.Common().Args
	site, isValue := c.(ssa.Value)
	summary, modeled := reflectSummaries[callee.Name()]

	// Every operand handed to reflect may be reached reflectively later on,
	// whatever the API does with it. This is what connects a constructor
	// passed to fx.Provide with the site that eventually invokes it.
	for _, arg := range args {
		b.addInFlowEdge(b.nodeFromVal(arg), reflectPool{typ: arg.Type()})
	}

	if !modeled {
		// A blind spot. The result's provenance is unknown, and so is the slot
		// it would have come from, so there is no pool to draw on: label it
		// unknown and let the seed answer any site that consumes it.
		if isValue {
			b.addInFlowEdge(unknown{}, b.nodeFromVal(site))
		}
		return true
	}

	// Method summaries move labels relative to the receiver, which SSA
	// passes as the first argument.
	if summary.toReceiver && len(args) > 1 {
		for _, arg := range args[1:] {
			b.addInFlowEdge(b.nodeFromVal(arg), b.nodeFromVal(args[0]))
		}
	}

	if isValue && summary.toResult && len(args) > 0 {
		// Direct edge from the summarized operand, which keeps this
		// value's identity distinct from the rest of the pool.
		b.addReflectResultEdges(b.nodeFromVal(args[0]), site)
	}

	if isValue && summary.dispatch {
		// The callees are not known until propagation has run, so their
		// results cannot be wired up here. They do not need to be: every
		// function used as a value already deposits its results into the pool
		// slot for their type (see linkReflectPool), which is where the
		// consumer of an injected value draws from. All that is left to record
		// is that this slice itself holds something unidentified.
		b.addReflectResultEdges(unknown{}, site)
	}

	return true
}

// addReflectResultEdges adds an edge from src to the result of a reflect
// call. A result of type []reflect.Value is not itself flow-carrying, so the
// edge targets the slice's element node, which is where reads of the slice
// draw from.
func (b *builder) addReflectResultEdges(src node, site ssa.Value) {
	if s, ok := site.Type().Underlying().(*types.Slice); ok {
		b.addInFlowEdge(src, sliceElem{typ: s.Elem()})
		return
	}
	b.addInFlowEdge(src, b.nodeFromVal(site))
}

// linkReflectPool connects the reflection subsystem to the functions it may
// reach. Any function used as a value may be invoked reflectively, so the
// pool flows to its parameters and its results flow back to the pool. Both
// directions are needed for dependency injection: the container calls a
// constructor with dependencies it is holding, then holds the result so it
// can pass it to the next constructor.
//
// This is linear in the number of such functions, unlike the site-by-site
// cross product RTA computes.
func (b *builder) linkReflectPool() {
	if !b.usesReflect {
		return
	}
	for f := range b.addrTaken {
		for _, p := range f.Params {
			b.linkPoolTo(b.nodeFromVal(p), p.Type(), make(map[types.Type]bool))
		}
		results := f.Signature.Results()
		for i := 0; i < results.Len(); i++ {
			b.linkPoolFrom(resultVar{f: f, index: i}, results.At(i).Type(), make(map[types.Type]bool))
		}
	}
	b.linkPoolSlots()
}

// linkPoolSlots connects a slot to every slot whose type it satisfies.
//
// Slots are keyed by static type, but a container's producer and consumer
// rarely name the same one: a constructor returns *lottery.gateway and the
// controller asks for the lottery.Gateway interface. Without this closure the
// label would sit in the concrete slot and never reach the site that needs it
// — a false negative of exactly the kind this fork exists to prevent.
//
// The edges go from the satisfying type to the interface, matching the
// direction a value moves, so a slot never acquires labels of types that
// cannot appear there.
func (b *builder) linkPoolSlots() {
	srcs := b.poolSrc.Keys()
	b.poolDst.Iterate(func(dst types.Type, _ any) {
		i, ok := dst.Underlying().(*types.Interface)
		if !ok || i.Empty() {
			// A non-interface slot is satisfied only by its own type, which
			// already shares the slot. An empty interface is satisfied by
			// everything, and wiring that up would rebuild the single merged
			// pool this keying exists to avoid; the unknown label covers it.
			return
		}
		for _, src := range srcs {
			if !types.Identical(src, dst) && types.Implements(src, i) {
				b.graph.addEdge(reflectPool{typ: src}, reflectPool{typ: dst})
			}
		}
	})
}

// linkPoolTo makes the reflection pool flow into a value of type t reaching
// node n.
//
// Struct types need the recursion. A dependency-injection container does not
// hand a constructor its dependencies one at a time; fx and glue pass a single
// `fx.In` struct whose fields the container fills in reflectively. That struct
// is not itself flow-carrying, so without descending into its fields the pool
// would stop at the parameter and every injected dependency would be lost.
func (b *builder) linkPoolTo(n node, t types.Type, seen map[types.Type]bool) {
	if hasInFlow(n) {
		slot := canonicalize(n.Type(), &b.canon)
		b.poolDst.Set(slot, true)
		b.addInFlowEdge(reflectPool{typ: slot}, n)
		return
	}
	b.eachStructField(t, seen, func(fn node, ft types.Type) {
		b.linkPoolTo(fn, ft, seen)
	})
}

// linkPoolFrom makes a value of type t held by node n flow into the pool. The
// mirror of linkPoolTo: constructors return `fx.Out` structs just as they
// accept `fx.In` structs.
//
// The admission test is deliberately weaker than linkPoolTo's. A node only
// needs to be flow-carrying to *receive* labels; to *supply* one it just has
// to have a type worth naming, and a constructor's concrete return type is
// the single most important thing the pool can learn. linkPoolSlots is what
// carries it on to the interface slots it satisfies.
func (b *builder) linkPoolFrom(n node, t types.Type, seen map[types.Type]bool) {
	if nt := n.Type(); canSatisfyInterface(nt) {
		slot := canonicalize(nt, &b.canon)
		b.poolSrc.Set(slot, true)
		b.addInFlowEdge(n, reflectPool{typ: slot})
		return
	}
	b.eachStructField(t, seen, func(fn node, ft types.Type) {
		b.linkPoolFrom(fn, ft, seen)
	})
}

// eachStructField calls yield for each field of t, if t is a (pointer to)
// struct. seen guards against recursive types.
func (b *builder) eachStructField(t types.Type, seen map[types.Type]bool, yield func(node, types.Type)) {
	if t == nil || seen[t] {
		return
	}
	seen[t] = true

	u := t.Underlying()
	if p, ok := u.(*types.Pointer); ok {
		// field nodes are keyed by the struct type itself, not a pointer to
		// it: field.Type() asserts the core type is a struct.
		t = p.Elem()
		u = t.Underlying()
	}
	s, ok := u.(*types.Struct)
	if !ok {
		return
	}
	for i := 0; i < s.NumFields(); i++ {
		yield(field{StructType: t, index: i}, s.Field(i).Type())
	}
}

// canSatisfyInterface reports whether a value of type t is worth a pool slot
// of its own, i.e. whether it could ever be what some interface slot is
// waiting for.
//
// Structs are excluded even when they have methods: in the DI setting a struct
// return is an `fx.Out` bundle, and the caller's field recursion handles those
// better than a slot for the bundle type would.
func canSatisfyInterface(t types.Type) bool {
	if t == nil {
		return false
	}
	if types.IsInterface(t) || isFunction(t) {
		return true
	}
	if _, ok := t.Underlying().(*types.Struct); ok {
		return false
	}
	return types.NewMethodSet(t).Len() > 0
}

// noteAddrTaken records that f is used as a value and so may be invoked
// reflectively. Called from the two places that build a function node.
func (b *builder) noteAddrTaken(f *ssa.Function) {
	if b.addrTaken == nil {
		b.addrTaken = make(map[*ssa.Function]bool)
	}
	b.addrTaken[f] = true
}

// convert handles ssa.Convert. Upstream lumps Convert in with the no-op
// group, which is right for numeric widening, string/byte, etc. but wrong
// for unsafe.Pointer conversions to a flow-carrying type: the destination
// value is a load from raw memory, its provenance is not modeled anywhere,
// and treating the destination register as "no labels" would misrepresent
// silence as proof of infeasibility once the taint-only fallback lands in
// constructor.resolves.
//
// hasInFlow on the destination gates uninteresting targets (e.g. *byte,
// uintptr), so any Convert whose result is not an interface, function type,
// pointer-to-either, or reflect.Value silently no-ops.
func (b *builder) convert(c *ssa.Convert) {
	if !isUnsafePointer(c.X.Type()) {
		return
	}
	b.addInFlowEdge(unknown{}, b.nodeFromVal(c))
}

// isUnsafePointer reports whether t is unsafe.Pointer.
func isUnsafePointer(t types.Type) bool {
	b, ok := t.Underlying().(*types.Basic)
	return ok && b.Kind() == types.UnsafePointer
}

// linkBodylessResults seeds ⊤ on the results of functions the traversal
// cannot walk. builder.fun visits only functions with a body; assembly stubs,
// //go:linkname declarations, cgo boundaries and other body-less functions
// have result variables that no producer edge ever reaches. Without a label
// there, a caller invoking an interface or function returned by such a stub
// sees an empty answer at the dispatch site — and under the taint-only
// fallback in constructor.resolves that emptiness is read as proof of
// infeasibility. It is not: the stub's return value is a structural blind
// spot, and ⊤ is the correct label.
//
// Reflect functions are excluded: they are handled by the summary in
// reflectCall and never reach an unresolved dispatch site, so seeding ⊤
// on their results only adds noise. hasInFlow on the destination gates
// non-flow-carrying result types, so passing every index is safe.
func (b *builder) linkBodylessResults(funcs map[*ssa.Function]bool) {
	for f, in := range funcs {
		if !in || len(f.Blocks) != 0 || inReflectPackage(f) {
			continue
		}
		results := f.Signature.Results()
		for i := 0; i < results.Len(); i++ {
			b.addInFlowEdge(unknown{}, resultVar{f: f, index: i})
		}
	}
}

// linkUnwrittenFields seeds ⊤ on struct fields that are read in the reachable
// universe but never written there. A field's writers are its containing
// struct's constructors and any explicit `.f = v` assignment; if none of those
// live in `funcs` the field has no producer edge in the propagation graph and
// a read yields the empty set. Under the taint-only fallback that emptiness
// would be misread as proof of infeasibility — but the truth is a structural
// blind spot: the field's value was set somewhere the analysis did not visit.
//
// The concrete failure this fixes on cff-demo is an interface field of an
// inbound handler whose constructor is not fx-provided (so RTA still reaches
// the handler's method as an inbound entry, but VTA never sees the field
// being wired). Without this seed, dispatch through the field returns empty
// and the whole invocation chain is dropped.
//
// The write set is deliberately generous: any Store whose address is a
// FieldAddr counts, which covers both direct assignments and Go SSA's
// lowering of composite literals `T{F: v}` into Alloc + FieldAddr + Store.
// The read set is likewise every FieldAddr and Field instruction. Reflective
// writes (Value.Set on a field) are handled by reflectCall's toReceiver
// summary and do not need to be counted here — treating a reflectively-set
// field as unwritten only routes it through the fallback, which is sound.
//
// hasInFlow gates the addInFlowEdge, so passing non-flow-carrying field
// types is a silent no-op.
func (b *builder) linkUnwrittenFields(funcs map[*ssa.Function]bool) {
	type key struct {
		t   types.Type
		idx int
	}
	written := make(map[key]bool)
	read := make(map[key]bool)

	structOf := func(t types.Type) types.Type {
		if p, ok := t.Underlying().(*types.Pointer); ok {
			return canonicalize(p.Elem(), &b.canon)
		}
		return canonicalize(t, &b.canon)
	}

	for f, in := range funcs {
		if !in || inReflectPackage(f) {
			continue
		}
		for _, bl := range f.Blocks {
			for _, instr := range bl.Instrs {
				switch i := instr.(type) {
				case *ssa.Store:
					if fa, ok := i.Addr.(*ssa.FieldAddr); ok {
						written[key{t: structOf(fa.X.Type()), idx: fa.Field}] = true
					}
				case *ssa.FieldAddr:
					read[key{t: structOf(i.X.Type()), idx: i.Field}] = true
				case *ssa.Field:
					read[key{t: canonicalize(i.X.Type(), &b.canon), idx: i.Field}] = true
				}
			}
		}
	}

	for k := range read {
		if written[k] {
			continue
		}
		b.addInFlowEdge(unknown{}, field{StructType: k.t, index: k.idx})
	}
}
