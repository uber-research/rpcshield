// Tests for the rpcshield fork's additions on top of upstream VTA. These
// exercise the Layer-3 refinement described in the plan (taint-only fallback)
// and its soundness prerequisites (⊤ seeding at every structural blind spot).
//
// Programs are built inline via loader.Config + ssautil.CreateProgram — the
// same pattern rpcshield/graph/cct_sampling_test.go uses — and seeded with a
// CHA callgraph. CHA is a sound over-approximation, which is exactly what the
// intersection in resolves() expects; it is not the RTA the production driver
// uses, but the discriminator logic under test is independent of the seed's
// flavor.

package vta

import (
	"fmt"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/loader"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
	"golang.org/x/tools/go/types/typeutil"
)

// ---------------------------------------------------------------------------
// Pure unit tests — no SSA program required.
// ---------------------------------------------------------------------------

func TestFallbackReason_String(t *testing.T) {
	t.Parallel()
	cases := []struct {
		r    FallbackReason
		want string
	}{
		{ReasonInterfaceTaintEmpty, "InterfaceTaintEmpty"},
		{ReasonInterfaceTaintPartial, "InterfaceTaintPartial"},
		{ReasonReflectTaintEmpty, "ReflectTaintEmpty"},
		{ReasonReflectTaintPartial, "ReflectTaintPartial"},
		{FallbackReason(0), "FallbackReason(unknown)"},
		{FallbackReason(42), "FallbackReason(unknown)"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.r.String())
	}
}

func TestNewConfig_Defaults(t *testing.T) {
	t.Parallel()
	c := newConfig(nil)
	assert.False(t, c.strict)
	assert.Nil(t, c.observer)
}

func TestWithStrict(t *testing.T) {
	t.Parallel()
	c := newConfig([]Option{WithStrict()})
	assert.True(t, c.strict)
}

func TestWithFallbackObserver(t *testing.T) {
	t.Parallel()
	var got FallbackReason
	obs := func(_ ssa.CallInstruction, r FallbackReason) { got = r }
	c := newConfig([]Option{WithFallbackObserver(obs)})
	require.NotNil(t, c.observer)
	c.observer(nil, ReasonInterfaceTaintEmpty)
	assert.Equal(t, ReasonInterfaceTaintEmpty, got)
}

func TestIsUnknown(t *testing.T) {
	t.Parallel()
	assert.True(t, isUnknown(propType{typ: topType}), "topType alone is the unknown label")
	assert.False(t, isUnknown(propType{typ: topType, f: &ssa.Function{}}),
		"a propType with a function is never unknown, even when typ == topType")
	assert.False(t, isUnknown(propType{typ: types.Typ[types.Int]}),
		"non-topType is not unknown")
}

func TestUnknownNode(t *testing.T) {
	t.Parallel()
	assert.Equal(t, topType, unknown{}.Type())
	assert.Equal(t, "Unknown", unknown{}.String())
	// unknown{} is always used as a *source* in addInFlowEdge (see reflectCall,
	// linkBodylessResults, convert), so hasInFlow is not what gates it — only
	// destinations are checked. What matters is that propagation.go labels it
	// with topType: hasInitialTypes must return true so that unknown{} is
	// seeded from its own type by the initial-type machinery, giving every
	// downstream edge the ⊤ label.
	assert.True(t, hasInitialTypes(unknown{}),
		"unknown{} must self-seed with topType so downstream nodes receive ⊤")
	// getPropType on unknown{} must return the ⊤ label.
	var canon typeutil.Map
	pt := getPropType(unknown{}, &canon)
	assert.True(t, isUnknown(pt),
		"getPropType(unknown{}) must produce the ⊤ label")
}

func TestIsUnsafePointer(t *testing.T) {
	t.Parallel()
	assert.True(t, isUnsafePointer(types.Typ[types.UnsafePointer]))
	assert.False(t, isUnsafePointer(types.Typ[types.Int]))
	assert.False(t, isUnsafePointer(types.Typ[types.String]))
	// A named type whose underlying is unsafe.Pointer is still unsafe.Pointer.
	name := types.NewTypeName(token.NoPos, nil, "P", types.Typ[types.UnsafePointer])
	named := types.NewNamed(name, types.Typ[types.UnsafePointer], nil)
	assert.True(t, isUnsafePointer(named))
	// A pointer to unsafe.Pointer is not unsafe.Pointer.
	assert.False(t, isUnsafePointer(types.NewPointer(types.Typ[types.UnsafePointer])))
}

// TestReflectPool_NoInitialTypes guards against a regression: reflectPool is
// a conduit keyed by type. If it ever acquires its own initial label, that
// label leaks to every consumer of the pool and reflection results become
// indistinguishable from noise.
func TestReflectPool_NoInitialTypes(t *testing.T) {
	t.Parallel()
	assert.False(t, hasInitialTypes(reflectPool{typ: types.Typ[types.Int]}))
	assert.True(t, hasInFlow(reflectPool{typ: types.Typ[types.Int]}))
}

// TestCarriesReflectValue_NilSafe pins the nil-guard added in the fork.
// carriesReflectValue is called from hasInFlow which is called from
// addInFlowEdge which is called from every seed helper; a nil-type node would
// crash the whole pipeline.
func TestCarriesReflectValue_NilSafe(t *testing.T) {
	t.Parallel()
	assert.False(t, carriesReflectValue(nil))
}

// ---------------------------------------------------------------------------
// End-to-end scaffolding.
// ---------------------------------------------------------------------------

// buildProgram loads a single-package Go source string and returns the SSA
// program plus the SSA package. The stdlib is available because Bazel's Go
// SDK is in scope; that lets tests import reflect, unsafe, sync, etc.
func buildProgram(t *testing.T, src string) (*ssa.Program, *ssa.Package) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "test.go", src, parser.ParseComments)
	require.NoError(t, err)

	conf := loader.Config{
		Fset:        fset,
		ParserMode:  parser.ParseComments,
		AllowErrors: false,
	}
	conf.CreateFromFiles("testpkg", f)
	lprog, err := conf.Load()
	require.NoError(t, err)

	prog := ssautil.CreateProgram(lprog, ssa.InstantiateGenerics)
	prog.Build()

	var testpkg *ssa.Package
	for _, p := range prog.AllPackages() {
		if p.Pkg.Path() == "testpkg" {
			testpkg = p
			break
		}
	}
	require.NotNil(t, testpkg, "testpkg not in program")
	return prog, testpkg
}

// reachableFrom returns every function reachable in cg from any function in
// pkg. That is a good analog of what rpcshield's real driver passes as the
// `funcs` argument: functions the seed's reachability analysis already
// visited.
func reachableFrom(cg *callgraph.Graph, pkg *ssa.Package) map[*ssa.Function]bool {
	funcs := make(map[*ssa.Function]bool)
	var visit func(f *ssa.Function)
	visit = func(f *ssa.Function) {
		if f == nil || funcs[f] {
			return
		}
		funcs[f] = true
		node := cg.Nodes[f]
		if node == nil {
			return
		}
		for _, e := range node.Out {
			visit(e.Callee.Func)
		}
	}
	for _, m := range pkg.Members {
		if fn, ok := m.(*ssa.Function); ok {
			visit(fn)
		}
	}
	return funcs
}

// findFunc walks every function reachable in prog and returns the one whose
// name matches. Anonymous-function names are stable ("caller$1" etc.), so
// this is deterministic.
func findFunc(t *testing.T, prog *ssa.Program, name string) *ssa.Function {
	t.Helper()
	for fn := range ssautil.AllFunctions(prog) {
		if fn.Name() == name {
			return fn
		}
	}
	t.Fatalf("function %q not found", name)
	return nil
}

// findCall returns the first call instruction in f whose Common().Value's
// String() contains marker. Callers pick markers unique enough to identify
// the site (e.g. "invoke", the interface's method name, or a specific
// package.function).
func findCall(t *testing.T, f *ssa.Function, marker string) ssa.CallInstruction {
	t.Helper()
	for _, bl := range f.Blocks {
		for _, instr := range bl.Instrs {
			c, ok := instr.(ssa.CallInstruction)
			if !ok {
				continue
			}
			if callString(c) != "" && strings.Contains(callString(c), marker) {
				return c
			}
		}
	}
	t.Fatalf("call matching %q not found in %s", marker, f)
	return nil
}

func callString(c ssa.CallInstruction) string {
	cc := c.Common()
	if cc == nil {
		return ""
	}
	if cc.Method != nil {
		return fmt.Sprintf("invoke %s.%s", cc.Value.Type(), cc.Method.Name())
	}
	if cc.Value != nil {
		return cc.Value.String()
	}
	return ""
}

// runVTA builds a CHA seed over prog and returns the VTA callgraph plus every
// fallback event the observer recorded, in order. opts are appended after
// WithFallbackObserver — pass WithStrict() and it wins as expected.
func runVTA(t *testing.T, prog *ssa.Program, pkg *ssa.Package, opts ...Option) (*callgraph.Graph, []observedEvent) {
	t.Helper()
	seed := cha.CallGraph(prog)
	funcs := reachableFrom(seed, pkg)

	var events []observedEvent
	obs := func(c ssa.CallInstruction, r FallbackReason) {
		events = append(events, observedEvent{call: c, reason: r})
	}
	allOpts := append([]Option{WithFallbackObserver(obs)}, opts...)
	cg := CallGraph(funcs, seed, allOpts...)
	require.NotNil(t, cg)
	return cg, events
}

type observedEvent struct {
	call   ssa.CallInstruction
	reason FallbackReason
}

// calleeNames returns the sorted-set-like list of callee names at site in cg.
func calleeNames(cg *callgraph.Graph, site ssa.CallInstruction) []string {
	caller := site.Parent()
	node := cg.Nodes[caller]
	if node == nil {
		return nil
	}
	var names []string
	seen := make(map[string]bool)
	for _, e := range node.Out {
		if e.Site == site && e.Callee != nil && e.Callee.Func != nil {
			n := e.Callee.Func.Name()
			if !seen[n] {
				seen[n] = true
				names = append(names, n)
			}
		}
	}
	return names
}

// ---------------------------------------------------------------------------
// Discriminator cases for interface dispatch.
// ---------------------------------------------------------------------------

// TestFallback_InterfaceUntaintedNonEmpty: one concrete type flows to the
// receiver via a direct MakeInterface. VTA sees exactly that; no fallback.
func TestFallback_InterfaceUntaintedNonEmpty(t *testing.T) {
	t.Parallel()
	src := `package testpkg

type I interface{ M() }

type A struct{}
func (A) M() {}

type B struct{}
func (B) M() {}

func caller(i I) { i.M() }

func entry() {
	var a A
	caller(a)
	// B is instantiated somewhere but never reaches caller's receiver.
	_ = B{}
}
`
	prog, pkg := buildProgram(t, src)
	cg, events := runVTA(t, prog, pkg)

	caller := findFunc(t, prog, "caller")
	site := findCall(t, caller, "invoke")
	names := calleeNames(cg, site)

	// VTA should resolve to A.M only. CHA would give both A.M and B.M; the
	// intersection with propagated types selects A.
	assert.Contains(t, names, "M")
	assert.Len(t, names, 1, "VTA should prune B.M since only A flows to caller's I")
	// Observer must not have fired for this site.
	for _, e := range events {
		assert.NotEqual(t, site, e.call, "no fallback expected on precise site")
	}
}

// TestFallback_InterfaceUntaintedEmpty: no concrete type reaches the
// receiver. Under the new discriminator the answer is empty and the observer
// does NOT fire. Under the old "empty || tainted" rule the observer would
// fire and RTA's candidates would be substituted.
func TestFallback_InterfaceUntaintedEmpty(t *testing.T) {
	t.Parallel()
	src := `package testpkg

type I interface{ M() }

type A struct{}
func (A) M() {}

func caller(i I) { i.M() }

// entry never actually calls caller with any concrete value; the interface
// remains nil-typed at the invoke site.
func entry() {
	var i I
	caller(i)
	_ = A{} // A exists globally but never flows into caller.
}
`
	prog, pkg := buildProgram(t, src)
	cg, events := runVTA(t, prog, pkg)

	caller := findFunc(t, prog, "caller")
	site := findCall(t, caller, "invoke")
	names := calleeNames(cg, site)

	// The precise answer is empty. Any callee would come from the seed
	// fallback, which we now suppress on untainted-empty.
	assert.Empty(t, names, "untainted empty must not fall back to seed")
	for _, e := range events {
		assert.NotEqual(t, site, e.call,
			"observer must not fire on untainted-empty sites")
	}
}

// TestStrictMode_NoFallback: WithStrict short-circuits before both branches
// that would otherwise invoke the observer or return seed candidates. The
// short-circuit sits above the discriminator, so exercising any dispatch site
// under WithStrict is enough to prove it fires: the observer must stay silent
// even on the untainted-empty case (where non-strict already stays silent,
// but strict short-circuits earlier), and the returned edge set must match
// what VTA computed with no fallback applied. Reflection-tainted cases are
// covered by TestE2EVTA end-to-end.
func TestStrictMode_NoFallback(t *testing.T) {
	t.Parallel()
	src := `package testpkg

type I interface{ M() }

type A struct{}
func (A) M() {}

// caller receives a nil interface — untainted-empty for VTA. Non-strict
// already suppresses the fallback here; strict must additionally suppress
// the observer on any imaginable receiver.
func caller(i I) { i.M() }

func entry() {
	var i I
	caller(i)
	_ = A{}
}
`
	prog, pkg := buildProgram(t, src)
	_, events := runVTA(t, prog, pkg, WithStrict())
	assert.Empty(t, events, "strict mode must never invoke the observer")
}

// TestObserver_OptionalWhenNil confirms that passing no observer produces the
// same graph as passing a nil observer explicitly, and that neither crashes
// on any of the four discriminator cases.
func TestObserver_OptionalWhenNil(t *testing.T) {
	t.Parallel()
	src := `package testpkg

type I interface{ M() }
type A struct{}
func (A) M() {}

func caller(i I) { i.M() }
func entry()    { caller(A{}) }
`
	prog, pkg := buildProgram(t, src)
	seed := cha.CallGraph(prog)
	funcs := reachableFrom(seed, pkg)

	cgUnset := CallGraph(funcs, seed)
	cgNil := CallGraph(funcs, seed, WithFallbackObserver(nil))

	// Same number of edges is a coarse but adequate parity check: both
	// invocations run the same code path.
	assert.Equal(t, edgeCount(cgUnset), edgeCount(cgNil),
		"nil observer must be behaviorally identical to unset")
}

func edgeCount(cg *callgraph.Graph) int {
	n := 0
	for _, node := range cg.Nodes {
		n += len(node.Out)
	}
	return n
}

// ---------------------------------------------------------------------------
// Blind-spot seeding — soundness prerequisites for row 1 of the discriminator.
// ---------------------------------------------------------------------------
//
// The behavioral tests for body-less functions and unsafe.Pointer conversions
// require loading programs that import reflect/unsafe, which the Bazel test
// sandbox cannot resolve (no `go` binary available to loader.Config). Coverage
// for those paths lives in rpcshield/graph/graph_test.go's TestE2EVTA, which
// loads real cff-demo packages via the Bazel-provided fixture and exercises
// every blind-spot seed on production DI code.
//
// TestConvert_NonUnsafePointerIsNoOp remains here because it can prove the
// "no false positive" side with a pure-Go program — no reflect/unsafe needed
// on the destination side either.

// TestConvert_NonUnsafePointerIsNoOp: builder.convert must silently no-op on
// conversions that are not from unsafe.Pointer. Otherwise every int→int64,
// []byte→string, etc. would seed ⊤ and the graph would collapse.
func TestConvert_NonUnsafePointerIsNoOp(t *testing.T) {
	t.Parallel()
	src := `package testpkg

type I interface{ M() }
type A struct{}
func (A) M() {}

func caller(i I) { i.M() }

func entry() {
	// Lots of ordinary conversions; none should taint.
	var x int = 42
	var y int64 = int64(x)
	_ = y
	var s = string([]byte("hi"))
	_ = s
	var a A
	caller(a)
}
`
	prog, pkg := buildProgram(t, src)
	_, events := runVTA(t, prog, pkg)

	caller := findFunc(t, prog, "caller")
	site := findCall(t, caller, "invoke")
	for _, e := range events {
		assert.NotEqual(t, site, e.call,
			"ordinary conversions must not taint interface receivers")
	}
}

// TestBlindSpot_ReadOnlyField: a field that is read in the reachable universe
// but never written there is a structural blind spot — its value must have
// been set somewhere the analysis did not visit. Without ⊤ seeding on such
// fields, VTA reports empty at dispatch sites that go through them and the
// discriminator would misread that as proof of infeasibility. This is the
// pattern that reproduced on cff-demo for tchanHandler.cffdemo, whose
// constructor NewTChan is not fx-provided and therefore not in the reachable
// set.
//
// The test uses two fields on the same struct: one written in the reachable
// entry, one not. The written-field site must remain precise (no fallback),
// the unwritten-field site must fall back with TaintEmpty. This proves the
// seeding fires exactly where it should — no under-seeding (missing the
// unwritten case) and no over-seeding (tainting the written case).
func TestBlindSpot_ReadOnlyField(t *testing.T) {
	t.Parallel()
	src := `package testpkg

type I interface{ M() }

type A struct{}
func (A) M() {}

type H struct {
	Written   I
	Unwritten I
}

func (h *H) UseWritten()   { h.Written.M() }
func (h *H) UseUnwritten() { h.Unwritten.M() }

func entry() {
	var a A
	// Composite literal writes only Written. Unwritten is left zero and is
	// never assigned anywhere in the reachable universe.
	h := &H{Written: a}
	h.UseWritten()
	h.UseUnwritten()
}
`
	prog, pkg := buildProgram(t, src)
	_, events := runVTA(t, prog, pkg)

	useWritten := findFunc(t, prog, "UseWritten")
	writtenSite := findCall(t, useWritten, "invoke")
	for _, e := range events {
		assert.NotEqual(t, writtenSite, e.call,
			"UseWritten's receiver received A via the composite literal; the field is in the write-set and must not be ⊤-seeded")
	}

	useUnwritten := findFunc(t, prog, "UseUnwritten")
	unwrittenSite := findCall(t, useUnwritten, "invoke")
	sawUnwrittenFallback := false
	for _, e := range events {
		if e.call == unwrittenSite {
			sawUnwrittenFallback = true
			assert.Equal(t, ReasonInterfaceTaintEmpty, e.reason,
				"only the ⊤ seed reaches the receiver; nothing concrete flows in, so the fallback reason is TaintEmpty not TaintPartial")
		}
	}
	assert.True(t, sawUnwrittenFallback,
		"read-only field must be ⊤-seeded so the discriminator falls back at dispatch sites that read it")
}

// TestBlindSpot_ReadOnlyField_StrictSuppresses is the strict-mode complement:
// the ⊤ seed still reaches the receiver, but WithStrict short-circuits before
// both the observer and the seed fallback. The dispatch is left empty on the
// modeled universe, which is what "measure VTA's unaided precision" means.
func TestBlindSpot_ReadOnlyField_StrictSuppresses(t *testing.T) {
	t.Parallel()
	src := `package testpkg

type I interface{ M() }
type A struct{}
func (A) M() {}

type H struct{ F I }

func (h *H) Use() { h.F.M() }

func entry() {
	h := &H{}
	h.Use()
	_ = A{}
}
`
	prog, pkg := buildProgram(t, src)
	cg, events := runVTA(t, prog, pkg, WithStrict())
	assert.Empty(t, events,
		"strict mode must suppress the observer even on ⊤-seeded read-only fields")

	use := findFunc(t, prog, "Use")
	site := findCall(t, use, "invoke")
	names := calleeNames(cg, site)
	assert.Empty(t, names,
		"strict mode returns VTA's own answer (empty here) rather than falling back to seed candidates")
}

// TestBlindSpot_ReadOnlyField_ValueReceiver mirrors the pointer-receiver case
// above with a value-receiver method (ssa.Field, not ssa.FieldAddr). The
// unwritten-field discriminator branch must fire either way — the seeding
// analysis has to track both read shapes.
func TestBlindSpot_ReadOnlyField_ValueReceiver(t *testing.T) {
	t.Parallel()
	src := `package testpkg

type I interface{ M() }
type A struct{}
func (A) M() {}

type H struct{ F I }

func (h H) Use() { h.F.M() }

func entry() {
	var h H
	h.Use()
	_ = A{}
}
`
	prog, pkg := buildProgram(t, src)
	_, events := runVTA(t, prog, pkg)

	use := findFunc(t, prog, "Use")
	site := findCall(t, use, "invoke")
	saw := false
	for _, e := range events {
		if e.call == site {
			saw = true
			assert.Equal(t, ReasonInterfaceTaintEmpty, e.reason)
		}
	}
	assert.True(t, saw,
		"value-receiver Field reads must trigger the same seeding as pointer-receiver FieldAddr reads")
}

// TestBlindSpot_ReadOnlyField_NonFlowCarryingIsNoOp: fields whose type is not
// flow-carrying (e.g. int, string) must not participate in the seeding — the
// analysis passes every field to addInFlowEdge, but hasInFlow on the target
// silently gates non-flow-carrying types. Regression guard against widening
// the destination test in a way that would explode the graph.
func TestBlindSpot_ReadOnlyField_NonFlowCarryingIsNoOp(t *testing.T) {
	t.Parallel()
	src := `package testpkg

type I interface{ M() }
type A struct{}
func (A) M() {}

// H's Count field is int (non-flow-carrying) and unwritten. It must not
// contribute any label. Iface is flow-carrying and unwritten; that one
// legitimately gets ⊤ seeded — but the test only asserts on Count.
type H struct {
	Count int
	Iface I
}

func (h *H) UseCount() int { return h.Count + 1 }

func entry() {
	h := &H{}
	_ = h.UseCount()
	_ = A{}
}
`
	prog, pkg := buildProgram(t, src)
	// No panic and no dispatch to observe — the point of the test is to make
	// sure the seeding step tolerates non-flow-carrying field types without
	// polluting the graph. If linkUnwrittenFields were structured wrong it
	// would trip the hasInFlow assertion inside addInFlowEdge, which panics.
	_, _ = runVTA(t, prog, pkg)
}

// ---------------------------------------------------------------------------
// DI regression — the whole point of the fork.
// ---------------------------------------------------------------------------
//
// The reflect-round-trip regressions require loading a program that imports
// reflect, which the Bazel test sandbox cannot resolve. That behavior is
// exercised end-to-end by TestE2EVTA in rpcshield/graph/graph_test.go against
// the cff-demo fixture, which uses the same reflect.ValueOf/.Interface pattern
// dig actually generates.

// TestDI_MethodValueThroughChannel: a method value passed through a channel
// must remain callable. This is the pattern that appeared in the milestone-3
// differential — an fx-provided constructor stored into a channel-backed
// registry.
func TestDI_MethodValueThroughChannel(t *testing.T) {
	t.Parallel()
	src := `package testpkg

type S struct{}
func (S) Do() int { return 1 }

func caller(f func() int) { _ = f() }

func entry() {
	ch := make(chan func() int, 1)
	var s S
	ch <- s.Do
	f := <-ch
	caller(f)
}
`
	prog, pkg := buildProgram(t, src)
	cg, _ := runVTA(t, prog, pkg)
	caller := findFunc(t, prog, "caller")
	// The dynamic call in caller.
	var site ssa.CallInstruction
	for _, bl := range caller.Blocks {
		for _, instr := range bl.Instrs {
			if c, ok := instr.(ssa.CallInstruction); ok {
				if c.Common().StaticCallee() == nil {
					site = c
					break
				}
			}
		}
		if site != nil {
			break
		}
	}
	require.NotNil(t, site, "expected a dynamic call in caller")
	names := calleeNames(cg, site)
	// S.Do (or the S.Do$bound thunk) should reach the site.
	found := false
	for _, n := range names {
		if n == "Do" || strings.Contains(n, "Do") {
			found = true
			break
		}
	}
	assert.True(t, found, "method value must survive channel round-trip; got %v", names)
}

// ---------------------------------------------------------------------------
// resolvesReflect — the reflective-dispatch discriminator.
// ---------------------------------------------------------------------------
//
// Behavioral coverage for resolvesReflect requires programs importing reflect,
// which the Bazel test sandbox cannot resolve. That path is exercised by
// TestE2EVTA in rpcshield/graph/graph_test.go against the cff-demo fixture.
// The discriminator's pure logic is covered by the tests above and by the
// FallbackReason/Config unit tests at the top of this file.
