package graph

import (
	"errors"
	"go/token"
	"go/types"

	"go.uber.org/zap"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// Overview:
// -----------------
// This file enriches the call graph to correctly model execution dependencies
// introduced by errgroup-like concurrency constructs. It ensures that goroutines
// started via `.Go`/`.TryGo` are represented as callees of the corresponding `.Wait`
// callsite(s).
//
// # Goal
//
// Add edges from each `.Wait` call to every work function registered via `.Go`/`.TryGo`,
// improving static analysis ordering for code that uses `errgroup`-style patterns.
// The transformation only ADDS edges; it does not remove any existing Go/TryGo/Wait
// edges in the original call graph. This can change once we introduce other generic
// mechanisms for modeling concurrency.
//
// # Supported Features
//
// - Auto-discovers "errgroup-like" types across the SSA program by method-set shape:
//   exported named types that expose exported methods including `Go(...)` and
//   `Wait() error` (optionally `TryGo`, `SetLimit`/`Limit`, `FireAndForget`, `AnyTimedOut`).
//   Works for both concrete and interface types.
// - Tracks both method invocations and static calls to `Go`/`TryGo`/`Wait`.
// - Associates each `.Go`/`.TryGo` call with its statically-known work function
//   (plain function or closure; interfaces are unwrapped when resolvable).
// - Supports multiple `.Wait` callsites for the same group value. Each `.Wait`
//   is connected to all discovered work functions for that value.
// - Supports multiple group values within a function.
// - Skips modifying packages that implement the errgroup-like types themselves
//   (to avoid instrumenting provider internals).
//
// # Unsupported / Filtered Cases
//
// - Group values that "escape" or are used outside of allowed method calls
//   (e.g., stored in maps/structs, sent on channels, returned). Only values whose
//   uses are calls to allowed methods are enriched.
// - Dynamic work functions where the target cannot be resolved statically
//   (e.g., runtime-determined function values). These are ignored.
// - Alternate wait signatures (e.g., `WaitContext`) are not matched; only `Wait() error`.
//
// # Approach
//
// 1. Discover errgroup-like types by scanning all packages and selecting exported
//    named types whose method-sets match the criteria above.
// 2. For each function outside those provider packages, locate local variables of
//    such types whose uses are restricted to allowed method calls. Record the
//    `.Go`/`.TryGo` callsites and their resolved work functions, and the `.Wait`
//    callsites for the same value.
// 3. For every `.Wait` callsite, add call graph edges to each resolved work function
//    and mark them non-prunable. The original edges remain intact.
//
// # Examples
//
// 1) Basic
//
//    func processTasks() error {
//        var eg errgroup.Group
//        eg.Go(func() error { return task1() })
//        eg.TryGo(func() error { return task2() })
//        return eg.Wait()
//    }
//
// Original:
//    processTasks
//      ├──> eg.Go(task1)
//      ├──> eg.TryGo(task2)
//      └──> eg.Wait()
//
// Enriched:
//    processTasks
//      ├──> eg.Go(task1)
//      ├──> eg.TryGo(task2)
//      └──> eg.Wait()
//            ├──> task1
//            └──> task2
//
// 2) Multiple Waits on the same group value
//
//    func multiWait() error {
//        var eg errgroup.Group
//        eg.Go(func() error { return a() })
//        eg.Go(func() error { return b() })
//        if err := eg.Wait(); err != nil { return err }
//        // later
//        return eg.Wait()
//    }
//
// Enriched:
//    multiWait
//      ├──> eg.Go(a)
//      ├──> eg.Go(b)
//      └──> eg.Wait() (1st)
//      │      ├──> a
//      │      └──> b
//      └──> eg.Wait() (2nd)
//             ├──> a
//             └──> b
//

// errgroupUsage tracks the callsites of `.Go`, `.TryGo`, and `.Wait` methods
// for a single instance of an "errgroup.Group" or similar type.
type errgroupUsage struct {
	// The SSA value of the errgroup instance being analyzed.
	egValue ssa.Value
	// A map of callsites to the functions that were passed to .Go/.TryGo.
	goCalls map[ssa.CallInstruction]map[*ssa.Function]struct{}
	// A map of callsites that invoke .Wait.
	waitCalls map[ssa.CallInstruction]map[*ssa.Function]struct{}
}

// edgeUpdates tracks the callsites of `.Wait` methods that need to be added to the call graph.
type edgeUpdates struct {
	// A map of functions that need to be added to the call graph. (targets of the edge).
	waitCallsToAdd map[*ssa.Function]struct{}
	// The callsite of the .Wait method that is the source of the edges.
	waitCall ssa.CallInstruction
}

// enrichCallGraphWithErrgroup updates the call graph such that the
// lambdas passed to .Go/.TryGo are connected to the .Wait call.
func (b *builderImpl) enrichCallGraphWithErrgroup(cg *callgraph.Graph) error {
	// First discoverAllErrgroupTypes
	errGroupTypes, errGroupPkgs := b.discoverAllErrgroupTypes(b.ssaProg)
	// Add to metrics
	b.metrics["num_errgroup_types"] += float64(len(errGroupTypes))
	b.metrics["num_errgroup_pkgs"] += float64(len(errGroupPkgs))

	for fn := range cg.Nodes {
		if fn.Pkg != nil {
			if _, ok := errGroupPkgs[fn.Pkg.Pkg.Path()]; ok {
				continue // Skip packages that implement errgroup types.
			}

			// Get all errgroup variables in the function that are of an allowed errgroup type and used in a safe way.
			egInfo, numErrgroupValues := b.getSafeErrGroupUsageInfo(fn, errGroupTypes, errGroupPkgs)
			b.logger.Debugf("enrichCallGraphWithErrgroup analyzing function %s", fn.String())
			b.metrics["num_errgroup_variables_rewired"] += float64(numErrgroupValues)
			if len(egInfo) > 0 {
				b.metrics["num_functions_with_errgroup_variables"] += float64(1)
			}
			for _, egInfo := range egInfo {
				// Update the call graph to redirect .Wait calls to the lambdas passed to .Go/.TryGo.
				b.updateEdgesFromWait(fn, cg, egInfo)
				// Update metrics.
				b.metrics["num_errgroup_waits_rewired"] += float64(len(egInfo.waitCalls))
				b.metrics["num_errgroup_go_calls_rewired"] += float64(len(egInfo.goCalls))
			}
		}
	}
	// Check the call graph for correctness.
	cgChecker(cg, true, true)
	return nil
}

// updateEdgesFromWait redirects .Wait calls to the lambdas passed to .Go/.TryGo.
func (b *builderImpl) updateEdgesFromWait(fn *ssa.Function, cg *callgraph.Graph, egInfo *errgroupUsage) {
	// Add new edges for discovered lambda call sites to the .Wait call
	updateMap := map[ssa.CallInstruction]map[*ssa.Function]struct{}{}

	for update := range egInfo.waitCalls {
		updateMap[update] = map[*ssa.Function]struct{}{}
		b.logger.Debugf("addCGEdges:Adding %d edges for .Wait call at %s", len(updateMap[update]), positionString(update, fn.Prog.Fset))
		for _, callees := range egInfo.goCalls {
			for callee := range callees {
				updateMap[update][callee] = struct{}{}
			}
		}
	}
	_, newEdges := b.addCGEdges(updateMap, cg.Nodes[fn], cg, true /* registerAsAsync */)
	b.addEdgesToNoPruneSet(newEdges)

	if node, ok := cg.Nodes[fn]; ok {
		for _, e := range node.Out {
			b.logger.Debugf("addCGEdges:Outgoing edge from %s: %s at %s", fn.String(), e.Callee.Func.String(), e.Site.String())
		}
	}
}

// getSafeErrGroupUsageInfo checks if a function contains a variable referencing an instance of an allowed errgroup type.
// It returns a map of each errgroup-type value, its usage info and an integer of total errgroup variables found.
// Not all errgroup-type variables are safe to use.
func (b *builderImpl) getSafeErrGroupUsageInfo(
	fn *ssa.Function,
	errGroupTypes map[*types.Named]struct{},
	errGroupPkgs map[string]struct{}) (map[ssa.Value]*errgroupUsage, int) {
	egVals := make(map[ssa.Value]*errgroupUsage)
	numErrgroupValues := 0
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			// Skip debug references.
			if _, ok := instr.(*ssa.DebugRef); ok {
				continue
			}
			if value, ok := instr.(ssa.Value); ok {
				egInfo, isErrGrp, err := b.isFeasibleErrgroupValue(fn, value, errGroupTypes, errGroupPkgs)
				if isErrGrp {
					numErrgroupValues++
				}
				if err == nil && len(egInfo.goCalls) > 0 {
					egVals[value] = egInfo
				}
			}
		}
	}
	return egVals, numErrgroupValues
}

// getResolvedFunction determines if a value represents a statically known function.
// It does a level of indirection by following interfaces wrapped around the function.
func getResolvedFunction(val ssa.Value) *ssa.Function {
	switch fn := val.(type) {
	case *ssa.Function:
		return fn
	case *ssa.MakeClosure:
		if fnRef, ok := fn.Fn.(*ssa.Function); ok {
			return fnRef
		}
	case *ssa.MakeInterface:
		return getResolvedFunction(fn.X)
	}
	return nil
}

// positionString helper to format file:line for instructions and values
func positionString(x interface{ Pos() token.Pos }, fset *token.FileSet) string {
	if x == nil {
		return "<no pos>"
	}
	return fset.Position(x.Pos()).String()
}

// isFeasibleErrgroupValue check to make sure the value is a valid errgroup.
// 1. The value is of an allowed errgroup (or pointer to an allowed errgroup) type.
// 2. The value is not defined in one of the packages in errGroupPkgs itself.
// 3. There is no other use of the value in the function except a call to allowed methods.
// 4. There is at least one .Go/.TryGo call invocation on the value.
// 5. There is at least one .Wait call invocation on the value.
// 6. The first argument of the .Go/.TryGo call is a function literal or a closure.
func (b *builderImpl) isFeasibleErrgroupValue(
	fn *ssa.Function,
	value ssa.Value,
	errGroupTypes map[*types.Named]struct{},
	errGroupPkgs map[string]struct{}) (*errgroupUsage, bool, error) {
	if value == nil {
		return nil, false, errors.New("value is nil")
	}

	typ := value.Type()
	b.logger.Debugw("isFeasibleErrgroupValue entry Type", zap.Stringer("type", typ))
	// If it is a pointer, get the element type.
	if ptr, ok := typ.(*types.Pointer); ok {
		typ = ptr.Elem()
	}
	// If it is a named type, get the underlying type.
	named, ok := typ.(*types.Named)
	if !ok {
		return nil, false, errors.New("value is not a named type")
	}

	// Check if the value is of an allowed errgroup type.
	if _, ok := errGroupTypes[named]; !ok {
		return nil, false, errors.New("value is not an allowed errgroup type")
	}
	b.logger.Debugw("isFeasibleErrgroupValue_named", zap.Stringer("type", named))

	var pkgPath string
	if value.Parent().Pkg != nil {
		pkgPath = value.Parent().Pkg.Pkg.Path()
	}
	b.logger.Debugw("isFeasibleErrgroupValue_pkgPath", "pkgPath", pkgPath)
	// Check if the value is defined in one of the packages in errGroupPkgs.
	if _, ok := errGroupPkgs[pkgPath]; ok {
		b.logger.Debugf("Errgroup at %s is defined in one of the packages in errGroupPkgs", positionString(value, fn.Prog.Fset))
		return nil, false, errors.New("value is defined in one of the packages in errGroupPkgs")
	}
	egInfo, err := b.isSafeErrGroupUse(fn, value)
	return egInfo, true, err
}

// isSafeErrGroupUse checks if the value is used in a safe way.
// Only allowed uses are method calls to known functions
func (b *builderImpl) isSafeErrGroupUse(
	fn *ssa.Function,
	value ssa.Value) (*errgroupUsage, error) {
	egInfo := &errgroupUsage{
		egValue:   value,
		goCalls:   make(map[ssa.CallInstruction]map[*ssa.Function]struct{}),
		waitCalls: make(map[ssa.CallInstruction]map[*ssa.Function]struct{}),
	}
	// Ensure there is no other use of the value in the function except calls to allowed methods.
	for _, ref := range *value.Referrers() {
		// Skip dereferences.
		if _, ok := ref.(*ssa.DebugRef); ok {
			continue
		}
		// Can only be used in a call instruction..
		call, ok := ref.(ssa.CallInstruction)
		if !ok {
			return nil, errors.New("value is not a call")
		}
		// By filtering the type, we already know that the call is to an allowed method.
		commonCall := call.Common()
		// In method invocation?
		if commonCall.IsInvoke() && commonCall.Method != nil {
			// Is the call to .Go/.TryGo?
			if commonCall.Method.Name() == "Go" || commonCall.Method.Name() == "TryGo" {
				if len(commonCall.Args) < 1 {
					return nil, errors.New("value is not a call")
				}
				// Check that the first argument is a function literal or a closure.
				funcRef := getResolvedFunction(commonCall.Args[0])
				if funcRef == nil {
					return nil, errors.New("could not resolve function")
				}
				// All ok.
				egInfo.goCalls[call] = make(map[*ssa.Function]struct{})
				egInfo.goCalls[call][funcRef] = struct{}{}
			} else if commonCall.Method.Name() == "Wait" {
				egInfo.waitCalls[call] = nil // We don't need to track the .Wait call.
			}
		}
		// Static call.
		if callee := commonCall.StaticCallee(); callee != nil {
			if callee.Name() == "Go" || callee.Name() == "TryGo" {
				// The first arg is the receiver. Second is the function.
				if len(commonCall.Args) < 2 {
					return nil, errors.New("value is not a call")
				}
				funcRef := getResolvedFunction(commonCall.Args[1])
				if funcRef == nil {
					return nil, errors.New("could not resolve function")
				}
				egInfo.goCalls[call] = make(map[*ssa.Function]struct{})
				egInfo.goCalls[call][funcRef] = struct{}{}
			} else if callee.Name() == "Wait" {
				egInfo.waitCalls[call] = nil // We don't need to track the .Wait call.
			}
		}
	}
	// Check if there is at least one .Go/.TryGo call invocation on the value.
	if len(egInfo.goCalls) == 0 {
		return nil, errors.New("no .Go/.TryGo calls found")
	}
	// Check if there is at least one .Wait call invocation on the value.
	if len(egInfo.waitCalls) == 0 {
		return nil, errors.New("no .Wait calls found")
	}
	b.logger.Debugw("isFeasibleErrgroupValue_returning", "egInfo", egInfo)
	return egInfo, nil
}

// discoverAllErrgroupTypes discovers all errgroup types in the program.
// Walks all packages in the program and collects all types that match the errgroup type.
// The allowed types (either interface or concrete type) have these characteristics:
// - Exported named type
// - Exported methods limited to Go, Wait, (optional) TryGo, Limit/SetLimit (optional)
// - Must include both Go and Wait
// - Go must take at least one argument
// - Wait must be of the form: Wait() error
func (b *builderImpl) discoverAllErrgroupTypes(prog *ssa.Program) (map[*types.Named]struct{}, map[string]struct{}) {
	b.logger.Debugw("discoverAllErrgroupTypes")
	if prog == nil {
		return nil, nil
	}

	errType := types.Universe.Lookup("error").Type().Underlying()
	errTypeInterface, ok := errType.(*types.Interface)
	if !ok {
		b.logger.Debugf("Error type is not an interface! %s", errType.String())
		return nil, nil
	}
	// Allowed exported method names
	allowed := map[string]struct{}{
		"Go":            struct{}{},
		"Wait":          struct{}{}, // Todo: add WaitContext from example.internal/rt/service-0026/util
		"TryGo":         struct{}{},
		"SetLimit":      struct{}{},
		"Limit":         struct{}{},
		"FireAndForget": struct{}{},
		"AnyTimedOut":   struct{}{}, // hand-rolled WorkGroup variants expose a timeout flag
	}
	errGroupTypes := make(map[*types.Named]struct{})
	errGroupPkgs := make(map[string]struct{})

	exportedNamedType := func(obj types.Object) *types.Named {
		tname, ok := obj.(*types.TypeName)
		if !ok || tname == nil {
			return nil
		}
		if !tname.Exported() {
			return nil // not exported
		}
		named, ok := tname.Type().(*types.Named)
		if !ok || named == nil {
			return nil
		}
		return named
	}

	// Walk all packages and force evaluation to ensure the code is exercised for side-effect free discovery.
	for _, spkg := range prog.AllPackages() {
		if spkg == nil || spkg.Pkg == nil || spkg.Pkg.Scope() == nil {
			continue
		}
		b.logger.Debugw("discoverAllErrgroupTypes_lookingAt", "package", spkg.Pkg.Path())
		scope := spkg.Pkg.Scope()
		for _, obj := range scope.Names() {
			b.logger.Debugw("discoverAllErrgroupTypes_lookingAt", "object", obj)
			obj := scope.Lookup(obj)
			named := exportedNamedType(obj)
			if named == nil {
				continue
			}
			if isErrgroupLikeNamedType(named, allowed, errTypeInterface) {
				errGroupTypes[named] = struct{}{}
				errGroupPkgs[spkg.Pkg.Path()] = struct{}{}
				b.logger.Infow("discoverAllErrgroupTypes_found", "type", named.String())
			} else {
				b.logger.Debugw("discoverAllErrgroupTypes_not", "type", named.String())
			}
		}
	}
	return errGroupTypes, errGroupPkgs
}

// Helper to verify Wait() error signature
func isValidWaitMethod(sig *types.Signature, errType *types.Interface) bool {
	if sig == nil {
		return false
	}
	if sig.Params().Len() != 0 {
		return false
	}
	if sig.Results().Len() != 1 {
		return false
	}
	return types.Implements(sig.Results().At(0).Type(), errType)
}

// isValidGoMethod checks if the method is a valid Go method.
// It must take at least one argument and return at least one result.
func isValidGoMethod(sig *types.Signature) bool {
	if sig == nil {
		return false
	}
	if sig.Params().Len() < 1 {
		return false
	}
	return true
}

// Checks if a named type (interface or concrete) satisfies the errgroup-like API
func isErrgroupLikeNamedType(
	named *types.Named,
	allowed map[string]struct{},
	errType *types.Interface) bool {
	if named == nil || named.Obj() == nil || !named.Obj().Exported() {
		return false
	}

	// Interface type: inspect explicitly declared methods
	if iface, ok := named.Underlying().(*types.Interface); ok {
		hasGo := false
		hasWait := false
		for m := range iface.Methods() {
			if !isAllowedMethod(m, allowed, errType, &hasGo, &hasWait) {
				return false
			}
		}
		return hasGo && hasWait
	}

	// Concrete type: inspect method set on *T and only consider directly-declared exported methods
	// include both direct and pointer methods.
	namedPtr := types.NewPointer(named)
	receiverTypes := []types.Type{named, namedPtr}
	hasGo := false
	hasWait := false
	for _, t := range receiverTypes {
		mset := types.NewMethodSet(t)
		for sel := range mset.Methods() {
			fn, _ := sel.Obj().(*types.Func)
			if len(sel.Index()) != 1 {
				continue
			}
			if !isAllowedMethod(fn, allowed, errType, &hasGo, &hasWait) {
				return false
			}
		}
	}
	return hasGo && hasWait
}

// isAllowedMethod checks if the method is allowed.
// It must be in the allowed map.
// It sets the hasGo and hasWait flags if the method is Go or Wait.
func isAllowedMethod(
	fn *types.Func,
	allowed map[string]struct{},
	errType *types.Interface,
	hasGo *bool,
	hasWait *bool) bool {
	if fn == nil || !fn.Exported() {
		return true
	}
	name := fn.Name()
	if _, ok := allowed[name]; !ok {
		return false
	}

	switch name {
	case "Go", "TryGo":
		if sig, ok := fn.Type().(*types.Signature); ok {
			if !isValidGoMethod(sig) {
				return false
			}
			*hasGo = true
		}
	case "Wait":
		if sig, ok := fn.Type().(*types.Signature); ok {
			if !isValidWaitMethod(sig, errType) {
				return false
			}
			*hasWait = true
		}
	}
	return true
}
