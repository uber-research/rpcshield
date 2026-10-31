package graph

import (
	"regexp"

	"go.uber.org/zap"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// cgChecker checks if the callgraph is valid.
func cgChecker(cg *callgraph.Graph, doIn, doOut bool) {
	// Check if any Caller or Callee can be Nil
	if cg == nil || cg.Nodes == nil {
		panic("Callgraph is nil")
	}
	for f, node := range cg.Nodes {
		if f == nil {
			panic("f is nil")
		}

		if node == nil {
			panic("Node is nil for " + f.String())
		}
		if node.Func == nil {
			panic("Func is nil for " + f.String())
		}
		for _, edge := range node.Out {
			if edge == nil {
				if doOut {
					panic("Edge is nil")
				} else {
					continue
				}
			}
			if edge.Callee == nil {
				panic("Edge.Callee is nil")
			}
			if edge.Callee.Func == nil {
				panic("Edge.Callee.Func is nil")
			}
		}
		for _, edge := range node.In {
			if edge == nil {
				if doIn {
					panic("Edge is nil")
				} else {
					continue
				}
			}
			if edge.Caller == nil {
				panic("Edge.Caller is nil")
			}
			if edge.Caller.Func == nil {
				panic("Edge.Caller.Func is nil")
			}
		}
	}
}

func (g *builderImpl) debugNodeByName(cg *callgraph.Graph) {
	if g.debugFunRegexp == nil {
		return
	}

	for _, node := range cg.Nodes {
		if node.Func != nil && g.debugFunRegexp.MatchString(node.Func.String()) {
			g.logger.Debugf("debugNodeByName: %s", node.Func.String())
			g.logger.Debugf("Len Out: %d", len(node.Out))
			for i, edge := range node.Out {
				if edge == nil {
					g.logger.Debugf("  Out %d: nil", i)
				} else if edge.Callee == nil {
					g.logger.Debugf("  Out %d: edge.Callee = nil", i)
				} else if edge.Callee.Func == nil {
					g.logger.Debugf("  Out %d: edge.Callee.Func = nil", i)
				} else {
					g.logger.Debugf("  Out %d: %s", i, edge.Callee.Func.String())
				}
			}
			g.logger.Debugf("Len In: %d", len(node.In))
			for i, edge := range node.In {
				if edge == nil {
					g.logger.Debugf("  In %d: nil", i)
				} else if edge.Caller == nil {
					g.logger.Debugf("  In %d: edge.Caller = nil", i)
				} else if edge.Caller.Func == nil {
					g.logger.Debugf("  In %d: edge.Caller.Func = nil", i)
				} else {
					g.logger.Debugf("  In %d: %s", i, edge.Caller.Func.String())
				}
			}
		}
	}
}

// In one pass visit every In and Out edge of every node.
// Call shouldDrop() on each edge.
// If shouldDrop() returns true, make the edge entry nil.
// In the second pass, remove all nil entries from the In and Out slices of each node.
func (g *builderImpl) pruneGraph(cg *callgraph.Graph) error {
	// TODO: in a separate PR, we should refactor to move all needed data to the constructor.
	// first if g.blockedPkgs is empty, set it from blockListPackages()
	if len(g.blockedPkgs) == 0 {
		lst, err := g.getBlockListPackages(g.ssaProg.AllPackages())
		if err != nil {
			return err
		}
		g.blockedPkgs = lst
	}

	if len(g.blockedFuncsByFile) == 0 {
		lst, err := g.getFuncsBlockedByFile(g.ssaProg)
		if err != nil {
			return err
		}
		g.blockedFuncsByFile = lst
	}

	if g.neededTypes == nil {
		g.populateNeededTypes(g.ssaProg)
	}

	g.logGraphStats(cg, 10, zap.DebugLevel)
	g.logger.Debugf("PruneGraph: cleanupNodesInBlockedPkgsOrFiles")

	g.logger.Debugf("Before PruneGraph: cleanupNodesInBlockedPkgsOrFiles")
	g.debugNodeByName(cg)
	g.cleanupNodesInBlockedPkgsOrFiles(cg)
	g.logger.Debugf("After PruneGraph: cleanupNodesInBlockedPkgsOrFiles")
	g.debugNodeByName(cg)

	cgChecker(cg, true, true)
	g.logGraphStats(cg, 10, zap.DebugLevel)
	g.logger.Debugf("PruneGraph: pruneHeuristically")
	g.pruneHeuristically(cg)
	g.logger.Debugf("After PruneGraph: pruneHeuristically")
	g.debugNodeByName(cg)

	cgChecker(cg, true, true)
	g.logGraphStats(cg, 10, zap.DebugLevel)
	g.logger.Debugf("PruneGraph: doContextualGraphRefinement")
	g.doContextualGraphRefinement(cg)
	g.logger.Debugf("After PruneGraph: doContextualGraphRefinement")
	g.debugNodeByName(cg)
	g.logGraphStats(cg, 10, zap.DebugLevel)
	cgChecker(cg, true, true)
	return nil
}

// pruneHeuristically prunes the callgraph heuristically.
func (g *builderImpl) pruneHeuristically(cg *callgraph.Graph) {
	// First pass
	droppedOutEdges := edgeSet{}
	for _, node := range cg.Nodes {
		for i, edge := range node.Out {
			if g.shouldDropOutgoing(edge) {
				droppedOutEdges[edge] = struct{}{}
				node.Out[i] = nil
			}
		}
	}
	cgChecker(cg, true, false)

	g.logger.Debugf("1. Dropped %d outgoing edges", len(droppedOutEdges))

	droppedInEdges := edgeSet{}
	for _, node := range cg.Nodes {
		for i, edge := range node.In {
			if edge == nil {
				panic("Edge is nil")
			}
			if _, ok := droppedOutEdges[edge]; ok {
				node.In[i] = nil
				continue
			}
			if g.shouldDropIncoming(edge) {
				droppedInEdges[edge] = struct{}{}
				node.In[i] = nil
			}
		}
	}
	cgChecker(cg, false, false)

	g.logger.Debugf("2. Dropped %d outgoing edges", len(droppedInEdges))

	// Now remove the droppedInEdges from the Out of the caller
	for _, node := range cg.Nodes {
		for i, edge := range node.Out {
			// skip if the edge is nil, which it can be because we set it to nil in the first pass.
			if edge == nil {
				continue
			}
			if _, ok := droppedInEdges[edge]; ok {
				node.Out[i] = nil
			}
		}
	}

	droppedInEdges = nil // Help GC
	droppedOutEdges = nil

	// Second pass
	g.cleanupNilsInGraph(cg)
}

func (g *builderImpl) isNecessaryNode(n *callgraph.Node) bool {
	_, found := g.inboundMap[n.Func]
	if found {
		return true
	}
	_, found = g.outboundMap[n.Func]
	if found {
		return true
	}
	return false
}

// cleanupNilsInGraph removes all nil entries from the In and Out slices of each node.
func (g *builderImpl) cleanupNilsInGraph(cg *callgraph.Graph) {
	toDeleteNode := []*ssa.Function{}
	for f, node := range cg.Nodes {
		node.In = g.inplaceRemoveNilEdges(node.In)
		node.Out = g.inplaceRemoveNilEdges(node.Out)
		if len(node.In) == 0 && len(node.Out) == 0 {
			if g.isNecessaryNode(node) {
				g.logger.Debugf("%s has become orphaned", f.String())
			} else {
				toDeleteNode = append(toDeleteNode, f)
			}
		}
	}
	g.logger.Debugf("cleanupNilsInGraph: Deleting %d nodes", len(toDeleteNode))
	for _, f := range toDeleteNode {
		g.logger.Debugf("cleanupNilsInGraph: Deleting node %s", f.String())
		delete(cg.Nodes, f)
	}
}

// inplaceRemoveNilEdges removes all nil entries from the edges slice.
func (g *builderImpl) inplaceRemoveNilEdges(edges []*callgraph.Edge) []*callgraph.Edge {
	// Special case, if there is only one edge, return it
	if len(edges) == 1 {
		if edges[0] == nil {
			return nil
		}
		return edges
	}

	newEdges := edges[:0]
	for _, edge := range edges {
		if edge != nil {
			newEdges = append(newEdges, edge)
		}
	}
	return newEdges
}

// functionInBlockedPackage returns true if the function is in a blocked package.
func (g *builderImpl) functionInBlockedPackage(fn *ssa.Function) bool {
	// Exception: Wrappers don't have a package. They need to be kept.
	if fn != nil && g.getWrapperType(fn) != notSyntheticFunc {
		return false
	}

	// Empty function drop for sure
	if fn == nil || fn.Pkg == nil || fn.Pkg.Pkg == nil {
		return true
	}
	if _, ok := g.blockedPkgs[fn.Pkg]; ok {
		return true
	}
	return false
}

// cleanupNodesInBlockedPkgsOrFiles removes all nodes in blocked packages.
func (g *builderImpl) cleanupNodesInBlockedPkgsOrFiles(cg *callgraph.Graph) {
	// 	Why It's Correct and Safe:
	// Separate Slice Headers:

	// node.Out and newOut are two different slice headers (variables).
	// They point to the same underlying array but have different lengths during the operation.
	// No Overlapping of Read and Write:

	// The iteration reads from node.Out (original length and elements).
	// The append operation writes to newOut, starting from index 0 upwards.
	// Since newOut's length increases only when we append, and we start with a length of 0, the indices being written to (newOut) do not interfere with the indices being read from (node.Out).
	// Safe Iteration Despite Modifications:

	// The range loop in Go uses the length of the slice as it was at the start of the loop.
	// Modifying the slice (changing its length or contents beyond the current index) during iteration does not affect the loop's behavior.
	// Efficient Memory Usage:

	// By reusing the underlying array, we avoid additional memory allocations.
	// This is efficient, especially when dealing with large slices.
	// Final State Consistency:

	// After the operation, node.Out contains only the edges we want to keep.
	// No unwanted edges remain, and no needed edges are lost.

	toDelete := map[*ssa.Function]struct{}{}
	// Get all toDelete nodes by calling g.functionInBlockedPackage.
	for _, node := range cg.Nodes {
		if g.functionInBlockedPackage(node.Func) {
			toDelete[node.Func] = struct{}{}
		}
		if g.blockedFuncsByFile[node.Func] {
			toDelete[node.Func] = struct{}{}
		}
	}
	g.spliceDelegators(cg, toDelete)
	// Step 1: Iterate over all nodes to update their In and Out edges.
	for _, node := range cg.Nodes {
		// Update Out edges
		newOut := node.Out[:0]
		for _, edge := range node.Out {
			if _, ok := toDelete[edge.Callee.Func]; !ok {
				newOut = append(newOut, edge)
			}
		}
		node.Out = newOut

		// Update In edges
		newIn := node.In[:0]
		for _, edge := range node.In {
			if _, ok := toDelete[edge.Caller.Func]; !ok {
				newIn = append(newIn, edge)
			}
		}
		node.In = newIn
	}
	// Step 2: Delete the nodes
	for f := range toDelete {
		delete(cg.Nodes, f)
	}
}

// delegatorRegexps compiles Config.DelegatorPackagePatterns once. They identify generated
// delegator packages: packages blocked from appearing in paths like the rest of the block
// list, but unlike the rest pure delegators -- a delegator's whole body is a call to the
// implementation it wraps (generated decorators, interceptors). Deleting one outright
// therefore severs a real path rather than trimming noise off it.
//
// A type-based flavor never exposed this. Its global type pool gives the caller an edge to
// every implementation of the interface, including a direct one to the wrapped
// implementation, so the path survived alongside the delegator. A flow-based analysis
// resolves the call to the delegator alone -- which is what actually runs -- and the
// direct edge no longer exists to fall back on. Invalid patterns are logged and skipped.
func (g *builderImpl) delegatorRegexps() []*regexp.Regexp {
	g.delegatorPkgRegexOnce.Do(func() {
		for _, pattern := range g.config.DelegatorPackagePatterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				g.logger.Errorw("invalid delegator package pattern, skipping", "pattern", pattern, "error", err)
				continue
			}
			g.delegatorPkgRegex = append(g.delegatorPkgRegex, re)
		}
	})
	return g.delegatorPkgRegex
}

// isDelegatorPkg reports whether pkgPath matches any configured delegator package pattern.
func (g *builderImpl) isDelegatorPkg(pkgPath string) bool {
	for _, re := range g.delegatorRegexps() {
		if re.MatchString(pkgPath) {
			return true
		}
	}
	return false
}

// spliceDelegators reconnects the callers of a to-be-deleted delegator to what
// it delegates to, so that removing the frame shortens the path instead of
// deleting it. Chains of delegators are followed through to the first callee
// that survives.
func (g *builderImpl) spliceDelegators(cg *callgraph.Graph, toDelete map[*ssa.Function]struct{}) {
	if !g.config.RTAFlavor.isFlowBased() || len(g.delegatorRegexps()) == 0 {
		// A type-based flavor already has the direct caller-to-implementation
		// edge, so splicing would add nothing it needs — and it would drag in
		// every callee the decorator's own imprecise interface calls resolve
		// to, which is noise the block list is there to remove.
		return
	}
	pkgOf := func(f *ssa.Function) string {
		if f == nil || f.Pkg == nil || f.Pkg.Pkg == nil {
			return ""
		}
		return f.Pkg.Pkg.Path()
	}
	isDelegator := func(f *ssa.Function) bool {
		if _, ok := toDelete[f]; !ok {
			return false
		}
		return g.isDelegatorPkg(pkgOf(f))
	}

	// survivors walks past a run of delegators to the callees that remain.
	//
	// The walk is confined to the decorator package it started in, and only
	// callees named for the method being decorated are kept. Both constraints
	// are needed. A generated decorator method does not simply call its
	// wrapped implementation: it runs glue's interceptor chain, which dispatches
	// through a func value that the analysis resolves to the `newWrapper$N`
	// closure of *every* decorator package in the service. Staying in-package
	// discards the other services' closures; matching the name picks the right
	// one of this package's own, since there is one closure per method.
	var survivors func(n *callgraph.Node, pkg, name string, seen map[*ssa.Function]bool) []*callgraph.Node
	survivors = func(n *callgraph.Node, pkg, name string, seen map[*ssa.Function]bool) []*callgraph.Node {
		if seen[n.Func] {
			return nil
		}
		seen[n.Func] = true
		var out []*callgraph.Node
		for _, e := range n.Out {
			if e == nil || e.Callee == nil {
				continue
			}
			if isDelegator(e.Callee.Func) {
				if pkgOf(e.Callee.Func) == pkg {
					out = append(out, survivors(e.Callee, pkg, name, seen)...)
				}
				continue
			}
			if _, dropped := toDelete[e.Callee.Func]; dropped {
				continue
			}
			if e.Callee.Func.Name() != name {
				continue
			}
			out = append(out, e.Callee)
		}
		return out
	}

	// Collect first, add second: AddEdge mutates the Out slices being walked.
	type splice struct {
		caller *callgraph.Node
		site   ssa.CallInstruction
		callee *callgraph.Node
	}
	var splices []splice
	for _, node := range cg.Nodes {
		if isDelegator(node.Func) {
			continue
		}
		// Existing edges are recorded so the splice never duplicates one. A
		// caller can reach the same implementation both directly and through a
		// decorator, and adding a parallel edge would make path enumeration
		// report the same path twice.
		reached := map[*ssa.Function]bool{}
		for _, e := range node.Out {
			if e != nil && e.Callee != nil {
				reached[e.Callee.Func] = true
			}
		}
		for _, e := range node.Out {
			if e == nil || e.Callee == nil || !isDelegator(e.Callee.Func) {
				continue
			}
			// The delegator's callee is reached from this same call site, so
			// the site carries over: it is where control leaves the caller.
			d := e.Callee
			for _, s := range survivors(d, pkgOf(d.Func), d.Func.Name(), map[*ssa.Function]bool{}) {
				if reached[s.Func] {
					continue
				}
				reached[s.Func] = true
				splices = append(splices, splice{node, e.Site, s})
			}
		}
	}
	for _, s := range splices {
		callgraph.AddEdge(s.caller, s.site, s.callee)
	}
}

// shouldDropOutgoing returns true if the edge should be dropped due to heuristics.
func (g *builderImpl) shouldDropOutgoing(edge *callgraph.Edge) bool {
	if g.isDontPruneEdge(edge) {
		return false
	}
	if edge == nil {
		panic("Edge is nil")
	}
	if edge.Callee == nil {
		panic("Edge.Callee is nil")
	}
	if edge.Callee.Func == nil {
		panic("Edge.Callee.Func is nil")
	}

	if edge == nil {
		g.logger.Debugf("shouldDropOutgoing (nilEdge) DROPPING edge from %s to %s", edge.Caller.Func.String(), edge)
		return true
	}

	if edge.Callee == nil || edge.Caller.Func == nil {
		g.logger.Debugf("shouldDropOutgoing (nilEdge) DROPPING edge from %s to %s", edge.Caller.Func.String(), edge.Callee)
		return true
	}

	if edge.Site == nil {
		return true
	}

	// is defer call
	if g.isDeferCall(edge.Site) {
		g.logger.Debugf("shouldDropOutgoing (isDeferCall) DROPPING edge from %s to %s", edge.Caller.Func.String(), edge.Callee.Func.String())
		return true
	}

	// If the callsite is an impossible invoke drop it
	if edge.Site.Common().IsInvoke() {
		// Invokes an interface where names don't match or the method is not exported
		if g.isImpossibleInvoke(edge.Site, edge.Callee.Func) {
			g.logger.Debugf("shouldDropOutgoing (isImpossibleInvoke) DROPPING edge from %s to %s", edge.Caller.Func.String(), edge.Callee.Func.String())
			return true
		}
		// invokes a locker method
		if g.invokesLocker(edge.Site) {
			g.logger.Debugf("shouldDropOutgoing (invokesLocker) DROPPING edge from %s to %s", edge.Caller.Func.String(), edge.Callee.Func.String())
			return true
		}
		// invokes a context method
		if g.invokesContext(edge.Site) {
			g.logger.Debugf("shouldDropOutgoing (invokesContext) DROPPING edge from %s to %s", edge.Caller.Func.String(), edge.Callee.Func.String())
			return true
		}
	}

	// if calls an Error method
	if g.isErrorMethodCall(edge.Site) {
		g.logger.Debugf("shouldDropOutgoing (isErrorMethodCall) DROPPING edge from %s to %s", edge.Caller.Func.String(), edge.Callee.Func.String())
		return true
	}

	if g.isGoCall(edge.Site) {
		// Retain all Go calls to track missing paths.
		// 2 TODOs here:
		// 1. We need to prune some of these as well.
		// 2. Functions that take a lambda arg and launch it, which reach an outbound will still be missed.
		g.logger.Debugf("shouldDropOutgoing (isGoCall) KEEPING edge from %s to %s", edge.Caller.Func.String(), edge.Callee.Func.String())
		return false
	}

	// does it carry the context, request send, and error return signature?
	if !g.sendsCtxtAndReturnErr(edge.Site, edge.Callee.Func) {
		g.logger.Debugf("shouldDropOutgoing (sendsCtxtAndReturnErr) DROPPING edge from %s to %s", edge.Caller.Func.String(), edge.Callee.Func.String())
		return true
	}

	g.logger.Debugf("shouldDropOutgoing KEEPING edge from %s to %s", edge.Caller.Func.String(), edge.Callee.Func.String())

	return false
}

// shouldDropIncoming returns true if the edge should be dropped due to heuristics.
// Currently it only checks if the edge is nil.
func (g *builderImpl) shouldDropIncoming(edge *callgraph.Edge) bool {
	if g.isDontPruneEdge(edge) {
		return false
	}
	if edge == nil {
		panic("Edge is nil")
	}
	if edge.Caller == nil {
		panic("Edge.Caller is nil")
	}
	if edge.Callee.Func == nil {
		panic("Edge.Callee.Func is nil")
	}
	if edge == nil {
		g.logger.Debugf("shouldDropIncoming (nilEdge) DROPPING edge for incoming %s", edge.Callee.Func.String())
		return true
	}
	if edge.Caller == nil || edge.Caller.Func == nil {
		g.logger.Debugf("shouldDropIncoming (edge.Caller == nil) DROPPING edge for incoming %s", edge.Callee.Func.String())
		return true
	}
	g.logger.Debugf("shouldDropIncoming KEEPING edge from %s to %s", edge.Caller.Func.String(), edge.Callee.Func.String())
	// To add. Nothing for now.
	return false
}
