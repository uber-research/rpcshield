package graph

import (
	"cmp"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap/zapcore"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// isDebugEnabled checks if debug level logging is enabled.
func (b *builderImpl) isDebugEnabled() bool {
	return b.logger.Desugar().Core().Enabled(zapcore.DebugLevel)
}

const sampledInfowThreshold int64 = 200
const sampledInfowInterval int64 = 100

// sinkCanonicalNames builds a mapping from sink SSA function to canonical name.
func (b *builderImpl) sinkCanonicalNames() map[*ssa.Function]string {
	m := make(map[*ssa.Function]string)
	for _, sink := range b.outboundsSSA {
		if sink.originalOutboundPoint.CanonicalName != "" {
			m[sink.function] = sink.originalOutboundPoint.CanonicalName
		}
	}
	return m
}

// sourceCanonicalNames builds a mapping from source SSA function to canonical name.
func (b *builderImpl) sourceCanonicalNames() map[*ssa.Function]string {
	m := make(map[*ssa.Function]string)
	for _, src := range b.inboundsSSA {
		if src.originalInboundPoint.CanonicalName != "" {
			m[src.function] = src.originalInboundPoint.CanonicalName
		}
	}
	return m
}

// buildCallTree builds a non-recursive call tree from the call graph,
// starting from the source functions and ending at the sink functions.
// On any path from root to leaf, functions do not repeat, and all leaves are sinks.
func (b *builderImpl) buildCallTree(graph *callgraph.Graph) (map[*ssa.Function]*callgraph.Graph, error) {
	// Begin clean by forcing GC.
	runtime.GC()
	defer runtime.GC()

	b.logger.Infow("buildCallTree", "disable_parallel_calltree", b.config.DisableParallelCallTree)
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		b.logger.Infow("buildCallTree", "duration_seconds", duration.Seconds())
		b.metrics["buildCallTreeDurationSeconds"] += duration.Seconds()
	}()
	if len(b.inboundsSSA) == 0 || len(b.outboundsSSA) == 0 {
		return nil, errors.New("no source or sink functions provided")
	}

	if graph == nil {
		return nil, errors.New("call graph is nil")
	}

	// Step 1: Convert sinks to a set for efficient lookup.
	sinkSet := make(map[*ssa.Function][]ssa.CallInstruction)
	for _, sink := range b.outboundsSSA {
		sinkSet[sink.function] = append(sinkSet[sink.function], sink.ins)
	}

	sinkCanonicalNames := b.sinkCanonicalNames()
	sourceCanonicalNames := b.sourceCanonicalNames()

	// Optionally impose a canonical order on every node's outgoing edges so that
	// the depth-first exploration below does not depend on the order the packages
	// happened to be loaded in. Convergence pruning is order-sensitive: whichever
	// functions cross MaxFunctionVisits first are marked as convergence points and
	// have their subtrees cut, so two loaders that produce identical graphs but
	// different edge orderings otherwise disagree on the discovered path set (and
	// hence on fail-close/fail-open counts). Done once here, before any worker
	// starts, so the parallel exploration below only ever reads these slices.
	if b.config.CanonicalEdgeOrder {
		sortOutEdges(graph)
	}

	// Step 2: Initialize result channels
	b.logger.Debugf("Building call tree for %d source functions and %d sink functions", len(b.inboundsSSA), len(b.outboundsSSA))

	// Step 3: Build the call tree for each source function.
	// Channel to collect results
	type workerResult struct {
		fn          *ssa.Function
		graph       *callgraph.Graph
		metrics     map[string]float64
		err         error
		exploration SourceExplorationMetrics
	}
	resultChan := make(chan workerResult, len(b.inboundsSSA))

	// Worker function that processes a single source
	processSource := func(src inbound) {
		if b.isDebugEnabled() {
			b.logger.Debugf("Building call tree for source function %s", src.function.String())
		}

		// Create private metrics map for this worker (no sharing across workers)
		localMetrics := make(map[string]float64)

		visited := make(map[*ssa.Function]struct{})
		cfg := defaultExplorationConfig()
		cfg.PermutationThreshold = b.config.PermutationThreshold
		if b.config.MaxFunctionVisits > 0 {
			cfg.MaxFunctionVisits = b.config.MaxFunctionVisits
		}
		expState := newExplorationStateWithConfig(cfg)
		root, err := b.buildCallTreeNode(src.function, sinkSet, graph, visited, nil, localMetrics, expState)

		// Collect per-IB exploration data
		exploration := expState.Metrics(sinkCanonicalNames)

		if exploration.ConvergencePoints > 0 {
			// Log summary
			convergencePointFns := expState.GetConvergencePoints()
			pointNames := make([]string, 0, len(convergencePointFns))
			for _, cp := range convergencePointFns {
				pointNames = append(pointNames, cp.String())
			}
			b.logger.Infow("convergencePointsDetected",
				"source", src.function.String(),
				"count", exploration.ConvergencePoints,
				"skips", exploration.ConvergenceSkips,
				"points", pointNames)
		}

		// Always set metrics (0 if not hit)
		exploration.AddToMetrics(localMetrics)

		// Log diagnostic summary for this source
		for _, diag := range expState.GetDiagnostics() {
			// Only log sinks with significant path counts (skip trivial ones)
			if diag.TotalPaths > cfg.PermutationThreshold {
				b.logger.Infow("explorationDiagnostic",
					"source", src.function.String(),
					"sink", diag.SinkName,
					"totalPaths", diag.TotalPaths,
					"uniqueSets", diag.UniqueSets,
					"maxPerSet", diag.MaxPerSet,
					"avgPerSet", diag.AvgPerSet,
					"commutGroups", diag.CommutGroups,
					"coreSizes", diag.CoreSizes,
				)
			}
		}

		var resultGraph *callgraph.Graph
		if root != nil {
			resultGraph = &callgraph.Graph{Root: root}
		} else {
			if b.isDebugEnabled() {
				b.logger.Debugf("No call tree built for source function %s", src.function.String())
			}
			resultGraph = nil
		}

		// Send result (even if there was an error, send partial results and metrics)
		resultChan <- workerResult{
			fn:          src.function,
			graph:       resultGraph,
			metrics:     localMetrics,
			err:         err,
			exploration: exploration,
		}
	}

	if b.config.DisableParallelCallTree {
		// Sequential mode: process sources one by one
		b.logger.Info("Using sequential call tree computation")
		for _, source := range b.inboundsSSA {
			processSource(source)
		}
		close(resultChan)
	} else {
		// Parallel mode: process sources concurrently
		b.logger.Info("Using parallel call tree computation")
		var wg sync.WaitGroup
		for _, source := range b.inboundsSSA {
			wg.Add(1)
			go func(src inbound) {
				defer wg.Done()
				processSource(src)
			}(source)
		}
		// Wait for all goroutines to complete
		wg.Wait()
		close(resultChan)
	}

	// Merge all results, metrics, and collect errors
	callTree := map[*ssa.Function]*callgraph.Graph{}
	var errors []error

	// Build exploration metrics
	expCfg := defaultExplorationConfig()
	expCfg.PermutationThreshold = b.config.PermutationThreshold
	b.perSource = make(map[string]SourceExplorationMetrics)

	for result := range resultChan {
		// Add to call tree (even if there was an error)
		callTree[result.fn] = result.graph

		// Merge metrics (no mutex needed - all workers have finished, only main goroutine accesses b.metrics)
		for key, value := range result.metrics {
			b.metrics[key] += value
		}

		// Build per-source exploration metrics using canonical name if available, otherwise fully qualified function name
		sourceName := result.fn.String()
		if cn, ok := sourceCanonicalNames[result.fn]; ok {
			sourceName = cn
		}
		b.perSource[sourceName] = result.exploration

		// Collect error if any
		if result.err != nil {
			errors = append(errors, result.err)
		}
	}

	// Store config values in b.metrics for metrics reporting
	b.metrics["exploration_permutation_threshold"] = float64(expCfg.PermutationThreshold)
	b.metrics["exploration_min_core_size"] = float64(expCfg.MinCoreSize)
	b.metrics["exploration_max_function_visits"] = float64(expCfg.MaxFunctionVisits)

	// Return first error if any occurred (but we still have partial results)
	if len(errors) > 0 {
		return callTree, errors[0]
	}

	return callTree, nil
}

// checkPathFeasibility checks if a path is feasible.
// The caller and callsite in the first edge from in the source function.
// THe callee in the last edge contains a sink
// The result checks against every sink sinkCallSites and returns a filtered set of feasible callsite in the given path.
func (b *builderImpl) checkPathFeasibility(path []*callgraph.Edge, sinkCallSites []ssa.CallInstruction, metrics map[string]float64) ([]ssa.CallInstruction, error) {
	if b.config.DisableSCCPAnalysis {
		b.logger.Infow("checkPathFeasibility", "sccp_analysis_disabled", "returning all sink call sites")
		return sinkCallSites, nil
	}

	b.logger.Infow("checkPathFeasibility", "sccp_analysis_enabled", "running sccp analysis")
	if n := b.infowCount.Add(1); n <= sampledInfowThreshold || (n-sampledInfowThreshold)%sampledInfowInterval == 0 {
		sampled := n > sampledInfowThreshold
		b.logger.Infow("checkPathFeasibility", "path", fmt.Sprintf("%+v", path), "sampled", sampled, "totalCalls", n)
	}

	// SCCPAnalyzer is single-threaded, so no mutex is needed for the local metrics map.
	sccpAnalyzer := NewSCCPAnalyzer(b.ssaProg, path, b.logger, b.dontPruneEdges, metrics)
	sccpAnalyzer.Analyze()
	feasibleCallSites := []ssa.CallInstruction{}
	for _, sinkCallSite := range sinkCallSites {
		// Note/TODO: we are not checking a.getResolvedCallee(link) here because we don't know the resolved callee.
		// This should not be a major concern.
		if sccpAnalyzer.isBlockReachable(sinkCallSite.Block()) {
			b.logger.Infow("checkPathFeasibility", "sink_call_site_reachable", sinkCallSite.String())
			feasibleCallSites = append(feasibleCallSites, sinkCallSite)
		} else {
			b.logger.Infow("checkPathFeasibility", "sink_call_site_not_reachable", sinkCallSite.String())
		}
	}
	return feasibleCallSites, nil
}

// buildCallTreeNode recursively builds the call tree node for a given function.
func (b *builderImpl) buildCallTreeNode(
	fn *ssa.Function,
	sinkSet map[*ssa.Function][]ssa.CallInstruction,
	graph *callgraph.Graph,
	path map[*ssa.Function]struct{},
	curStack []*callgraph.Edge,
	metrics map[string]float64,
	expState *explorationState,
) (*callgraph.Node, error) {
	// Check if the function is already in the current path.
	if _, ok := path[fn]; ok {
		return nil, nil // Function repeats on this path; do not include it again.
	}

	// Convergence check: unlike cycle detection (same path), this limits cross-path fan-out.
	// If this function has been visited too many times across different paths,
	// it's a convergence point and we skip re-exploring its subtree.
	if expState.ShouldSkipConvergence(fn) {
		return nil, nil
	}

	// Get the corresponding node from the original graph.
	origNode, exists := graph.Nodes[fn]
	if !exists {
		// Function not in the original graph; return nil.
		if b.isDebugEnabled() {
			b.logger.Debugw("buildCallTreeNode", "fn_not_in_graph", fn.String())
		}
		return nil, fmt.Errorf("%s function not found in the call graph", fn.String())
	}

	// Create a new node for the call tree.
	newNode := &callgraph.Node{
		Func: fn,
		ID:   0, // ID can be assigned later if needed.
		In:   []*callgraph.Edge{},
		Out:  []*callgraph.Edge{},
	}

	// Mark the function as visited in the current path.
	path[fn] = struct{}{}
	// Make room for the next edge.
	curStack = append(curStack, nil)
	defer func() {
		// Pop the current edge from the stack.
		curStack = curStack[:len(curStack)-1]
	}()
	defer delete(path, fn) // Clean up for other paths after returning.

	// Track if this function contains a sink call site(ob)
	hasSink := false
	if callsites, ok := sinkSet[fn]; ok {
		// Track for permutation detection.
		expState.trackSinkPath(fn, path, curStack)

		// Add the last edge to the current stack.
		curStack[len(curStack)-1] = &callgraph.Edge{
			Caller: newNode,
			Site:   nil, // instead of giving the sink call site, we give nil and pass the sink call sites to checkPathFeasibility
			Callee: nil, // No callee for a sink.
		}

		feasibleCallSites, err := b.checkPathFeasibility(curStack, callsites, metrics)
		// No mutex needed - each shard has its own independent metrics map
		metrics[_constpropCandidatePaths] += float64(len(callsites))
		metrics[_constpropFeasiblePaths] += float64(len(feasibleCallSites))
		metrics[_constpropInfeasiblePaths] += float64((len(callsites) - len(feasibleCallSites)))

		if err != nil {
			b.logger.Infow("buildCallTreeNode", "sink_function", fn.String(), "callsites after", len(callsites), "err", err)
		}
		if len(feasibleCallSites) > 0 {
			// Mark the function has a sink and has feasible callsites.
			hasSink = true

			// Create outgoing edges for each instruction in the sink
			for _, ins := range feasibleCallSites {
				newEdge := &callgraph.Edge{
					Caller: newNode,
					Site:   ins,
					Callee: nil, // No callee for a sink.
				}
				newNode.Out = append(newNode.Out, newEdge)
			}
		}
	}

	// Recursively build children for each outgoing edge.
	hasChildren := false
	b.logger.Debugf("num outgoing edges: %d", len(origNode.Out))
	for _, edge := range origNode.Out {
		calleeFn := edge.Callee.Func
		if slices.Contains(sinkSet[fn], edge.Site) {
			continue // skip the callee that is a sink call site.
		}

		// Permutation pruning: if a commutative group has been detected and
		// visiting this callee would violate its canonical ordering, skip.
		if len(expState.commutativeGroups) > 0 {
			if expState.shouldSkipPermutation(path, calleeFn) {
				continue
			}
		}

		// Update the current edge in the stack.
		// It is critical to use the edge from the original graph, not the one created in the call tree.
		// This is because we will use dontPruneEdges to check if the edge should be pruned.
		curStack[len(curStack)-1] = edge
		childNode, err := b.buildCallTreeNode(calleeFn, sinkSet, graph, path, curStack, metrics, expState)
		if err != nil {
			return nil, err
		}
		if childNode != nil {
			hasChildren = true
			// Create a new edge in the call tree.
			newEdge := &callgraph.Edge{
				Caller: newNode,
				Site:   edge.Site,
				Callee: childNode,
			}
			newNode.Out = append(newNode.Out, newEdge)
			childNode.In = append(childNode.In, newEdge)
			if b.isDebugEnabled() {
				b.logger.Debugw("buildCallTreeNode", "child_node", fn.String(), "callee", calleeFn.String())
			}
		} else {
			if b.isDebugEnabled() {
				b.logger.Debugw("buildCallTreeNode", "child_node_nil", fn.String(), "callee", calleeFn.String())
			}
		}
	}

	// If no children were added and the function is not a sink, discard this node.
	if !hasChildren && !hasSink {
		if b.isDebugEnabled() {
			b.logger.Debugw("buildCallTreeNode", "no_children", fn.String())
		}
		return nil, nil
	}
	return newNode, nil
}

// CollectPaths collects all paths from the root to the leaves in the call tree.
func (b *builderImpl) collectPaths(sources map[*ssa.Function]*callgraph.Graph) ([][]*callgraph.Edge, error) {
	var paths [][]*callgraph.Edge
	for _, g := range sources {
		if g != nil {
			path := []*callgraph.Edge{}
			b.traverse(g.Root, path, &paths)
		}
	}
	return paths, nil
}

// traverse recursively explores all paths from the current node to the leaves.
func (b *builderImpl) traverse(node *callgraph.Node, path []*callgraph.Edge, paths *[][]*callgraph.Edge) {
	if node == nil {
		return
	}

	// If the node has no outgoing edges, it's a leaf node.
	if len(node.Out) == 0 {
		// Record the current path (no need to add any edge since there are no outgoing edges).
		pathCopy := make([]*callgraph.Edge, len(path))
		copy(pathCopy, path)
		*paths = append(*paths, pathCopy)
		return
	}

	// Iterate over outgoing edges.
	for _, edge := range node.Out {
		// Append the edge to the path.
		newPath := append(path, edge)

		if edge.Callee == nil {
			// Edge leads to a leaf (Callee is nil).
			// Record the current path including this edge.
			pathCopy := make([]*callgraph.Edge, len(newPath))
			copy(pathCopy, newPath)
			*paths = append(*paths, pathCopy)
		} else {
			// Continue traversal with the callee node.
			b.traverse(edge.Callee, newPath, paths)
		}
	}
}

// sortOutEdges imposes a deterministic total order on every node's outgoing
// edges, in place. The order is (callee name, call-site position, callee node
// ID): a caller can hold several edges to the same callee from different call
// sites, so the callee name alone is not a total order, and the node ID breaks
// any remaining tie so the result never depends on the incoming slice order.
//
// Only the ordering of each Out slice changes; no edge is added or removed, so
// node and edge counts are unaffected.
func sortOutEdges(graph *callgraph.Graph) {
	for _, node := range graph.Nodes {
		if node == nil || len(node.Out) < 2 {
			continue
		}
		slices.SortFunc(node.Out, func(a, b *callgraph.Edge) int {
			if c := strings.Compare(calleeName(a), calleeName(b)); c != 0 {
				return c
			}
			if c := cmp.Compare(sitePos(a), sitePos(b)); c != 0 {
				return c
			}
			return cmp.Compare(calleeID(a), calleeID(b))
		})
	}
}

// calleeName returns the callee's fully qualified name, or "" for a leaf edge.
func calleeName(e *callgraph.Edge) string {
	if e.Callee == nil || e.Callee.Func == nil {
		return ""
	}
	return e.Callee.Func.String()
}

// sitePos returns the edge's call-site offset, or -1 when it has no site
// (synthetic edges), keeping those ahead of any real call site.
func sitePos(e *callgraph.Edge) int {
	if e.Site == nil {
		return -1
	}
	return int(e.Site.Pos())
}

// calleeID returns the callee node's ID, or -1 for a leaf edge.
func calleeID(e *callgraph.Edge) int {
	if e.Callee == nil {
		return -1
	}
	return e.Callee.ID
}
