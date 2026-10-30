package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"go/types"
	"maps"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/uber-research/rpcshield/go/common/edgeinfo"
	"github.com/uber-research/rpcshield/go/common/instrtoast"
	"github.com/uber-research/rpcshield/go/common/mapper"
	"github.com/uber-research/rpcshield/go/common/syntheticfunc"
	"github.com/uber-research/rpcshield/go/common/utils"
	fty "github.com/uber-research/rpcshield/go/finder/types"
	"go.uber.org/zap"
	"golang.org/x/tools/go/ast/astutil"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

const _maxCGNodesToLog = 10
const _maxClosestInstructions = 3
const _debugFunRegexpEnv = "DEBUG_FUNC_REGEXP"
const _dumpCallPathsMaxEdges = 1000

// Predefined metric keys.
const (
	_inboundNeeded             = "inboundNeeded"
	_outboundNeeded            = "outboundNeeded"
	_inboundFound              = "inboundFound"
	_outboundFound             = "outboundFound"
	_inboundNodesSynthesized   = "inboundNodesSynthesized"
	_numIns2ExprQueries        = "num_ins2expr_queries"
	_numIns2ExprFailures       = "num_ins2expr_failures"
	_numIns2ExprSyntheticFuncs = "num_ins2expr_query_synthetic_funcs"
	_constpropCandidatePaths   = "constprop_candidate_paths"
	_constpropFeasiblePaths    = "constprop_feasible_paths"
	_constpropInfeasiblePaths  = "constprop_infeasible_paths"
	_tupleAsBinopType          = "tuple_as_binop_type"
	_tupleAsBinopArgX          = "tuple_as_binop_arg_x"
	_tupleAsBinopArgY          = "tuple_as_binop_arg_y"
	_extractIndexOutOfBounds   = "extract_index_out_of_bounds"
	_typeAssertionInfeasible   = "type_assertion_infeasible"
	_binopXTop                 = "binop_x_top"
	_binopYTop                 = "binop_y_top"
	_nilOperand                = "nil_operand"
	_topAsIfCond               = "top_as_if_cond"
	_boolAsIfCond              = "bool_as_if_cond"
	_bottomAsIfCond            = "bottom_as_if_cond"
)

// CallPath represents a path (caller-callee edges) from an inbound to an outbound point.
type CallPath struct {
	Inbound  fty.InboundPoint
	Outbound fty.OutboundPoint
	Edges    []*edgeinfo.EdgeInfo
	IsAsync  bool
}

// Hash returns a hash of the call path.
func (cp *CallPath) Hash() string {
	in := cp.Inbound.CanonicalName
	out := cp.Outbound.CanonicalName
	edgesString := ""
	for _, edge := range cp.Edges {
		edgesString += edge.Edge.Site.String()
	}
	data := []byte(in + out + edgesString)
	hashValue := sha256.Sum256(data)
	return hex.EncodeToString(hashValue[:])
}

// SourceExplorationMetrics holds per-source (inbound) exploration diagnostics.
type SourceExplorationMetrics struct {
	// ConvergencePoints is the number of functions identified as convergence points for this source.
	ConvergencePoints int `json:"convergence_points"`
	// ConvergenceSkips is the number of times exploration was skipped due to convergence for this source.
	ConvergenceSkips int64 `json:"convergence_skips"`
	// CommutativeGroups is the number of commutative groups detected for this source.
	CommutativeGroups int `json:"commutative_groups"`
	// PermutationHitPerSink maps sink function name to whether the permutation threshold was hit.
	PermutationHitPerSink map[string]bool `json:"permutation_hit_per_sink"`
}

// AddToMetrics adds this struct's scalar fields into the provided metrics map.
func (m SourceExplorationMetrics) AddToMetrics(dst map[string]float64) {
	dst["convergencePoints"] += float64(m.ConvergencePoints)
	dst["convergenceSkips"] += float64(m.ConvergenceSkips)
	dst["commutativeGroups"] += float64(m.CommutativeGroups)
}

// BuildResult holds the combined output of Build() or BuildCGOnly().
type BuildResult struct {
	// Metrics is the key-value map of graph-specific metrics (includes exploration totals and config).
	Metrics map[string]float64 `json:"metrics"`
	// PerSource holds per-source (IB) exploration diagnostics, keyed by canonical name or function name.
	PerSource map[string]SourceExplorationMetrics `json:"per_source,omitempty"`
}

// Builder is an interface that builds a call graph from a set of packages.
type Builder interface {
	// Build returns the necessary inbound-to-outbound as set of list of edges.
	Build() (paths []*CallPath, result *BuildResult, err error)
	// BuildCGOnly constructs only the call graph and returns metrics without path analysis.
	BuildCGOnly() (result *BuildResult, err error)
}

// Config contains configuration options for the graph builder.
type Config struct {
	// DisableSCCPAnalysis disables SCCP (Sparse Conditional Constant Propagation) analysis.
	DisableSCCPAnalysis bool
	// DisableRelaxedContext disables relaxed context / error propagation support (i.e., where context and error can be
	// sent / returned in unconventional ways like receiver fields or captured free vars).
	DisableRelaxedContext bool
	// DisableParallelCallTree disables parallel call tree computation.
	DisableParallelCallTree bool
	// RTAFlavor is the single RTA flavor used for the normal Build() path.
	RTAFlavor RTAFlavor
	// RTANumWorkers is the single worker count for the normal Build() path.
	RTANumWorkers int
	// RTABenchFlavors is the list of RTA flavors to sweep in BuildCGOnly (benchmarking).
	RTABenchFlavors []RTAFlavor
	// RTABenchNumWorkers is the list of worker counts to sweep in BuildCGOnly (benchmarking).
	RTABenchNumWorkers []int
	// CheckIsomorphism enables isomorphism checking between srta and parallel flavors.
	// Only used by BuildCGOnly.
	CheckIsomorphism bool
	// PermutationThreshold is the number of times the same function-set hash must
	// be observed reaching a sink before permutation detection triggers.
	// Default is 100. Set to 0 to disable.
	PermutationThreshold int64
	// MaxFunctionVisits limits how many times any single function's subtree
	// is re-explored across different call paths before marking it as a
	// convergence point. Default is 1000. Set to 0 to disable.
	MaxFunctionVisits int64
	// CodebasePkgPrefix is the package-path prefix used to distinguish the analyzed
	// organization's own code from third-party/stdlib dependencies for the codebase-size
	// metrics computed in computeCodebaseMetrics/printTopNodes. Empty matches every package.
	// The monorepo fork sets this to "example.internal".
	CodebasePkgPrefix string
	// ExcludePackagePatterns holds regexp patterns (regexp.Compile syntax) matched against the
	// full import path of every package reachable from the analyzed program. A package whose
	// import path matches any pattern is excluded (transitively) from call-graph construction
	// and traversal -- typically third-party SDKs, and RPC/tracing/metrics/DI-framework
	// generated or vendored code that fail-close analysis doesn't need to see inside of.
	//
	// A pattern is matched with (*regexp.Regexp).MatchString against the package's import
	// path, so "^foo(/.*)?$" matches "foo" and every "foo/..." subpackage.
	//
	// nil (the zero value) uses DefaultExcludePackagePatterns. A non-nil value -- including a
	// non-nil empty slice, which disables all pattern-based exclusion -- is used exactly as
	// given, with no default and no automatic merge. Callers that want the default set plus
	// their own additions (e.g. a company-internal monorepo's own framework/glue packages)
	// should build that combined list themselves and assign it here, typically
	// append(append([]string{}, DefaultExcludePackagePatterns...), extra...).
	//
	// Every package under GOROOT/src's top-level directories (except those with a "sync"
	// prefix) is always additionally excluded automatically, regardless of this field.
	ExcludePackagePatterns []string
	// SafeGoPkgPath is the fully qualified import path of the "safego"-shaped package whose
	// Go(func()) function the safego enricher recognizes as fire-and-forget goroutine spawning
	// (see safegoenricher.go) -- both to identify importers of the package and to recognize a
	// call site as SafeGoPkgPath+".Go(...)" via its SSA string representation. Empty uses
	// DefaultSafeGoPkgPath, this repo's own features/safego test-fixture package. A company-
	// internal fork wanting to recognize its own real internal safego-equivalent package sets
	// this to that package's import path -- see features/safego/BUILD.bazel's doc comment for
	// the wrapper-package recipe that lets a real internal package delegate to this one without
	// requiring existing call sites to change their imports.
	SafeGoPkgPath string
	// CanonicalEdgeOrder sorts every call-graph node's outgoing edges into a
	// deterministic order before call-tree exploration, so convergence pruning does
	// not depend on the order packages happened to be loaded in.
	CanonicalEdgeOrder bool
}

// builderImpl is a struct that builds a call graph from a set of packages.
type builderImpl struct {
	logger               *zap.SugaredLogger
	pkgs                 []*packages.Package
	ssaProg              *ssa.Program
	ssaPkgs              []*ssa.Package
	ssa2ast              mapper.SSAASTMap
	sig2ast              mapper.SignatureASTMap
	isGlue               bool
	entryPkg             *packages.Package
	inbounds             []fty.InboundPoint
	outbounds            []fty.OutboundPoint
	hasMain              bool
	inboundsSSA          []inbound
	outboundsSSA         []outbound
	neededTypes          map[pkgNamePair]*types.Interface
	blockedPkgs          map[*ssa.Package]bool
	blockedFuncsByFile   map[*ssa.Function]bool
	blockedCallsiteCache map[ssa.CallInstruction]bool
	inboundMap           map[*ssa.Function]inbound
	outboundMap          map[*ssa.Function]outbound
	debugFunRegexp       *regexp.Regexp
	metrics              map[string]float64
	dontPruneEdges       map[*callgraph.Edge]struct{}
	asyncSites           map[ssa.CallInstruction]struct{}
	converter            *instrtoast.Converter
	unwrapper            *syntheticfunc.Unwrapper
	config               Config
	// perSource collects per-inbound exploration metrics, keyed by canonical name.
	perSource map[string]SourceExplorationMetrics
	// infowCount tracks calls to rateLimitedInfow for log suppression.
	infowCount atomic.Int64
	// excludePkgRegexOnce/excludePkgRegex/excludePkgRegexErr cache the compiled result of
	// config.ExcludePackagePatterns (or DefaultExcludePackagePatterns) plus the GOROOT/src
	// stdlib scan, computed once per builderImpl and reused by every getBlockListPackages call
	// -- see pkgfilter.go.
	excludePkgRegexOnce sync.Once
	excludePkgRegex     []*regexp.Regexp
	excludePkgRegexErr  error
	// safeGoRegexOnce/safeGoPkgRegex/safeGoCallerPattern cache the two regexes derived from
	// config.SafeGoPkgPath (or DefaultSafeGoPkgPath), computed once per builderImpl and reused
	// by every safego-detection call -- see safegoenricher.go.
	safeGoRegexOnce     sync.Once
	safeGoPkgRegex      *regexp.Regexp
	safeGoCallerPattern *regexp.Regexp
}

type inbound struct {
	function             *ssa.Function
	originalInboundPoint fty.InboundPoint
}

type outbound struct {
	function              *ssa.Function
	ins                   ssa.CallInstruction
	originalOutboundPoint fty.OutboundPoint
}

// Read DEBUG_FUNC_REGEXP from the environment and return a list of compiled regexps.
// the list is expected to be a semicolon-separated list of regexps.
func readDebugFunRegexp(debugFunRegexpStr string) (*regexp.Regexp, error) {
	envs := os.Getenv(_debugFunRegexpEnv)
	if envs == "" {
		return nil, nil
	}
	r, err := regexp.Compile(envs)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regexp %v: %v", envs, err)
	}
	return r, nil
}

// NewBuilder creates a new Builder instance.
func NewBuilder(logger *zap.SugaredLogger,
	pkgs []*packages.Package,
	ssaProg *ssa.Program,
	ssaPkgs []*ssa.Package,
	ssa2ast mapper.SSAASTMap,
	sig2ast mapper.SignatureASTMap,
	isGlue bool,
	entryPkg *packages.Package,
	inbounds []fty.InboundPoint,
	outbounds []fty.OutboundPoint,
	hasMain bool,
	config Config,
) Builder {
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}
	neededTypes := map[pkgNamePair]*types.Interface{
		_contextContext: nil,
		_syncLocker:     nil,
		_builtinError:   nil,
	}

	debugFunRegexp, err := readDebugFunRegexp(_debugFunRegexpEnv)
	if err != nil {
		logger.Warnf("Failed to read debug function regexps: %v", err)
	}

	return &builderImpl{
		logger:               logger,
		pkgs:                 pkgs,
		isGlue:               isGlue,
		entryPkg:             entryPkg,
		inbounds:             inbounds,
		outbounds:            outbounds,
		hasMain:              hasMain,
		ssaProg:              ssaProg,
		ssaPkgs:              ssaPkgs,
		ssa2ast:              ssa2ast,
		sig2ast:              sig2ast,
		neededTypes:          neededTypes,
		blockedCallsiteCache: map[ssa.CallInstruction]bool{},
		inboundMap:           map[*ssa.Function]inbound{},
		outboundMap:          map[*ssa.Function]outbound{},
		debugFunRegexp:       debugFunRegexp,
		metrics:              map[string]float64{},
		blockedFuncsByFile:   map[*ssa.Function]bool{},
		dontPruneEdges:       map[*callgraph.Edge]struct{}{},
		asyncSites:           map[ssa.CallInstruction]struct{}{},
		converter:            instrtoast.New(ssaProg, pkgs),
		unwrapper:            syntheticfunc.NewUnwrapper(logger),
		config:               config,
	}
}

func (b *builderImpl) getCG() (*callgraph.Graph, error) {
	// Begin clean by forcing GC.
	runtime.GC()
	defer runtime.GC()

	// Build the call graph based on the presence of the main function.
	if b.hasMain {
		entry, err := b.getRTAEntryFunctions()
		if err != nil {
			return nil, err
		}

		usage := utils.GetMaxUsedDram()
		b.logger.Infow("rta_construction", "rss_before_rta_construction", usage)
		b.metrics["rss_before_rta_construction"] = float64(usage)

		numWorkers := b.config.RTANumWorkers
		if b.config.RTAFlavor.IsSequential() {
			numWorkers = 1
		}

		start := time.Now()
		result, err := b.runSingleFlavor(entry, b.config.RTAFlavor, numWorkers)
		if err != nil {
			return nil, err
		}
		duration := time.Since(start)
		b.logger.Infof("Graph construction took %v", duration)
		b.metrics["rta_duration_secs"] = duration.Seconds()

		usage = utils.GetMaxUsedDram()
		b.logger.Infow("rta_construction", "rss_after_rta_construction", usage)
		b.metrics["rss_after_rta_construction"] = float64(usage)
		if result == nil {
			return nil, errors.New("RTA call graph is nil")
		}

		return result, nil
	}

	// Build CHA (Class Hierarchy Analysis) call graph.
	chaGraph := cha.CallGraph(b.ssaProg)
	if chaGraph == nil {
		b.logger.Warn("CHA call graph is nil")
		return nil, errors.New("CHA call graph is nil")
	}
	return chaGraph, nil
}

func (b *builderImpl) populateSSAInbounds() ([]inbound, error) {
	// Map inbound AST functions to SSA function nodes via ssa2ast.AtoS.
	inboundsSSA := make([]inbound, 0, len(b.inbounds))
	for _, ib := range b.inbounds {
		// Get the AST node corresponding to the inbound function's signature.
		astNode, ok := b.sig2ast.StoA[ib.Func.Type().(*types.Signature)]
		if !ok {
			b.logger.Warnf("populateSSAInbounds failed to find AST node for function %s with signature %s", ib.Func.String(), ib.Func.Type())
			continue
		}

		// Use ssa2ast.AtoS to map the AST node to the SSA function.
		ssaFunc, ok := b.ssa2ast.AtoS[astNode]
		if !ok {
			b.logger.Warnf("populateSSAInbounds b.ssa2ast.AtoS[astNode] failed for function %v", ib.Func.String())
			continue
		}

		inboundsSSA = append(inboundsSSA, inbound{
			function:             ssaFunc,
			originalInboundPoint: ib,
		})
		b.logger.Debugf("populateSSAInbounds mapped ast %s to %s", ib.Func.String(), ssaFunc.String())
	}
	if len(inboundsSSA) != len(b.inbounds) {
		return nil, fmt.Errorf("failed to map all inbound functions to SSA")
	}
	return inboundsSSA, nil
}

// populateSSAOutbounds maps outbound AST call sites to SSA functions and call instructions.
func (b *builderImpl) populateSSAOutbounds() ([]outbound, error) {
	// Map outbound AST call sites to SSA functions and call instructions.
	outboundsSSA := make([]outbound, 0, len(b.outbounds))
	for _, ob := range b.outbounds {
		call := ob.Call
		callInfo := astToString(call, b.ssaProg.Fset)

		// Find the enclosing function AST node of the call expression.
		enclosingFunc, err := findEnclosingFunction(call, ob.Pkg)
		if err != nil {
			b.logger.Debugf("populateSSAOutbounds: findEnclosingFunction for pkg %v and call site %v failed with error = %v", ob.Pkg.String(), callInfo, err)
			continue
		}

		// Use ssa2ast.AtoS to map the enclosing function AST node to the SSA function.
		ssaFunc, ok := b.ssa2ast.AtoS[enclosingFunc]

		if !ok {
			funcInfo := astToString(enclosingFunc, b.ssaProg.Fset)
			callInfo := astToString(call, b.ssaProg.Fset)
			b.logger.Debugf("populateSSAOutbounds b.ssa2ast.AtoS[enclosingFunc] failed for function %v and call site %v", funcInfo, callInfo)
			continue
		}

		// Use ssaFunc.ValueForExpr to get the SSA value corresponding to the call expression.
		ci, err := getClosestCallInstruction(ssaFunc, call, b.ssaProg.Fset, _maxClosestInstructions)
		if err != nil {
			funcInfo := astToString(enclosingFunc, b.ssaProg.Fset)
			callInfo := astToString(call, b.ssaProg.Fset)
			// get disassembly of the function from WriteTo().
			// Use a strings.Builder to capture the output.
			var builder strings.Builder
			// Write SSA representation to the strings.Builder.
			ssaFunc.WriteTo(&builder)

			b.logger.Debugw("populateSSAOutbounds getClosestCallInstruction could not find the call site for. Function %v, body %v, ssa = %v and call site %v", ssaFunc.String(), funcInfo, builder.String(), callInfo)
			continue
		}

		// Add the SSA function and call instruction to outboundsSSA.
		outboundsSSA = append(outboundsSSA, outbound{
			function:              ssaFunc,
			ins:                   ci,
			originalOutboundPoint: ob,
		})
		b.logger.Debugf("populateSSAOutbounds mapped ast to %s", ssaFunc.String())
	}
	if len(outboundsSSA) != len(b.outbounds) {
		return nil, fmt.Errorf("failed to map all outbound calls to SSA")
	}
	return outboundsSSA, nil
}

func (b *builderImpl) setSSAInOutBounds() error {
	// Map inbound AST functions to SSA function nodes via ssa2ast.
	ibs, err := b.populateSSAInbounds()
	if err != nil {
		b.logger.Errorf("Error populating SSA inbounds: %v", err)
		return err
	}
	b.inboundsSSA = ibs

	// Map outbound AST call sites to SSA functions and call instructions.
	obs, err := b.populateSSAOutbounds()
	if err != nil {
		b.logger.Errorf("Error populating SSA outbounds: %v", err)
		return err
	}
	b.outboundsSSA = obs

	// Create a map of inbound functions for quick lookup.
	for _, ib := range b.inboundsSSA {
		b.inboundMap[ib.function] = ib
	}
	// Create a map of inbound functions for quick lookup.
	for _, ob := range b.outboundsSSA {
		b.outboundMap[ob.function] = ob
	}

	return nil
}

func (b *builderImpl) logAvailableInboundsOutbounds(cg *callgraph.Graph, metricPrefix string) {
	b.logger.Infow("Available inbounds", "num_inbounds", len(b.inboundsSSA))
	foundOb := 0
	foundIb := 0
	for _, ib := range b.inboundsSSA {
		if _, ok := cg.Nodes[ib.function]; ok {
			foundIb++
			b.logger.Infow("Available inbound", "function", ib.function.String())
		} else {
			b.logger.Infow("Inbound not found in call graph", "function", ib.function.String())
		}
	}
	b.logger.Infow("Available outbounds", "num_outbounds", len(b.outboundsSSA))
	for _, ob := range b.outboundsSSA {
		if _, ok := cg.Nodes[ob.function]; ok {
			foundOb++
			b.logger.Infow("Available outbound", "function", ob.function.String())
		} else {
			b.logger.Infow("Outbound not found in call graph", "function", ob.function.String())
		}
	}
	b.logger.Infow("Found inbounds", "num_inbounds", foundIb, "expected", len(b.inboundsSSA))
	b.logger.Infow("Found outbounds", "num_outbounds", foundOb, "expected", len(b.outboundsSSA))
	b.metrics[metricPrefix+"_inbound"] = float64(foundIb)
	b.metrics[metricPrefix+"_outbound"] = float64(foundOb)
}

// synthesizeMissingInboundNodes creates an isolated (no in/out edges) call-graph node for every
// inbound (source handler) that RTA marked reachable -- it was passed as a root in
// getRTAEntryFunctions -- but for which no node ended up in cg.Nodes.
//
// This happens because callgraph.Graph nodes are only materialized as a side effect of recording
// an edge (see rta/srta/impl.go's addEdge/addInvokeEdge, both of which call g.CreateNode); RTA
// never calls CreateNode merely because a function is reachable. An inbound legitimately has no
// incoming edge (by definition -- it's an entry point, not called by other in-program code), so
// it only gets a node if at least one of its own calls resolves to a recorded outgoing edge. A
// handler whose only calls are dynamic dispatches RTA can't resolve in this binary -- e.g. calls
// through function-valued struct fields (closures) whose only assignment site lives in a sibling
// binary sharing the same source tree, as with jaegertracing/jaeger's
// plugin/storage/grpc/shared.GRPCHandler.Capabilities when analyzing cmd/collector, whose
// closures are only ever populated from cmd/remote-storage -- ends up reachable but nodeless.
//
// Without this, buildCallTreeNode (cct.go) hits such a function as a call-tree root, finds it
// missing from cg.Nodes, and returns a hard error that aborts the entire build (discarding valid
// results for every other inbound) instead of the same "nothing more to explore from here"
// outcome its sibling early-return branches (cycle / convergence-limit) already treat as
// non-fatal. Giving the node an empty Node (no in/out edges) here makes buildCallTreeNode's normal
// "no edges to explore" path apply to it -- i.e. it becomes a legitimate zero-call-paths inbound,
// consistent with the existing success_no_call_paths outcome for a whole service -- rather than a
// distinct crash.
func (b *builderImpl) synthesizeMissingInboundNodes(cg *callgraph.Graph) {
	synthesized := 0
	for _, ib := range b.inboundsSSA {
		if _, ok := cg.Nodes[ib.function]; ok {
			continue
		}
		cg.CreateNode(ib.function)
		synthesized++
		b.logger.Warnw("Synthesizing empty call-graph node for reachable-but-nodeless inbound",
			"function", ib.function.String())
	}
	if synthesized > 0 {
		b.logger.Warnw("Synthesized empty call-graph nodes for inbounds RTA never recorded an edge for",
			"num_synthesized", synthesized)
	}
	b.metrics[_inboundNodesSynthesized] = float64(synthesized)
}

func (b *builderImpl) addGraphStatsToMetrics(gs graphStats, prefix string) {
	b.metrics[prefix+"NumNodes"] = float64(gs.numNodes)
	b.metrics[prefix+"NumEdges"] = float64(gs.numEdges)
	b.metrics[prefix+"InAvg"] = gs.inAvg
	b.metrics[prefix+"InMax"] = float64(gs.inMax)
	b.metrics[prefix+"OutAvg"] = gs.outAvg
	b.metrics[prefix+"OutMax"] = float64(gs.outMax)
}

// Build constructs the call graph and maps AST functions to SSA function nodes.
func (b *builderImpl) Build() ([]*CallPath, *BuildResult, error) {
	// Begin clean by forcing GC.
	runtime.GC()
	defer runtime.GC()

	paths, _, _, err := b.getCallPathsAndCallGraph()
	return paths, b.buildResult(), err
}

// BuildCGOnly constructs only the call graph and returns metrics without path analysis.
// This is used for CG construction-only evaluation benchmarks.
// It sweeps across all configured RTABenchFlavors × RTABenchNumWorkers.
func (b *builderImpl) BuildCGOnly() (*BuildResult, error) {
	metrics, err := b.buildCGOnlySweep()
	return &BuildResult{Metrics: metrics}, err
}

// buildResult creates a BuildResult from the builder's collected metrics.
func (b *builderImpl) buildResult() *BuildResult {
	return &BuildResult{
		Metrics:   maps.Clone(b.metrics),
		PerSource: b.perSource,
	}
}

// getCallPathsAndCallGraph is a helper function that constructs the call graph and maps AST functions to SSA function nodes.
func (b *builderImpl) getCallPathsAndCallGraph() ([]*CallPath, []*CallPath, *callgraph.Graph, error) {
	// Compute codebase metrics first (outside of RTA timing)
	b.computeCodebaseMetrics()

	b.logger.Infof("Setting SSA inbounds and outbounds")
	if err := b.setSSAInOutBounds(); err != nil {
		b.logger.Errorf("Error setting SSA inbounds and outbounds")
		return nil, nil, nil, err
	}
	b.metrics[_inboundNeeded] = float64(len(b.inbounds))
	b.metrics[_inboundFound] = float64(len(b.inboundsSSA))
	b.metrics[_outboundNeeded] = float64(len(b.outbounds))
	b.metrics[_outboundFound] = float64(len(b.outboundsSSA))

	b.logger.Infow("Inbounds and ssaInbounds", "num_inbounds", len(b.inbounds), "num_ssaInbounds", len(b.inboundsSSA))
	b.logger.Infow("Outbounds and ssaOutbounds", "num_outbounds", len(b.outbounds), "num_ssaOutbounds", len(b.outboundsSSA))

	b.logger.Infof("Building call graph")
	cg, err := b.getCG()
	if err != nil {
		b.logger.Errorf("Error getting call graph: %v", err)
		return nil, nil, nil, err
	}

	b.logger.Infof("Analyzing raw call graph")
	gs := b.logGraphStats(cg, _maxCGNodesToLog, zap.InfoLevel)
	b.addGraphStatsToMetrics(gs, "rawGraph")

	b.dumpSSAFunctionsWithRegexp(cg)

	b.logAvailableInboundsOutbounds(cg, "raw_graph" /* metricPrefix */)
	b.logger.Infof("Setting up blocked packages")
	// Set up the list of blocked packages.
	b.blockedPkgs, err = b.getBlockListPackages(b.ssaProg.AllPackages())
	if err != nil {
		b.logger.Errorf("Error setting up blocked packages: %v", err)
		return nil, nil, nil, err
	}
	b.logger.Infow("Blocked packages", "num_packages", len(b.blockedPkgs))

	b.logger.Infof("Populating needed types")
	b.populateNeededTypes(b.ssaProg)
	for k, v := range b.neededTypes {
		if v == nil {
			b.logger.Errorf("needed type %v is nil", k)
			return nil, nil, nil, fmt.Errorf("needed type %v is nil", k)
		}
	}

	b.logger.Infof("Enriching call graph with CFF calls")
	b.enrichWithCFFCall(cg)
	gs = b.logGraphStats(cg, _maxCGNodesToLog, zap.InfoLevel)
	b.addGraphStatsToMetrics(gs, "cffGraph")

	b.logger.Infof("Enriching call graph with errgroup calls")
	b.enrichCallGraphWithErrgroup(cg)
	gs = b.logGraphStats(cg, _maxCGNodesToLog, zap.InfoLevel)
	b.addGraphStatsToMetrics(gs, "errgroupGraph")

	b.logger.Infof("Enriching call graph with safego calls")
	b.enrichWithSafeGoCall(cg)
	gs = b.logGraphStats(cg, _maxCGNodesToLog, zap.InfoLevel)
	b.addGraphStatsToMetrics(gs, "safeGoGraph")

	b.logger.Infof("Populating synthetic function unwrapper")
	b.populateUnwrapper(cg)

	b.logger.Infof("Pruning the call graph")
	if b.pruneGraph(cg) != nil {
		b.logger.Errorf("Error pruning the call graph")
		return nil, nil, nil, err
	}
	b.logger.Infof("Analyzing pruned call graph")
	gs = b.logGraphStats(cg, _maxCGNodesToLog, zap.InfoLevel)
	b.logAvailableInboundsOutbounds(cg, "pruned_graph" /* metricPrefix */)
	b.addGraphStatsToMetrics(gs, "prunedGraph")

	b.synthesizeMissingInboundNodes(cg)

	b.logger.Infof("Building call tree")
	// Now get the calltree from the pruned graph.
	cct, err := b.buildCallTree(cg)
	if err != nil {
		b.logger.Errorf("Error building call tree: %v", err)
		return nil, nil, nil, err
	}

	b.logger.Infof("Collecting call paths")
	// collect all call paths.
	callpaths, err := b.collectPaths(cct)
	if err != nil {
		b.logger.Errorf("Error collecting call paths: %v", err)
		return nil, nil, nil, err
	}

	// Separate goroutine and non-goroutine call paths.
	nongoCallpaths, goCallpaths := b.separateGoroutineCalls(callpaths)
	b.dumpCallpaths(goCallpaths, "goCallpaths")
	b.dumpCallpaths(nongoCallpaths, "nongoCallpaths")
	b.metrics["nongoCallpaths"] = float64(len(nongoCallpaths))
	b.metrics["goCallpaths"] = float64(len(goCallpaths))
	b.metrics["numCallPaths"] = float64(len(callpaths))
	b.logger.Infof("Number of call paths: %d", len(callpaths))
	b.logger.Infof("Number of goroutine call paths: %d", len(goCallpaths))
	b.logger.Infof("Number of non-goroutine call paths: %d", len(nongoCallpaths))
	b.addIbObMatchingMetric(callpaths)

	// Wrap raw nongoCallpaths in CallPath objects.
	b.logger.Debugw("Wrapping non-Go Callpaths call paths with IB and OB endpoints info", "num_callpaths", len(nongoCallpaths))
	nongoEdgeInfos := b.edgeToEdgeInfo(nongoCallpaths)
	wrappedNonGoCallPaths, err := b.wrapCallPathsWithIBOB(nongoEdgeInfos)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("wrapping nongoCallpaths with IB and OB endpoints info: %v", err)
	}
	b.logger.Debugw("Wrapping go Callpaths call paths with IB and OB endpoints info", "num_callpaths", len(goCallpaths))

	goEdgeInfos := b.edgeToEdgeInfo(goCallpaths)
	wrappedGoCallPaths, err := b.wrapCallPathsWithIBOB(goEdgeInfos)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("wrapping goCallpaths with IB and OB endpoints info: %v", err)
	}

	asyncCount := 0
	for _, cp := range wrappedNonGoCallPaths {
		if cp.IsAsync {
			asyncCount++
		}
	}
	asyncCount += len(wrappedGoCallPaths) // all go call paths are async by definition
	b.metrics["asyncCallpaths"] = float64(asyncCount)
	b.logger.Infof("Number of async call paths: %d", asyncCount)

	return wrappedNonGoCallPaths, wrappedGoCallPaths, cg, nil
}

func isSyntheticCaller(edge *callgraph.Edge) bool {
	return edge.Caller != nil && edge.Caller.Func != nil && edge.Caller.Func.Synthetic != ""
}

func (b *builderImpl) edgeToEdgeInfo(callpaths [][]*callgraph.Edge) [][]*edgeinfo.EdgeInfo {
	queries := 0
	failures := 0
	syntheticFunc := 0
	edgeInfo := make([][]*edgeinfo.EdgeInfo, 0, len(callpaths))
	for _, path := range callpaths {
		onePath := make([]*edgeinfo.EdgeInfo, 0, len(path))
		queries += len(path)
		for _, edge := range path {
			if isSyntheticCaller(edge) {
				syntheticFunc++
				// for synthetic callers, we don't have a call expression.
				onePath = append(onePath, &edgeinfo.EdgeInfo{
					Edge:     edge,
					CallExpr: nil,
				})
			} else {
				// for non-synthetic callers, convert the call instruction to a call expression.
				expr, err := b.converter.CallInstrToCallExpr(edge.Site)
				if err != nil {
					failures++
					caller := "<nil>"
					if edge.Caller != nil {
						caller = edge.Caller.String()
					}
					b.logger.Infof("edgeToEdgeInfo failed for inst %v in func %v with error: %v", edge.Site, caller, err)
					expr = nil
				}
				onePath = append(onePath, &edgeinfo.EdgeInfo{
					Edge:     edge,
					CallExpr: expr,
				})
			}
		}
		edgeInfo = append(edgeInfo, onePath)
	}
	b.metrics[_numIns2ExprQueries] += float64(queries)
	b.metrics[_numIns2ExprFailures] += float64(failures)
	b.metrics[_numIns2ExprSyntheticFuncs] += float64(syntheticFunc)

	return edgeInfo
}

func (b *builderImpl) wrapCallPathsWithIBOB(callpaths [][]*edgeinfo.EdgeInfo) ([]*CallPath, error) {
	var wrappedCallPaths []*CallPath
	for _, path := range callpaths {
		if len(path) == 0 {
			continue
		}
		ib, ok := b.inboundMap[path[0].Edge.Caller.Func]
		if !ok {
			return nil, fmt.Errorf("inbound not found for %s", path[0].Edge.Caller.Func.String())
		}
		ob, ok := b.outboundMap[path[len(path)-1].Edge.Caller.Func]
		if !ok {
			return nil, fmt.Errorf("outbound not found for %s", path[len(path)-1].Edge.Caller.Func.String())
		}

		wrappedCallPaths = append(wrappedCallPaths, &CallPath{
			Inbound:  ib.originalInboundPoint,
			Outbound: ob.originalOutboundPoint,
			Edges:    path,
			IsAsync:  b.hasAsyncEdge(path),
		})

	}
	return wrappedCallPaths, nil
}

func (b *builderImpl) addIbObMatchingMetric(callpaths [][]*callgraph.Edge) {
	uniqueIbs := map[*ssa.Function]struct{}{}
	uniqueObs := map[*ssa.Function]struct{}{}
	// Add metrics for inbound and outbound matching.
	for _, path := range callpaths {
		ib := path[0].Caller.Func
		ob := path[len(path)-1].Caller.Func
		if _, ok := b.inboundMap[ib]; ok {
			uniqueIbs[ib] = struct{}{}
		}
		if _, ok := b.outboundMap[ob]; ok {
			uniqueObs[ob] = struct{}{}
		}
	}
	b.metrics["inboundsWithPathToOutbound"] = float64(len(uniqueIbs))
	b.metrics["outboundsWithPathFromInbound"] = float64(len(uniqueObs))
}

func (b *builderImpl) separateGoroutineCalls(paths [][]*callgraph.Edge) ([][]*callgraph.Edge, [][]*callgraph.Edge) {
	nonGoroutinePaths := [][]*callgraph.Edge{}
	goroutinePaths := [][]*callgraph.Edge{}
	for _, path := range paths {
		if b.hasGoroutineCall(path) {
			goroutinePaths = append(goroutinePaths, path)
		} else {
			nonGoroutinePaths = append(nonGoroutinePaths, path)
		}
	}
	return nonGoroutinePaths, goroutinePaths
}

func (b *builderImpl) hasGoroutineCall(path []*callgraph.Edge) bool {
	for _, edge := range path {
		if b.isGoCall(edge.Site) {
			return true
		}
	}
	return false
}

// findEnclosingFunction finds the enclosing function AST node for a given AST node.
func findEnclosingFunction(ob *ast.CallExpr, pkg *packages.Package) (ast.Node, error) {
	if ob == nil || pkg == nil {
		return nil, fmt.Errorf("call expression / pkg are nill is nil")
	}
	// Find the AST file containing the call expression.
	var file *ast.File
	for _, f := range pkg.Syntax {
		if f.Pos() <= ob.Pos() && ob.Pos() <= f.End() {
			file = f
			break
		}
	}
	if file == nil {
		return nil, fmt.Errorf("no AST file found containing call at %v", ob.Pos())
	}

	// Use astutil.PathEnclosingInterval to find the path to the call expression.
	path, _ := astutil.PathEnclosingInterval(file, ob.Pos(), ob.End())
	if len(path) == 0 {
		return nil, fmt.Errorf("no AST path found for call at %v", ob.Pos())
	}

	// Find the enclosing function in the path.
	var enclosingFunc ast.Node
LOOP:
	for _, node := range path {
		switch node.(type) {
		case *ast.FuncDecl, *ast.FuncLit:
			enclosingFunc = node
			break LOOP
		}
	}
	if enclosingFunc == nil {
		return nil, fmt.Errorf("no enclosing function found for call at %v", ob.Pos())
	}
	return enclosingFunc, nil
}

func (b *builderImpl) addEdgesToNoPruneSet(newEdges map[*callgraph.Edge]struct{}) {
	for e := range newEdges {
		b.dontPruneEdges[e] = struct{}{}
	}
}

// createAndRegisterAsyncEdge registers the call sites of the given edges as async.
func (b *builderImpl) createAndRegisterAsyncEdge(edges map[*callgraph.Edge]struct{}) {
	for e := range edges {
		b.asyncSites[e.Site] = struct{}{}
	}
}

// hasAsyncEdge returns true if any edge in the path is async (registered via enrichers or a go statement).
func (b *builderImpl) hasAsyncEdge(path []*edgeinfo.EdgeInfo) bool {
	for _, ei := range path {
		if _, ok := b.asyncSites[ei.Edge.Site]; ok {
			return true
		}
		if b.isGoCall(ei.Edge.Site) {
			return true
		}
	}
	return false
}

func (b *builderImpl) isDontPruneEdge(edge *callgraph.Edge) bool {
	_, ok := b.dontPruneEdges[edge]
	return ok
}

func (b *builderImpl) dumpCallpaths(callpaths [][]*callgraph.Edge, name string) {
	b.logger.Infof("Dumping %s", name)
	var cnt int

	for i, path := range callpaths {
		b.logger.Infof("Path %d", i)
		for j, edge := range path {
			if edge.Callee != nil {
				callee := edge.Callee.Func.String()
				b.logger.Infow("dumpCallpaths", "edge", j, "caller", edge.Caller.String(), "callee", callee)
			} else {
				callee := edge.Site.String()
				b.logger.Infow("dumpCallpaths", "edge", j, "caller", edge.Caller.String(), "callee", callee)
			}
			cnt++
			if cnt >= _dumpCallPathsMaxEdges {
				b.logger.Infow("Reached max edges to dump, skipping the remaining", "max_edges", _dumpCallPathsMaxEdges, "num_remaining_paths", len(callpaths)-i-1)
				return
			}
		}
	}
}

func (b *builderImpl) populateUnwrapper(cg *callgraph.Graph) {
	b.unwrapper = b.unwrapper.WithCallgraph(cg, b.ssaProg)
}

// computeCodebaseMetrics computes metrics about the codebase size.
func (b *builderImpl) computeCodebaseMetrics() {
	numPackages := len(b.pkgs)
	numFunctions := 0
	numFiles := 0
	numLinesOfCode := 0
	numConcreteTypes := 0
	numInterfaces := 0

	// Codebase-scoped counters: only packages whose path contains "example.internal".
	codebaseNumPackages := 0
	codebaseNumFunctions := 0
	codebaseNumFiles := 0
	codebaseNumLinesOfCode := 0
	codebaseNumConcreteTypes := 0
	codebaseNumInterfaces := 0

	seenFiles := make(map[string]bool)
	seenTypes := make(map[types.Type]bool)

	for _, pkg := range b.pkgs {
		if pkg == nil {
			continue
		}
		isCodebasePkg := strings.Contains(pkg.PkgPath, b.config.CodebasePkgPrefix)
		if isCodebasePkg {
			codebaseNumPackages++
		}
		for _, file := range pkg.Syntax {
			if file == nil {
				continue
			}
			// Get the file path
			pos := pkg.Fset.Position(file.Pos())
			if pos.Filename != "" && !seenFiles[pos.Filename] {
				seenFiles[pos.Filename] = true
				numFiles++
				// Count lines in the file
				endPos := pkg.Fset.Position(file.End())
				numLinesOfCode += endPos.Line
				if isCodebasePkg {
					codebaseNumFiles++
					codebaseNumLinesOfCode += endPos.Line
				}
			}
			// Count functions in the file
			for _, decl := range file.Decls {
				if _, ok := decl.(*ast.FuncDecl); ok {
					numFunctions++
					if isCodebasePkg {
						codebaseNumFunctions++
					}
				}
			}
		}

		// Count types defined in this package
		if pkg.TypesInfo != nil {
			for _, obj := range pkg.TypesInfo.Defs {
				if obj == nil {
					continue
				}
				typeName, ok := obj.(*types.TypeName)
				if !ok {
					continue
				}
				typ := typeName.Type()
				if seenTypes[typ] {
					continue
				}
				seenTypes[typ] = true

				// Check if this is an interface or concrete type
				if _, isInterface := typ.Underlying().(*types.Interface); isInterface {
					numInterfaces++
					if isCodebasePkg {
						codebaseNumInterfaces++
					}
				} else {
					numConcreteTypes++
					if isCodebasePkg {
						codebaseNumConcreteTypes++
					}
				}
			}
		}
	}

	// Also count SSA functions including anonymous functions
	if b.ssaProg != nil {
		ssaFuncCount := 0
		for fn := range ssautil.AllFunctions(b.ssaProg) {
			if fn != nil {
				ssaFuncCount++
			}
		}
		b.metrics["num_ssa_functions"] = float64(ssaFuncCount)
	}

	b.metrics["num_packages"] = float64(numPackages)
	b.metrics["num_functions"] = float64(numFunctions)
	b.metrics["num_files"] = float64(numFiles)
	b.metrics["num_lines_of_code"] = float64(numLinesOfCode)
	b.metrics["num_concrete_types"] = float64(numConcreteTypes)
	b.metrics["num_interfaces"] = float64(numInterfaces)

	b.metrics["uber_num_packages"] = float64(codebaseNumPackages)
	b.metrics["uber_num_functions"] = float64(codebaseNumFunctions)
	b.metrics["uber_num_files"] = float64(codebaseNumFiles)
	b.metrics["uber_num_lines_of_code"] = float64(codebaseNumLinesOfCode)
	b.metrics["uber_num_concrete_types"] = float64(codebaseNumConcreteTypes)
	b.metrics["uber_num_interfaces"] = float64(codebaseNumInterfaces)

	b.logger.Infof("Codebase metrics: %d packages, %d functions, %d files, %d lines of code, %d concrete types, %d interfaces",
		numPackages, numFunctions, numFiles, numLinesOfCode, numConcreteTypes, numInterfaces)
	b.logger.Infof("Codebase-scoped metrics: %d packages, %d functions, %d files, %d lines of code, %d concrete types, %d interfaces",
		codebaseNumPackages, codebaseNumFunctions, codebaseNumFiles, codebaseNumLinesOfCode, codebaseNumConcreteTypes, codebaseNumInterfaces)
}
