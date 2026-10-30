package graph

import (
	"fmt"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/uber-research/rpcshield/go/common/mapper"
	"github.com/uber-research/rpcshield/go/finder"
	"github.com/uber-research/rpcshield/go/finder/servicemapping"
	"github.com/uber-research/rpcshield/go/grail"
	"github.com/uber-research/rpcshield/go/rpcshieldtest"
	"go.uber.org/zap"
)

func TestCCT(t *testing.T) {
	t.Parallel()
	testPkg := rpcshieldtest.LoadrpcshieldDemoPackages()
	entryPkg, allPkgs, ssaProg, ssaPkgs := testPkg.Entry, testPkg.All, testPkg.SSAProg, testPkg.SSAPkgs
	require.NotNil(t, entryPkg)
	require.Greater(t, len(allPkgs), 0)

	SSAASTBidirMap := mapper.SSAToASTMap(allPkgs, ssaPkgs, ssaProg)
	SigASTBidirMap := mapper.SignatureToASTMap(allPkgs)

	logger := zap.NewNop().Sugar()
	inboundService := grail.Service{Name: "rpcshielddemo", Tier: -1}
	lotteryService := grail.Service{Name: "lottery", Tier: 5}
	clientTypeToService := servicemapping.ServiceMapping{}
	clientTypeToService.AddMappings(
		servicemapping.FullyQualifiedType{PkgPath: "thriftrw/lottery/lotteryclient", Name: "Interface"},
		&servicemapping.ServiceWithIDLInfo{Service: lotteryService},
	)
	serviceMapper := servicemapping.New([]grail.Service{lotteryService}, clientTypeToService, logger)
	f := finder.New(inboundService, serviceMapper, logger, map[string]bool{} /* keepIBPkgs */, "" /* codebasePkgPrefix */, "" /* kafkaConsumerProxyPkgPath */, nil /* infraPkgPrefixes */, false /* enableGenericGRPCThriftDetection */)

	inbounds, err := f.Inbound(entryPkg, allPkgs, ssaProg)
	require.NoError(t, err)
	require.NotEmpty(t, inbounds)

	outbounds, _, err := f.Outbound(entryPkg, allPkgs)
	require.NoError(t, err)
	require.NotEmpty(t, outbounds)

	b := NewBuilder(logger, allPkgs, ssaProg, ssaPkgs, SSAASTBidirMap, SigASTBidirMap, true,
		entryPkg, inbounds, outbounds, true, DefaultSerialGraphConfig())
	paths, _, err := b.Build()
	require.NoError(t, err)

	if len(_rpcshieldDemoAllPaths) == 0 {
		for _, path := range paths {
			canonocalPath := path.Edges[0].Edge.Caller.Func.String()
			for _, edge := range path.Edges {
				if edge.Edge.Callee != nil {
					canonocalPath += edge.Edge.Callee.Func.String()
				}
			}
			t.Logf("DISCOVERY path=%q", canonocalPath)
		}
	}

	require.Len(t, paths, len(_rpcshieldDemoAllPaths))
	for _, path := range paths {
		canonocalPath := path.Edges[0].Edge.Caller.Func.String()
		for _, edge := range path.Edges {
			if edge.Edge.Callee != nil {
				canonocalPath += edge.Edge.Callee.Func.String()
			}
		}
		require.Contains(t, _rpcshieldDemoAllPaths, canonocalPath)
	}
}

func TestCCT_WithConvergence(t *testing.T) {
	t.Parallel()
	testPkg := rpcshieldtest.LoadrpcshieldDemoPackages()
	entryPkg, allPkgs, ssaProg, ssaPkgs := testPkg.Entry, testPkg.All, testPkg.SSAProg, testPkg.SSAPkgs
	require.NotNil(t, entryPkg)
	require.Greater(t, len(allPkgs), 0)

	SSAASTBidirMap := mapper.SSAToASTMap(allPkgs, ssaPkgs, ssaProg)
	SigASTBidirMap := mapper.SignatureToASTMap(allPkgs)

	logger := zap.NewNop().Sugar()
	inboundService := grail.Service{Name: "rpcshielddemo", Tier: -1}
	lotteryService := grail.Service{Name: "lottery", Tier: 5}
	clientTypeToService := servicemapping.ServiceMapping{}
	clientTypeToService.AddMappings(
		servicemapping.FullyQualifiedType{PkgPath: "thriftrw/lottery/lotteryclient", Name: "Interface"},
		&servicemapping.ServiceWithIDLInfo{Service: lotteryService},
	)
	serviceMapper := servicemapping.New([]grail.Service{lotteryService}, clientTypeToService, logger)
	f := finder.New(inboundService, serviceMapper, logger, map[string]bool{}, "" /* codebasePkgPrefix */, "" /* kafkaConsumerProxyPkgPath */, nil /* infraPkgPrefixes */, false /* enableGenericGRPCThriftDetection */)

	inbounds, err := f.Inbound(entryPkg, allPkgs, ssaProg)
	require.NoError(t, err)
	require.NotEmpty(t, inbounds)

	outbounds, _, err := f.Outbound(entryPkg, allPkgs)
	require.NoError(t, err)
	require.NotEmpty(t, outbounds)

	cfg := DefaultSerialGraphConfig()
	cfg.MaxFunctionVisits = 2
	b := NewBuilder(logger, allPkgs, ssaProg, ssaPkgs, SSAASTBidirMap, SigASTBidirMap, true,
		entryPkg, inbounds, outbounds, true, cfg)
	paths, buildResult, err := b.Build()
	require.NoError(t, err)
	require.NotNil(t, buildResult)
	require.Greater(t, len(paths), 0)

	hasConvergence := false
	for _, srcMetrics := range buildResult.PerSource {
		if srcMetrics.ConvergencePoints > 0 {
			hasConvergence = true
			break
		}
	}
	require.True(t, hasConvergence, "expected convergence detection with MaxFunctionVisits=2")
}

// TestSortOutEdges checks the property the canonical ordering exists for: the
// resulting edge order must depend only on the edge set, never on the order the
// edges happened to arrive in. Two scrambled permutations of the same edges must
// sort to the same sequence, and no edge may be gained or lost.
func TestSortOutEdges(t *testing.T) {
	t.Parallel()
	fns := makeDummyFunctions(t, 4)

	newEdges := func() []*callgraph.Edge {
		caller := &callgraph.Node{Func: fns[0], ID: 0}
		return []*callgraph.Edge{
			{Caller: caller, Callee: &callgraph.Node{Func: fns[3], ID: 3}},
			{Caller: caller, Callee: nil},
			{Caller: caller, Callee: &callgraph.Node{Func: fns[1], ID: 1}},
			{Caller: caller, Callee: &callgraph.Node{Func: fns[2], ID: 2}},
			{Caller: caller, Callee: &callgraph.Node{Func: fns[1], ID: 4}},
		}
	}

	order := func(edges []*callgraph.Edge) []string {
		node := &callgraph.Node{Func: fns[0], Out: edges}
		g := &callgraph.Graph{Nodes: map[*ssa.Function]*callgraph.Node{fns[0]: node}}
		sortOutEdges(g)
		out := make([]string, 0, len(node.Out))
		for _, e := range node.Out {
			out = append(out, fmt.Sprintf("%s#%d", calleeName(e), calleeID(e)))
		}
		return out
	}

	first := newEdges()
	scrambled := newEdges()
	scrambled[0], scrambled[4] = scrambled[4], scrambled[0]
	scrambled[1], scrambled[3] = scrambled[3], scrambled[1]

	got, want := order(scrambled), order(first)
	require.Equal(t, want, got, "sorted order must not depend on input order")
	require.Len(t, got, len(newEdges()), "sorting must not add or drop edges")
}

// TestSortOutEdgesSkipsTrivialNodes checks that nil nodes and nodes with fewer
// than two out-edges are left untouched rather than panicking.
func TestSortOutEdgesSkipsTrivialNodes(t *testing.T) {
	t.Parallel()
	fns := makeDummyFunctions(t, 2)

	single := &callgraph.Node{Func: fns[0], Out: []*callgraph.Edge{{Callee: nil}}}
	g := &callgraph.Graph{Nodes: map[*ssa.Function]*callgraph.Node{
		fns[0]: single,
		fns[1]: nil,
	}}

	require.NotPanics(t, func() { sortOutEdges(g) })
	require.Len(t, single.Out, 1)
}
