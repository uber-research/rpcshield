package graph

import (
	"go/ast"
	"go/types"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uber-research/rpcshield/go/common/edgeinfo"
	"github.com/uber-research/rpcshield/go/common/mapper"
	"github.com/uber-research/rpcshield/go/finder"
	"github.com/uber-research/rpcshield/go/finder/servicemapping"
	fty "github.com/uber-research/rpcshield/go/finder/types"
	"github.com/uber-research/rpcshield/go/grail"
	"github.com/uber-research/rpcshield/go/rpcshieldtest"
	"github.com/uber-research/rpcshield/go/rta/rtatest"
	"go.uber.org/zap"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// _rpcshieldDemoPaths is the set of expected canonical SSA call paths (Caller.Func.String()
// concatenated with each Callee.Func.String()) through rpcshielddemo's Get/Create RPCs, discovered
// by running TestE2E against the fixture (see the DISCOVERY log fallback below).
var _rpcshieldDemoPaths = map[string]struct{}{
	"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/handler.handler).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).failCloseDemo" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/gateway/lottery.gateway).Play": {},
	"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/handler.handler).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).failOpenDemo" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/gateway/lottery.gateway).Play": {},
	"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/handler.handler).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).failCloseAnnotationDemo" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/gateway/lottery.gateway).Play": {},
	"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/handler.handler).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).failOpenAnnotationDemo" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/gateway/lottery.gateway).Play": {},
	"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/handler.handler).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).suppressFailCloseAnnotationDemo" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/gateway/lottery.gateway).Play": {},
	"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/handler.handler).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).boundExample$bound" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).boundExample" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/gateway/lottery.gateway).Play": {},
	"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/handler.handler).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).errGroupDemo" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).errGroupDemo$1" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/gateway/lottery.gateway).Play": {},
	"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/handler.handler).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).anonymousFuncDemo" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).anonymousFuncDemo$1" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/gateway/lottery.gateway).Play": {},
	// Create's real go.uber.org/cff Flow, reachable from each of the 3 handlers implementing the
	// generated YARPC/Thrift server interfaces (see enrichWithCFFCall/processCFFEnqueueCall).
	"(github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/handler.valueReceiverHandler).Create" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Create" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Create$1" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Create$1$8" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Create$1$2" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/gateway/lottery.gateway).Play": {},
	"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/handler.handler).Create" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Create" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Create$1" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Create$1$8" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Create$1$2" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/gateway/lottery.gateway).Play": {},
	"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/handler/thrifthandler.handler).Create" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Create" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Create$1" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Create$1$8" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Create$1$2" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/gateway/lottery.gateway).Play": {},
}

// _rpcshieldDemoAllPaths is the full set of canonical SSA call paths through rpcshielddemo's
// Get/Create RPCs (unlike _rpcshieldDemoPaths, not restricted to a single debug-regexp'd entry
// point), used by TestCCT which builds paths from every inbound.
var _rpcshieldDemoAllPaths = map[string]struct{}{
	"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/handler/thrifthandler.handler).Create" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Create" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Create$1" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Create$1$8" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Create$1$2" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/gateway/lottery.gateway).Play": {},
	"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/handler.handler).Create" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Create" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Create$1" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Create$1$8" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Create$1$2" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/gateway/lottery.gateway).Play": {},
	"(github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/handler.valueReceiverHandler).Create" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Create" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Create$1" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Create$1$8" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Create$1$2" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/gateway/lottery.gateway).Play": {},
	"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/handler.handler).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).failCloseDemo" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/gateway/lottery.gateway).Play": {},
	"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/handler.handler).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).failOpenDemo" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/gateway/lottery.gateway).Play": {},
	"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/handler.handler).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).failCloseAnnotationDemo" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/gateway/lottery.gateway).Play": {},
	"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/handler.handler).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).failOpenAnnotationDemo" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/gateway/lottery.gateway).Play": {},
	"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/handler.handler).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).suppressFailCloseAnnotationDemo" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/gateway/lottery.gateway).Play": {},
	"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/handler.handler).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).boundExample$bound" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).boundExample" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/gateway/lottery.gateway).Play": {},
	"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/handler.handler).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).errGroupDemo" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).errGroupDemo$1" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/gateway/lottery.gateway).Play": {},
	"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/handler.handler).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).anonymousFuncDemo" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).anonymousFuncDemo$1" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/gateway/lottery.gateway).Play": {},
	"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/handler.handler).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).httpservicefooDemo" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/gateway/httpservicefoo.gateway).Call": {},
	"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/handler.handler).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).httpservicefooDemo" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/gateway/httpservicefoo.gateway).Call" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/util/wrappedclient.Client).Do": {},
	"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/handler.handler).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Get" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).httpservicefooDemo" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/gateway/httpservicefoo.gateway).Call" +
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/util/httpclient.Client).Do": {},
}

var _rpcshieldDemoGoGetPath = [][]string{
	{
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/handler.handler).Get",
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Get",
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).Get$1",
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/controller.controller).failCloseDemo",
		"(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/gateway/lottery.gateway).Play",
	},
}

func commonSetup(t *testing.T, rta bool) Builder {
	return commonSetupWithConfig(t, rta, DefaultSerialGraphConfig())
}

func commonSetupWithConfig(t *testing.T, rta bool, cfg Config) Builder {
	testPkg := rpcshieldtest.LoadrpcshieldDemoPackages()
	entryPkg, allPkgs, ssaProg, ssaPkgs := testPkg.Entry, testPkg.All, testPkg.SSAProg, testPkg.SSAPkgs
	// Produce SSA to AST mapping.
	SSAASTBidirMap := mapper.SSAToASTMap(allPkgs, ssaPkgs, ssaProg)
	SigASTBidirMap := mapper.SignatureToASTMap(allPkgs)
	isGlue := true
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
	var filteredOutbounds []fty.OutboundPoint
	for _, ob := range outbounds {
		if ob.Type != fty.TypeHTTP {
			filteredOutbounds = append(filteredOutbounds, ob)
		}
	}
	outbounds = filteredOutbounds
	require.NoError(t, err)
	require.NotEmpty(t, outbounds)

	// Now, create a graph builder with CHA.
	b := NewBuilder(logger, allPkgs, ssaProg, ssaPkgs, SSAASTBidirMap, SigASTBidirMap, isGlue, entryPkg, inbounds, outbounds, rta, cfg)
	return b
}

// TestFindEnclosingFunction tests the findEnclosingFunction function, including error cases.
func TestFindEnclosingFunction(t *testing.T) {
	b := commonSetup(t, false)
	require.NotNil(t, b)
	chaBuilder := b.(*builderImpl)
	// Build the graph.
	err := chaBuilder.setSSAInOutBounds()
	require.NoError(t, err)
	// Lengths of SSA inbounds and outbounds should be the same the ones given to the builder.
	require.Equal(t, len(chaBuilder.inbounds), len(chaBuilder.inboundsSSA))
	require.Equal(t, len(chaBuilder.outbounds), len(chaBuilder.outboundsSSA))

	// Now, create a graph builder with RTA
	b2 := commonSetup(t, true)
	require.NotNil(t, b2)
	rtaBuilder := b2.(*builderImpl)
	err = rtaBuilder.setSSAInOutBounds()
	require.NoError(t, err)
	require.Equal(t, len(rtaBuilder.inbounds), len(rtaBuilder.inboundsSSA))
	require.Equal(t, len(rtaBuilder.outbounds), len(rtaBuilder.outboundsSSA))

	// Now exercise corner cases.
	// 1. set empty sig2ast.StoA.
	oldsig2ast := rtaBuilder.sig2ast
	rtaBuilder.sig2ast = mapper.SignatureASTMap{
		StoA: make(map[*types.Signature]ast.Node),
		AtoS: make(map[ast.Node]*types.Signature),
	}
	_, err = rtaBuilder.populateSSAInbounds()
	require.Error(t, err)
	err = rtaBuilder.setSSAInOutBounds()
	require.Error(t, err)
	// restore sig2ast.
	rtaBuilder.sig2ast = oldsig2ast
	// Set empty ssa2ast.StoA.
	oldssa2ast := rtaBuilder.ssa2ast
	rtaBuilder.ssa2ast = mapper.SSAASTMap{
		StoA: make(map[*ssa.Function]ast.Node),
		AtoS: make(map[ast.Node]*ssa.Function),
	}
	_, err = rtaBuilder.populateSSAInbounds()
	require.Error(t, err)
	err = rtaBuilder.setSSAInOutBounds()
	require.Error(t, err)
	_, err = rtaBuilder.populateSSAOutbounds()
	require.Error(t, err)
	// restore ssa2ast.
	rtaBuilder.ssa2ast = oldssa2ast
}

func TestE2E(t *testing.T) {
	// Now, create a graph builder with CHA.
	// get envvar to set the debug function regexp
	t.Setenv(_debugFunRegexpEnv, `^\(\*.*rpcshielddemo\.handler\)\.Get$`)
	b := commonSetup(t, true)
	require.NotNil(t, b)
	paths, buildResult, err := b.Build()
	require.NoError(t, err)
	if len(_rpcshieldDemoPaths) == 0 {
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
	require.Len(t, paths, len(_rpcshieldDemoPaths))
	for _, path := range paths {
		canonocalPath := path.Edges[0].Edge.Caller.Func.String()
		for _, edge := range path.Edges {
			if edge.Edge.Callee != nil {
				canonocalPath += edge.Edge.Callee.Func.String()
			}
		}
		require.Contains(t, _rpcshieldDemoPaths, canonocalPath)
	}
	require.NotNil(t, buildResult)
}

// TestE2EVTA runs the same rpcshielddemo scenario as TestE2E under the VTA flavor.
// The demo service is wired by fx, so the paths it asserts only exist if VTA's
// reflection model reconnects dependency-injected values (see rpcshield/vta).
// The exact-count assertion is the point: it catches both paths VTA drops and
// noise it adds.
func TestE2EVTA(t *testing.T) {
	t.Setenv(_debugFunRegexpEnv, `^\(\*.*rpcshielddemo\.handler\)\.Get$`)
	b := commonSetupWithConfig(t, true /* rta */, Config{RTAFlavor: FlavorVTA, RTANumWorkers: runtime.GOMAXPROCS(0)})
	require.NotNil(t, b)
	paths, buildResult, err := b.Build()
	require.NoError(t, err)
	require.Len(t, paths, len(_rpcshieldDemoPaths))
	for _, path := range paths {
		canonicalPath := path.Edges[0].Edge.Caller.Func.String()
		for _, edge := range path.Edges {
			if edge.Edge.Callee != nil {
				canonicalPath += edge.Edge.Callee.Func.String()
			}
		}
		require.Contains(t, _rpcshieldDemoPaths, canonicalPath)
	}
	require.NotNil(t, buildResult)
}

func TestE2EParallel(t *testing.T) {
	// get envvar to set the debug function regexp
	t.Setenv(_debugFunRegexpEnv, `^\(\*.*rpcshielddemo\.handler\)\.Get$`)

	// Setup
	testPkg := rpcshieldtest.LoadrpcshieldDemoPackages()
	entryPkg, allPkgs, ssaProg, ssaPkgs := testPkg.Entry, testPkg.All, testPkg.SSAProg, testPkg.SSAPkgs
	// Produce SSA to AST mapping.
	SSAASTBidirMap := mapper.SSAToASTMap(allPkgs, ssaPkgs, ssaProg)
	SigASTBidirMap := mapper.SignatureToASTMap(allPkgs)
	isGlue := true
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
	var filteredOutbounds []fty.OutboundPoint
	for _, ob := range outbounds {
		if ob.Type != fty.TypeHTTP {
			filteredOutbounds = append(filteredOutbounds, ob)
		}
	}
	outbounds = filteredOutbounds
	require.NoError(t, err)
	require.NotEmpty(t, outbounds)

	// Now, create a parallel RTA graph builder
	b := NewBuilder(
		logger, allPkgs, ssaProg, ssaPkgs, SSAASTBidirMap, SigASTBidirMap, isGlue, entryPkg, inbounds, outbounds,
		true /* rta */, DefaultSerialGraphConfig())

	require.NotNil(t, b)
	paths, buildResult, err := b.Build()
	require.NoError(t, err)
	require.Len(t, paths, len(_rpcshieldDemoPaths))
	for _, path := range paths {
		canonocalPath := path.Edges[0].Edge.Caller.Func.String()
		for _, edge := range path.Edges {
			if edge.Edge.Callee != nil {
				canonocalPath += edge.Edge.Callee.Func.String()
			}
		}
		require.Contains(t, _rpcshieldDemoPaths, canonocalPath)
	}
	require.NotNil(t, buildResult)
}

func TestWrapCallPaths(t *testing.T) {
	// Test successful case
	t.Setenv(_debugFunRegexpEnv, `^\(\*.*rpcshielddemo\.handler\)\.Get$`)
	b := commonSetup(t, true)
	require.NotNil(t, b)
	paths, buildResult, err := b.Build()
	require.NotNil(t, buildResult)
	require.NoError(t, err)
	require.Len(t, paths, len(_rpcshieldDemoPaths))

	extractedCallPaths := make([][]*edgeinfo.EdgeInfo, 0, len(paths))
	for _, path := range paths {
		extractedCallPaths = append(extractedCallPaths, path.Edges)
	}

	// Test when inbound is not found
	bi, ok := b.(*builderImpl)
	require.True(t, ok)
	originalInboundMap := bi.inboundMap
	bi.inboundMap = make(map[*ssa.Function]inbound)
	_, err = bi.wrapCallPathsWithIBOB(extractedCallPaths)
	require.Error(t, err)
	bi.inboundMap = originalInboundMap

	// Test when outbound is not found
	bi, ok = b.(*builderImpl)
	require.True(t, ok)
	originalOutboundMap := bi.outboundMap
	bi.outboundMap = make(map[*ssa.Function]outbound)
	_, err = bi.wrapCallPathsWithIBOB(extractedCallPaths)
	require.Error(t, err)
	bi.outboundMap = originalOutboundMap

	// Test path is empty in call path
	extractedCallPaths[0] = []*edgeinfo.EdgeInfo{}
	wrappedPaths, err := bi.wrapCallPathsWithIBOB(extractedCallPaths)
	require.NoError(t, err)
	require.Len(t, wrappedPaths, len(extractedCallPaths)-1)

	hash := paths[0].Hash()
	require.NotEmpty(t, hash)
}

func TestEdgeToEdgeInfo(t *testing.T) {
	paths := [][]*callgraph.Edge{
		{
			{},
			{},
		},
		{
			{},
		},
	}
	builder := NewBuilder(zap.NewNop().Sugar(), nil, nil, nil, mapper.SSAASTMap{}, mapper.SignatureASTMap{}, false, nil, nil, nil, false, DefaultSerialGraphConfig())
	b := builder.(*builderImpl)
	infos := b.edgeToEdgeInfo(paths)
	require.Len(t, infos, 2)
	require.Len(t, infos[0], 2)
	require.Len(t, infos[1], 1)
}

func TestGoCallPaths(t *testing.T) {
	t.Setenv(_debugFunRegexpEnv, `^\(\*.*rpcshielddemo\.handler\)\.Get$`)
	b := commonSetup(t, true)
	require.NotNil(t, b)
	bi, _ := b.(*builderImpl)
	_, goPaths, _, err := bi.getCallPathsAndCallGraph()
	require.NoError(t, err)
	require.NotNil(t, goPaths)
	if len(_rpcshieldDemoGoGetPath) == 0 {
		for _, path := range goPaths {
			var callers []string
			for _, edge := range path.Edges {
				callers = append(callers, edge.Edge.Caller.Func.String())
			}
			t.Logf("DISCOVERY goPath=%#v", callers)
		}
	}
	require.Len(t, goPaths, len(_rpcshieldDemoGoGetPath))
	// The order of items in goPath vs. _rpcshieldDemoGoGetPath may not be the same, so we need to compare the content.
	for _, path := range goPaths {
		found := false
	NEXT_PATH:
		for _, expectedPath := range _rpcshieldDemoGoGetPath {
			if len(path.Edges) == len(expectedPath) {
				for i, edge := range path.Edges {
					if edge.Edge.Caller.Func.String() != expectedPath[i] {
						continue NEXT_PATH
					}
				}
				found = true
			}
		}
		require.True(t, found)
	}
}

func TestCreateAndRegisterAsyncEdge(t *testing.T) {
	t.Parallel()

	builder := &builderImpl{
		asyncSites: map[ssa.CallInstruction]struct{}{},
	}

	site1 := &mockCallInstruction{}
	site2 := &mockCallInstruction{}
	edge1 := &callgraph.Edge{Site: site1}
	edge2 := &callgraph.Edge{Site: site2}

	edges := map[*callgraph.Edge]struct{}{
		edge1: {},
		edge2: {},
	}
	builder.createAndRegisterAsyncEdge(edges)

	// Verify both call sites are registered.
	_, ok := builder.asyncSites[site1]
	assert.True(t, ok, "site1 should be registered as async")
	_, ok = builder.asyncSites[site2]
	assert.True(t, ok, "site2 should be registered as async")

	// Verify a non-registered site is not present.
	unregistered := &mockCallInstruction{}
	_, ok = builder.asyncSites[unregistered]
	assert.False(t, ok, "unregistered site should not be async")
}

func TestHasAsyncEdge(t *testing.T) {
	t.Parallel()

	asyncSite := &mockCallInstruction{}
	nonAsyncSite := &mockCallInstruction{}

	builder := &builderImpl{
		asyncSites: map[ssa.CallInstruction]struct{}{
			asyncSite: {},
		},
	}

	t.Run("path with async enricher edge", func(t *testing.T) {
		path := []*edgeinfo.EdgeInfo{
			{Edge: &callgraph.Edge{Site: nonAsyncSite}},
			{Edge: &callgraph.Edge{Site: asyncSite}},
		}
		assert.True(t, builder.hasAsyncEdge(path))
	})

	t.Run("path without async edge", func(t *testing.T) {
		path := []*edgeinfo.EdgeInfo{
			{Edge: &callgraph.Edge{Site: nonAsyncSite}},
		}
		assert.False(t, builder.hasAsyncEdge(path))
	})

	t.Run("empty path", func(t *testing.T) {
		assert.False(t, builder.hasAsyncEdge(nil))
	})
}

func TestAddCGEdgesWithAsyncRegistration(t *testing.T) {
	t.Parallel()

	cg := callgraph.New(nil)
	fA := &ssa.Function{}
	fB := &ssa.Function{}
	nodeA := cg.CreateNode(fA)
	cg.CreateNode(fB)

	callInst := &mockCallInstruction{}
	callsites := map[ssa.CallInstruction]map[*ssa.Function]struct{}{
		callInst: {fB: {}},
	}

	builder := &builderImpl{
		asyncSites: map[ssa.CallInstruction]struct{}{},
	}
	_, newEdges := builder.addCGEdges(callsites, nodeA, cg, false)
	require.Len(t, newEdges, 1)

	// addCGEdges with registerAsAsync=false should NOT register async sites.
	_, ok := builder.asyncSites[callInst]
	assert.False(t, ok, "addCGEdges with registerAsAsync=false should not register async sites")

	// addCGEdges with registerAsAsync=true should register async sites.
	callInst2 := &mockCallInstruction{}
	callsites2 := map[ssa.CallInstruction]map[*ssa.Function]struct{}{
		callInst2: {fB: {}},
	}
	_, newEdges2 := builder.addCGEdges(callsites2, nodeA, cg, true)
	require.Len(t, newEdges2, 1)
	_, ok = builder.asyncSites[callInst2]
	assert.True(t, ok, "addCGEdges with registerAsAsync=true should register call sites as async")
}

func TestIsAsyncOnCallPaths(t *testing.T) {
	t.Setenv(_debugFunRegexpEnv, `^\(\*.*rpcshielddemo\.handler\)\.Get$`)
	b := commonSetup(t, true)
	require.NotNil(t, b)
	bi, _ := b.(*builderImpl)

	nonGoPaths, goPaths, _, err := bi.getCallPathsAndCallGraph()
	require.NoError(t, err)

	// All go paths should have IsAsync = true.
	for _, path := range goPaths {
		assert.True(t, path.IsAsync, "go call path should be async: %s", path.Hash())
	}

	// Non-go paths that go through CFF/errgroup enriched edges should also be async.
	asyncCount := 0
	for _, path := range nonGoPaths {
		if path.IsAsync {
			asyncCount++
		}
	}
	// The rpcshielddemo app has CFF and errgroup enriched paths, so we expect some async non-go paths.
	assert.Greater(t, asyncCount, 0, "expected some non-go paths to be async due to CFF/errgroup enrichment")

	// Verify the metric is set.
	assert.Contains(t, bi.metrics, "asyncCallpaths")
	assert.Greater(t, bi.metrics["asyncCallpaths"], float64(0))
}

// TestReadDebugFunRegexp tests the readDebugFunRegexp function, including error cases.
func TestReadDebugFunRegexp(t *testing.T) {
	// Unset the environment variable to simulate the case where it's not set
	// get the original value to restore it later
	originalValue := os.Getenv(_debugFunRegexpEnv)
	defer os.Setenv(_debugFunRegexpEnv, originalValue)
	os.Unsetenv(_debugFunRegexpEnv)
	reg, err := readDebugFunRegexp("")
	require.NoError(t, err, "No error should be returned when the env var is not set")
	assert.Nil(t, reg, "Regexp should be nil when the env var is not set")

	// Set the environment variable to a valid regexp
	os.Setenv(_debugFunRegexpEnv, `foo.*`)

	reg, err = readDebugFunRegexp("")
	require.NoError(t, err, "No error should be returned for a valid regexp")
	require.NotNil(t, reg, "Regexp should not be nil for a valid regexp")
	assert.True(t, reg.MatchString("foobar"), "The regexp should match 'foobar'")
	// Set the environment variable to an invalid regexp
	os.Setenv(_debugFunRegexpEnv, `foo[`)
	reg, err = readDebugFunRegexp("")
	require.Error(t, err, "An error should be returned for an invalid regexp")
	assert.Nil(t, reg, "Regexp should be nil for an invalid regexp")
}

func TestMain(m *testing.M) {
	rtatest.SetupGoSDK()
	os.Exit(m.Run())
}
