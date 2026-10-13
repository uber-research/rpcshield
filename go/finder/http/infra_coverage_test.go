package http

import (
	"go/types"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/uber-research/rpcshield/go/common/mapper"
	fty "github.com/uber-research/rpcshield/go/finder/types"
	"github.com/uber-research/rpcshield/go/grail"
	"github.com/uber-research/rpcshield/go/loader"
	"go.uber.org/zap"
	"golang.org/x/tools/go/ssa"
)

const muxinfraPkg = "github.com/uber-research/rpcshield/go/exampleapps/muxinfra"

// testEmbeddedRouterProvider is a minimal, framework-agnostic MuxProvider used to
// exercise the shared inbound-finder infra:
//   - the router-value-following logic (registrations reached through a
//     field-addressed embedded sub-router value), and
//   - the ssa.MakeInterface unwrapping in the handler parser (interface-boxed
//     http.HandlerFunc handlers).
//
// It matches the hermetic muxinfra example app, which reproduces both SSA shapes
// using only net/http handler signatures, so no real framework dependency is
// needed to cover the generalized machinery.
type testEmbeddedRouterProvider struct {
	baseProvider

	handlerParser  *HandlerParser
	endpointParser *EndpointParser
}

func newTestEmbeddedRouterProvider(logger *zap.SugaredLogger, service grail.Service, codebase *fty.Codebase) *testEmbeddedRouterProvider {
	return &testEmbeddedRouterProvider{
		baseProvider: baseProvider{
			logger:   logger,
			service:  service,
			codebase: codebase,
		},
		handlerParser:  NewHandlerParser(logger, codebase),
		endpointParser: NewEndpointParser(UnknownEndpoint),
	}
}

var _ MuxProvider = (*testEmbeddedRouterProvider)(nil)

// MatchMuxRouterType matches both the outer router and its embedded group. The
// embedded group is the derived router value the value-following logic recurses
// into.
func (p *testEmbeddedRouterProvider) MatchMuxRouterType(val ssa.Value) bool {
	s := val.Type().String()
	return s == "*"+muxinfraPkg+".router" || s == "*"+muxinfraPkg+".group"
}

// MatchMuxCreation matches the newRouter() constructor call.
func (p *testEmbeddedRouterProvider) MatchMuxCreation(instr ssa.Instruction) bool {
	call, ok := instr.(*ssa.Call)
	if !ok {
		return false
	}
	if call.Call.Method != nil {
		return false
	}
	fn, ok := call.Call.Value.(*ssa.Function)
	if !ok || fn.Pkg == nil {
		return false
	}
	return fn.Pkg.Pkg.Path() == muxinfraPkg && fn.Name() == "newRouter"
}

// MatchHandlerRegistration matches HandleFunc/Handle method calls and extracts
// the inbound point via the shared handler/endpoint parsers.
func (p *testEmbeddedRouterProvider) MatchHandlerRegistration(instr ssa.Instruction) ([]fty.InboundPoint, bool) {
	call, ok := instr.(*ssa.Call)
	if !ok {
		return nil, false
	}
	fn, ok := call.Call.Value.(*ssa.Function)
	if !ok || fn.Signature.Recv() == nil {
		return nil, false
	}
	if name := fn.Name(); name != "HandleFunc" && name != "Handle" {
		return nil, false
	}
	// recv, pattern, handler
	if len(call.Call.Args) != 3 {
		return nil, false
	}

	endpoint := p.endpointParser.ParseEndpointWithDefault(call.Call.Args[1])
	handlers, err := p.handlerParser.ParseHandleFuncs(call.Call.Args[2])
	if err != nil {
		return nil, false
	}

	ibs := make([]fty.InboundPoint, len(handlers))
	for i, h := range handlers {
		ibs[i] = fty.InboundPoint{
			Service:       p.service,
			Func:          h.obj,
			Pkg:           h.pkg,
			CanonicalName: canonicalName(endpoint, h),
		}
	}
	return ibs, true
}

// TestHTTPInboundFinder__EmbeddedRouterAndInterfaceBoxing covers the generalized
// inbound-finder infra: registrations reached through a field-addressed embedded
// sub-router (router-value-following) and interface-boxed handlers (MakeInterface
// unwrapping). Both are validated against the hermetic muxinfra example app.
func TestHTTPInboundFinder__EmbeddedRouterAndInterfaceBoxing(t *testing.T) {
	t.Parallel()

	logger := zap.NewExample().Sugar()
	dummyService := grail.Service{Name: "muxinfra-testdata", Tier: 1}

	ssaProg, entryPkg, allPkgs, err := loader.LoadSSAWithGoPath(
		"rpcshield",
		[]string{"exampleapps", "muxinfra", "muxinfra-anal"},
		"github.com/uber-research/rpcshield/go/exampleapps/muxinfra",
	)
	require.NoError(t, err)

	codebase, err := fty.NewCodebase(logger, entryPkg, allPkgs, map[string]bool{} /* keepPkgs */)
	require.NoError(t, err)

	muxProviders := []MuxProvider{
		newTestEmbeddedRouterProvider(logger, dummyService, codebase),
	}
	hf := NewInboundFinder(logger, muxProviders)
	ibs, err := hf.Find(dummyService, ssaProg)
	require.NoError(t, err)

	type InboundRepr struct {
		PkgPath       string
		FullFuncName  string
		CanonicalName string
	}

	expected := []InboundRepr{
		// Reached through the embedded (promoted) group -> router-value-following.
		{PkgPath: muxinfraPkg, FullFuncName: muxinfraPkg + ".homeHandler", CanonicalName: "/promoted"},
		// Interface-boxed http.HandlerFunc -> MakeInterface unwrapping.
		{PkgPath: muxinfraPkg, FullFuncName: muxinfraPkg + ".pingHandler", CanonicalName: "/boxed"},
		// Interface-typed method value -> the source-less leaf (net/http's
		// abstract Handler.ServeHTTP) is resolved to the concrete codebase
		// implementation. embedHandler also implements http.Handler, but only
		// through a promoted net/http method, so it is filtered out.
		{PkgPath: muxinfraPkg, FullFuncName: "(" + muxinfraPkg + ".appHandler).ServeHTTP", CanonicalName: "/ifacevalue"},
		// NOTE: "/wrapped" (a call whose candidates are all empty) and
		// "/sourceless" (a method value on *http.ServeMux) intentionally yield
		// no inbounds.
	}

	got := make([]InboundRepr, 0, len(ibs))
	s := mapper.SignatureToASTMap(allPkgs)
	for _, ib := range ibs {
		got = append(got, InboundRepr{
			PkgPath:       ib.Pkg.PkgPath,
			FullFuncName:  ib.Func.FullName(),
			CanonicalName: ib.CanonicalName,
		})
		if _, ok := s.StoA[ib.Func.Type().(*types.Signature)]; !ok {
			require.True(t, ok, "Could not find signature for inbound", ib)
		}
	}

	require.ElementsMatch(t, expected, got)
}
