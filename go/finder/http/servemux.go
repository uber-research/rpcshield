package http

import (
	fty "github.com/uber-research/rpcshield/go/finder/types"
	"github.com/uber-research/rpcshield/go/grail"
	"go.uber.org/zap"
	"golang.org/x/tools/go/ssa"
)

// ServeMuxProvider implements the MuxProvider interface for the standard library
// net/http.ServeMux. It recognises routers created via http.NewServeMux() and
// routes registered via (*ServeMux).HandleFunc and (*ServeMux).Handle.
//
// It reuses the shared HandlerParser and EndpointParser unchanged: net/http
// handlers have the same func(http.ResponseWriter, *http.Request) signature that
// the gorilla provider already relies on.
type ServeMuxProvider struct {
	baseProvider

	handlerParser  *HandlerParser
	endpointParser *EndpointParser
}

// NewServeMuxProvider creates a new ServeMuxProvider instance.
func NewServeMuxProvider(logger *zap.SugaredLogger, service grail.Service, codebase *fty.Codebase) *ServeMuxProvider {
	return &ServeMuxProvider{
		baseProvider: baseProvider{
			logger:   logger,
			service:  service,
			codebase: codebase,
		},
		handlerParser:  NewHandlerParser(logger, codebase),
		endpointParser: NewEndpointParser(UnknownEndpoint),
	}
}

var _ MuxProvider = (*ServeMuxProvider)(nil)

// MatchMuxRouterType checks if the value is a *net/http.ServeMux.
func (p *ServeMuxProvider) MatchMuxRouterType(val ssa.Value) bool {
	return val.Type().String() == "*net/http.ServeMux"
}

// MatchMuxCreation checks if the instruction is an http.NewServeMux() call.
func (p *ServeMuxProvider) MatchMuxCreation(instr ssa.Instruction) bool {
	call, ok := instr.(*ssa.Call)
	if !ok {
		return false
	}

	if call.Call.Method != nil {
		return false
	}

	fn, ok := call.Call.Value.(*ssa.Function)
	if !ok {
		return false
	}

	if fn.Pkg == nil {
		return false
	}

	return fn.Pkg.Pkg.Path() == "net/http" && fn.Name() == "NewServeMux"
}

// MatchHandlerRegistration checks if the instruction is a HandleFunc or Handle
// method call on a ServeMux and extracts the inbound point(s).
func (p *ServeMuxProvider) MatchHandlerRegistration(instr ssa.Instruction) (ib []fty.InboundPoint, ok bool) {
	call, ok := instr.(*ssa.Call)
	if !ok {
		return nil, false
	}

	fn, ok := call.Call.Value.(*ssa.Function)
	if !ok {
		return nil, false
	}

	if fn.Signature.Recv() == nil {
		return nil, false
	}

	// Both HandleFunc(pattern, handlerFunc) and Handle(pattern, handler) have the
	// same SSA arg shape: (receiver, pattern, handler).
	switch fn.Name() {
	case "HandleFunc", "Handle":
		return p.extractInbound(call)
	}

	return nil, false
}

func (p *ServeMuxProvider) extractInbound(call *ssa.Call) ([]fty.InboundPoint, bool) {
	// 3 because the first argument is the ServeMux receiver.
	if len(call.Call.Args) != 3 {
		return nil, false
	}

	endpointArg := call.Call.Args[1]
	handlerArg := call.Call.Args[2]

	endpoint := p.endpointParser.ParseEndpointWithDefault(endpointArg)
	handlers, err := p.handlerParser.ParseHandleFuncs(handlerArg)
	if err != nil {
		p.logger.Debugf("Could not extract ServeMux handler for %s (%T): %v", handlerArg.String(), handlerArg, err)
		return nil, false
	}

	ibs := make([]fty.InboundPoint, len(handlers))
	for i, handler := range handlers {
		ibs[i] = fty.InboundPoint{
			Service:       p.service,
			Func:          handler.obj,
			Pkg:           handler.pkg,
			CanonicalName: canonicalName(endpoint, handler),
		}
	}

	return ibs, true
}
