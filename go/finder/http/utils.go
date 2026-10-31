package http

import (
	"fmt"
	"go/types"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

type handler struct {
	pkg *packages.Package
	obj *types.Func
}

// canonicalName constructs the canonical name for an HTTP inbound endpoint.
func canonicalName(endpoint string, h handler) string {
	return endpoint
}

// isResponseWriterType checks if the type is http.ResponseWriter
func isResponseWriterType(t types.Type) bool {
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}

	obj := named.Obj()
	return obj.Pkg() != nil && obj.Pkg().Path() == "net/http" && obj.Name() == "ResponseWriter"
}

// isRequestType checks if the type is *http.Request
func isRequestType(t types.Type) bool {
	ptr, ok := t.(*types.Pointer)
	if !ok {
		return false
	}

	named, ok := ptr.Elem().(*types.Named)
	if !ok {
		return false
	}

	obj := named.Obj()
	return obj.Pkg() != nil && obj.Pkg().Path() == "net/http" && obj.Name() == "Request"
}

func lookupMethod(t types.Type, methodName string, pkg *types.Package) (*types.Func, error) {
	obj, _, _ := types.LookupFieldOrMethod(t, false /* addressable */, pkg, methodName)
	if obj == nil {
		return nil, fmt.Errorf("method %q not found in type %q", methodName, t.String())
	}
	funcObj, ok := obj.(*types.Func)
	if !ok {
		return nil, fmt.Errorf("method %q is not a function in type %q", methodName, t.String())
	}
	return funcObj, nil
}

func unwrapFuncObj(f *ssa.Function) *types.Func {
	obj := f.Object()
	if v, ok := obj.(*types.Func); ok {
		return v
	}

	if f.Pkg == nil || f.Pkg.Pkg == nil {
		return nil
	}

	return types.NewFunc(f.Pos(), f.Pkg.Pkg, f.Name(), f.Signature)
}

// isHTTPHandlerFuncSignatureRelaxed checks if the signature is a valid net/http handler
// signature using the following heuristic:
//
//	Signature must contain at least http.ResponseWriter and *http.Request parameters, in any order
//
// This is useful for flagging handlers that take in additional parameters, like
// a context (which is quite common in large codebases).
func isHTTPHandlerFuncSignatureRelaxed(sig *types.Signature) bool {
	params := sig.Params()
	if params.Len() < 2 {
		return false
	}

	hasResponseWriter := false
	hasRequest := false

	// Check all parameters to find ResponseWriter and Request in any order
	for i := 0; i < params.Len(); i++ {
		param := params.At(i)
		paramType := param.Type()

		if isResponseWriterType(paramType) {
			hasResponseWriter = true
		} else if isRequestType(paramType) {
			hasRequest = true
		}

		// Early exit if we found both
		if hasResponseWriter && hasRequest {
			return true
		}
	}

	return hasResponseWriter && hasRequest

}
