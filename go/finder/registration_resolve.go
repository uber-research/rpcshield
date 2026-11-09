package finder

// Resolving a registered value to the concrete types it may hold, and an interface method on
// such a type to the method that runs. The syntax is followed where it pins the value down
// (constructor returns, a single assignment, field stores); otherwise the type-keyed flows of
// registration_flows.go are the fallback.

import (
	"go/ast"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/types/typeutil"
)

const (
	// _maxFlowDepth bounds the interface-to-interface hops followed when resolving an interface
	// type to the concrete types that flow into it.
	_maxFlowDepth = 12
	// _maxResolveDepth bounds the resolution of an expression through constructor returns and
	// local variable assignments.
	_maxResolveDepth = 6
)

// concreteTypes returns the non-interface types that reach the interface type t through
// type-keyed flows, following interface-to-interface hops up to _maxFlowDepth.
//
//	flows: pb.KVServer <- *kvServer, ReadOnlyKV;   ReadOnlyKV <- *dbKV
//
//	concreteTypes(pb.KVServer)  -> [*kvServer, *dbKV]
//	concreteTypes(ReadOnlyKV)   -> [*dbKV]
//	concreteTypes(Unused)       -> []              nothing flows into it
//	concreteTypes(*kvServer)    -> [*kvServer]     a non-interface type is its own answer
//
// Type parameters are dropped: "var kv pb.KVServer = v" with v of type parameter T says nothing
// about concrete types. The result is in insertion order without duplicates, so callers'
// output is stable from run to run.
func (ix *registrationIndex) concreteTypes(t types.Type) []types.Type {
	var out typeSet
	seen := make(map[string]bool)
	var visit func(t types.Type, depth int)
	visit = func(t types.Type, depth int) {
		k := typeKey(t)
		if seen[k] || depth > _maxFlowDepth {
			return
		}
		seen[k] = true
		if !isInterfaceType(t) {
			if _, isParam := types.Unalias(t).(*types.TypeParam); !isParam {
				out.add(t)
			}
			return
		}
		if set := ix.flows[k]; set != nil {
			for _, src := range set.types {
				visit(src, depth+1)
			}
		}
	}
	visit(t, 0)
	return out.types
}

// exprTypes returns the concrete types the expression e may hold. scope is the top-level
// declaration e appears in; depth counts the resolution hops taken so far. e is the handler
// argument of a registration call, or an expression reached while resolving one.
//
//	pb.RegisterKVServer(s, &kvServer{})     -> [*kvServer]                non-interface: its static type
//	pb.RegisterKVServer(s, newKV())         -> newKV's return statements  (returnedTypes)
//	srv := newKV(); pb.RegisterKVServer(s, srv)
//	                                        -> through srv's only assignment (localVarTypes)
//	pb.RegisterKVServer(s, app.kv)          -> the expressions stored into app.kv (fieldTypes)
//	pb.RegisterKVServer(s, params.KV)       params embeds fx.In: the field is open
//	                                        -> every type that flows into pb.KVServer (concreteTypes)
//	pb.RegisterKVServer(s, kvs[i])          -> no syntax rule: concreteTypes(pb.KVServer)
//	pb.RegisterKVServer(s, nil)             -> []
//	a value of type parameter T             -> []
//
// The static type decides first: a non-interface type is final. For an interface-typed
// expression the syntax is tried according to its node kind (call, identifier, selector) down to
// _maxResolveDepth hops, and the type-keyed flows are the fallback whenever the syntax does not
// pin the value down.
func (ix *registrationIndex) exprTypes(info *types.Info, scope ast.Node, e ast.Expr, depth int) []types.Type {
	e = ast.Unparen(e)
	t := info.TypeOf(e)
	if t == nil {
		return nil
	}
	if b, ok := types.Unalias(t).(*types.Basic); ok && (b.Kind() == types.UntypedNil || b.Kind() == types.Invalid) {
		return nil
	}
	if !isInterfaceType(t) {
		if _, isParam := types.Unalias(t).(*types.TypeParam); isParam {
			return nil
		}
		return []types.Type{t}
	}
	if depth < _maxResolveDepth {
		switch x := e.(type) {
		case *ast.CallExpr:
			if out, ok := ix.returnedTypes(info, x, 0, 1, depth); ok {
				return out
			}
		case *ast.Ident:
			if v, ok := info.Uses[x].(*types.Var); ok {
				if out, ok := ix.localVarTypes(info, scope, v, depth); ok {
					return out
				}
			}
		case *ast.SelectorExpr:
			if key, ok := selectedField(info, x); ok {
				if out, ok := ix.fieldTypes(key, t, depth); ok {
					return out
				}
			}
		}
	}
	return ix.concreteTypes(t)
}

// fieldTypes resolves the struct field key, declared with the interface type t, through the
// expressions stored into it anywhere in the program.
//
//	type App struct{ kv pb.KVServer }
//
//	a.kv = &kvServer{}            -> [*kvServer]
//	a := App{kv: newKV()}         -> newKV's return statements
//	a.kv, err = build()           -> result 0 of build's return statements; if build is not a
//	                                 declared, statically called function, every type that flows
//	                                 into pb.KVServer instead
//	a.kv = x; b.kv = y            -> the union over both stores (same field, possibly different
//	                                 functions)
//	no store anywhere             -> ok=false
//	p := &a.kv                    -> ok=false     open field: written through a pointer
//	type P struct{ fx.In; KV pb.KVServer }; p.KV
//	                              -> ok=false     open field: fx populates it
//
// ok=false sends the caller to concreteTypes(t).
func (ix *registrationIndex) fieldTypes(key string, t types.Type, depth int) (out []types.Type, ok bool) {
	stores := ix.fieldStores[key]
	if len(stores) == 0 || ix.openFields[key] {
		return nil, false
	}
	var set typeSet
	for _, s := range stores {
		var resolved []types.Type
		if s.index < 0 {
			resolved = ix.exprTypes(s.info, s.scope, s.expr, depth+1)
		} else {
			call, isCall := ast.Unparen(s.expr).(*ast.CallExpr)
			done := false
			if isCall {
				resolved, done = ix.returnedTypes(s.info, call, s.index, s.numResults, depth+1)
			}
			if !done {
				resolved = ix.concreteTypes(t)
			}
		}
		for _, r := range resolved {
			set.add(r)
		}
	}
	return set.types, true
}

// localVarTypes resolves the local variable v through its only assignment in scope, the
// top-level declaration v is used in.
//
//	srv := newKV()                       -> newKV's return statements
//	var srv pb.KVServer = &kvServer{}    -> [*kvServer]
//	srv, err := build()                  -> result 0 of build's return statements; ok=false if
//	                                        build is not a declared, statically called function
//	srv := a; srv = b                    -> ok=false   assigned twice
//	var srv pb.KVServer                  -> ok=false   declared, never assigned
//	p := &srv                            -> ok=false   address taken
//	for _, srv = range servers {}        -> ok=false   assigned by range
//	a parameter                          -> ok=false   no assignment in scope
//	a package-level variable, a field    -> ok=false   not local
//
// scope is walked once; every assignment statement and var declaration naming v counts as a
// definition, and only exactly one is accepted. ok=false sends the caller to the type-keyed
// fallback.
func (ix *registrationIndex) localVarTypes(info *types.Info, scope ast.Node, v *types.Var, depth int) (out []types.Type, ok bool) {
	if scope == nil || v.IsField() || v.Pkg() == nil || v.Parent() == v.Pkg().Scope() {
		return nil, false
	}
	var (
		rhs      ast.Expr
		index    int // result index if rhs is a call that yields several values, else -1
		numLHS   int
		numDefs  int
		escapes  bool
		isTarget = func(e ast.Expr) bool {
			id, isIdent := ast.Unparen(e).(*ast.Ident)
			return isIdent && (info.Defs[id] == v || info.Uses[id] == v)
		}
	)
	ast.Inspect(scope, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range x.Lhs {
				if !isTarget(lhs) {
					continue
				}
				numDefs++
				switch {
				case len(x.Lhs) == len(x.Rhs):
					rhs, index = x.Rhs[i], -1
				case len(x.Rhs) == 1:
					rhs, index, numLHS = x.Rhs[0], i, len(x.Lhs)
				}
			}
		case *ast.ValueSpec:
			for i, name := range x.Names {
				if info.Defs[name] != v {
					continue
				}
				numDefs++
				switch {
				case len(x.Values) == len(x.Names):
					rhs, index = x.Values[i], -1
				case len(x.Values) == 1:
					rhs, index, numLHS = x.Values[0], i, len(x.Names)
				}
			}
		case *ast.RangeStmt:
			if (x.Key != nil && isTarget(x.Key)) || (x.Value != nil && isTarget(x.Value)) {
				escapes = true
			}
		case *ast.UnaryExpr:
			if x.Op == token.AND && isTarget(x.X) {
				escapes = true
			}
		}
		return true
	})
	if escapes || numDefs != 1 || rhs == nil {
		return nil, false
	}
	if index < 0 {
		return ix.exprTypes(info, scope, rhs, depth+1), true
	}
	call, isCall := ast.Unparen(rhs).(*ast.CallExpr)
	if !isCall {
		return nil, false
	}
	return ix.returnedTypes(info, call, index, numLHS, depth)
}

// returnedTypes resolves result number index of a call of a statically known, non-generic
// function with numResults unnamed results, through that function's return statements.
//
//	func newKV() pb.KVServer { return &kvServer{} }
//	returnedTypes(newKV(), 0, 1)         -> [*kvServer]
//
//	func build(c Config) (pb.KVServer, error) {
//		if c.InMemory { return &memKV{}, nil }
//		return newDBKV(c), nil
//	}
//	returnedTypes(build(c), 0, 2)        -> [*memKV] plus newDBKV's return statements
//
//	returnedTypes(factory(), 0, 1)       factory is a variable or an interface method
//	                                     -> ok=false   no static callee
//	returnedTypes(lib.New(), 0, 1)       lib's source is not in the program
//	                                     -> ok=false   no declaration
//	func named() (srv pb.KVServer) { srv = &kvServer{}; return }
//	                                     -> ok=false   named results: a bare return carries the value
//	func gen[T any]() T                  -> ok=false   generic
//	func never() pb.KVServer { panic("x") }
//	                                     -> ok=false   no return statement
//
// Return statements inside function literals belong to the literal and are skipped. Each
// returned expression is resolved with exprTypes one hop deeper, so a constructor that returns
// another constructor's result is followed too.
func (ix *registrationIndex) returnedTypes(info *types.Info, call *ast.CallExpr, index, numResults, depth int) (out []types.Type, ok bool) {
	callee := typeutil.StaticCallee(info, call)
	if callee == nil {
		return nil, false
	}
	d, found := ix.decls[callee]
	if !found {
		return nil, false
	}
	sig := callee.Type().(*types.Signature)
	if sig.Results().Len() != numResults || sig.Results().At(0).Name() != "" || sig.TypeParams().Len() > 0 || sig.RecvTypeParams().Len() > 0 {
		return nil, false
	}
	var set typeSet
	resolved, numReturns := true, 0
	ast.Inspect(d.decl.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			numReturns++
			if len(x.Results) != numResults {
				resolved = false
				return false
			}
			for _, t := range ix.exprTypes(d.info, d.decl, x.Results[index], depth+1) {
				set.add(t)
			}
		}
		return resolved
	})
	if !resolved || numReturns == 0 {
		return nil, false
	}
	return set.types, true
}

// resolveMethod returns the concrete methods that a call of the server-interface method m on a
// value of type t runs. visited holds the types already resolved for m.
//
//	type kvServer struct{}; func (*kvServer) Get(...)
//	resolveMethod(*kvServer, Get)     -> [(*kvServer).Get]
//
//	type kvServer struct{ pb.UnimplementedKVServer }     Get is not overridden
//	resolveMethod(*kvServer, Get)     -> [(*pb.UnimplementedKVServer).Get]   (handlersOf drops it:
//	                                     declared in a generated file)
//
//	type quota struct{ pb.KVServer }                      a decorator: Get is promoted from an
//	quota{KVServer: &kvServer{}}                          embedded interface field
//	resolveMethod(quota, Get)         -> [(*kvServer).Get], through the values stored into
//	                                     quota.KVServer (fieldTypes); if that field is open,
//	                                     through every type that flows into pb.KVServer
//
//	type partial struct{}                                 lacks Get
//	resolveMethod(partial, Get)       -> []
//
// types.LookupFieldOrMethod yields the method and the embedding path. A method whose receiver is
// an interface is promoted: the path minus its last element names the embedded field. visited
// stops cycles such as a struct embedding an interface whose flows lead back to the struct.
func (ix *registrationIndex) resolveMethod(t types.Type, m *types.Func, visited map[string]bool) []*types.Func {
	if k := typeKey(t); visited[k] {
		return nil
	} else {
		visited[k] = true
	}
	obj, path, _ := types.LookupFieldOrMethod(t, true /* addressable */, m.Pkg(), m.Name())
	fn, ok := obj.(*types.Func)
	if !ok {
		return nil
	}
	recv := fn.Type().(*types.Signature).Recv()
	if recv == nil {
		return nil
	}
	if !isInterfaceType(recv.Type()) {
		return []*types.Func{fn}
	}
	// The method is promoted from an embedded interface field: path leads to that field and
	// ends with the method's index in the interface.
	var values []types.Type
	resolved := false
	if len(path) >= 2 {
		if key, ok := fieldKeyOf(t, path[:len(path)-1]); ok {
			values, resolved = ix.fieldTypes(key, recv.Type(), 0)
		}
	}
	if !resolved {
		values = ix.concreteTypes(recv.Type())
	}
	var out []*types.Func
	for _, c := range values {
		out = append(out, ix.resolveMethod(c, m, visited)...)
	}
	return out
}
