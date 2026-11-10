package finder

// Program facts gathered by one syntax walk, for registration-rooted detection: type-keyed
// flows (which static types reach each interface type) and struct-field stores (which
// expressions are written into each field).

import (
	"go/ast"
	"go/token"
	"go/types"
	"strconv"

	"golang.org/x/tools/go/types/typeutil"
)

// fieldStore is an expression stored into a struct field, by a composite literal or an
// assignment.
type fieldStore struct {
	info *types.Info
	// scope is the top-level declaration the store appears in.
	scope ast.Node
	expr  ast.Expr
	// index is the result number if expr is a call that yields numResults values, else -1.
	index, numResults int
}

// fieldKey identifies a field by its struct type and name.
//
//	type App struct{ kv pb.KVServer }    fieldKey(App's struct, "kv") -> "struct{kv example.com/pb.KVServer}.kv"
//	type App2 struct{ kv pb.KVServer }   same key: identical struct types are convertible to
//	                                     each other, so their fields share stores
func fieldKey(st *types.Struct, name string) string {
	return types.TypeString(st, nil) + "." + name
}

// fieldKeyOf returns the key of the field reached from a value of type recv through the field
// index path that types.Selection.Index or types.LookupFieldOrMethod report.
//
//	type Deps struct{ KV pb.KVServer }
//	type App struct{ deps Deps; *Logger; names []string }
//
//	fieldKeyOf(*App, [0])    -> App.deps                 one pointer is dereferenced per step
//	fieldKeyOf(*App, [0, 0]) -> Deps.KV                  path through a nested struct
//	fieldKeyOf(App, [1, 0])  -> Logger's first field     through an embedded pointer field
//	fieldKeyOf(App, [2, 0])  -> ok=false                 []string is not a struct
//	fieldKeyOf(Box[int], [0]) -> ok=false                instantiated generic: stores not tracked
//	fieldKeyOf(*App, [])     -> ok=false
func fieldKeyOf(recv types.Type, path []int) (key string, ok bool) {
	if len(path) == 0 {
		return "", false
	}
	cur := recv
	for n, i := range path {
		if ptr, isPtr := cur.Underlying().(*types.Pointer); isPtr {
			cur = ptr.Elem()
		}
		named, isNamed := types.Unalias(cur).(*types.Named)
		st, isStruct := cur.Underlying().(*types.Struct)
		if !isStruct || i >= st.NumFields() {
			return "", false
		}
		if n == len(path)-1 {
			if isNamed && named.TypeArgs().Len() > 0 {
				return "", false
			}
			return fieldKey(st, st.Field(i).Name()), true
		}
		cur = st.Field(i).Type()
	}
	return "", false
}

// typeSet is an insertion-ordered set of types, keyed by typeKey.
type typeSet struct {
	seen  map[string]bool
	types []types.Type
}

func (s *typeSet) add(t types.Type) {
	k := typeKey(t)
	if s.seen == nil {
		s.seen = make(map[string]bool)
	}
	if !s.seen[k] {
		s.seen[k] = true
		s.types = append(s.types, t)
	}
}

// typeKey returns a string that identifies t in the flow and visited maps.
//
//	*pb.KVServer                      -> "*example.com/pb.KVServer"
//	type S = pb.KVServer; S           -> "example.com/pb.KVServer"      aliases resolve to their target
//	func f() { type T struct{} }; T   -> "example.com/app.T@1203"       declaration position appended
//	func g() { type T struct{} }; T   -> "example.com/app.T@1457"
//
// Two function-local types named T in one package print identically with types.TypeString, so a
// named type whose declaring scope is not the package scope carries its declaration position.
// Strings are used instead of typeutil.Map so that the index does not depend on how the x/tools
// version in use hashes newer type kinds.
func typeKey(t types.Type) string {
	t = types.Unalias(t)
	key := types.TypeString(t, nil)
	if named, ok := t.(*types.Named); ok && named.Obj().Pkg() != nil && named.Obj().Parent() != named.Obj().Pkg().Scope() {
		key += "@" + strconv.Itoa(int(named.Obj().Pos()))
	}
	return key
}

// isInterfaceType reports whether values of type t are interface values.
//
//	pb.KVServer                      -> true
//	any                              -> true
//	*pb.KVServer                     -> false
//	T in func f[T pb.KVServer]()     -> false: a type parameter's underlying type is its
//	                                    constraint interface, but its values are not interfaces
func isInterfaceType(t types.Type) bool {
	if _, ok := types.Unalias(t).(*types.TypeParam); ok {
		return false
	}
	_, ok := t.Underlying().(*types.Interface)
	return ok
}

// flow records that an expression of static type src is used where the interface type dst is
// expected: a value of type src may be behind an interface value of type dst.
//
//	var kv pb.KVServer = &kvServer{}      -> flows[pb.KVServer] += *kvServer
//	var ro ReadOnlyKV = kv                -> flows[ReadOnlyKV] += pb.KVServer   (an interface hop;
//	                                         concreteTypes follows it)
//	var kv pb.KVServer = other            other also of type pb.KVServer: identical, nothing recorded
//	var x any = &kvServer{}               dst has no methods: nothing recorded
//	var kv pb.KVServer = nil              untyped nil: nothing recorded
//	kv, err = build()                     src would be a tuple: nothing recorded (callers split tuples)
func (ix *registrationIndex) flow(dst, src types.Type) {
	if dst == nil || src == nil || !isInterfaceType(dst) || types.Identical(dst, src) {
		return
	}
	if dst.Underlying().(*types.Interface).NumMethods() == 0 {
		return
	}
	switch s := types.Unalias(src).(type) {
	case *types.Basic:
		if s.Kind() == types.UntypedNil || s.Kind() == types.Invalid {
			return
		}
	case *types.Tuple:
		return
	}
	set := ix.flows[typeKey(dst)]
	if set == nil {
		set = &typeSet{}
		ix.flows[typeKey(dst)] = set
	}
	set.add(src)
}

// selectedField returns the key of the struct field e selects.
//
//	type App struct{ Deps; kv pb.KVServer }; type Deps struct{ log Logger }
//
//	a.kv            -> App.kv
//	a.log           -> Deps.log      promoted field: the selection's index path ends in Deps
//	(a.kv)          -> App.kv        parentheses are ignored
//	a.Close         -> ok=false      method, not field
//	pb.Something    -> ok=false      qualified identifier
//	a               -> ok=false      not a selector
//
// The type checker's Selection for e supplies the receiver type and index path for fieldKeyOf.
func selectedField(info *types.Info, e ast.Expr) (key string, ok bool) {
	sel, isSel := ast.Unparen(e).(*ast.SelectorExpr)
	if !isSel {
		return "", false
	}
	selection := info.Selections[sel]
	if selection == nil || selection.Kind() != types.FieldVal {
		return "", false
	}
	return fieldKeyOf(selection.Recv(), selection.Index())
}

// collectFlows walks root and records the type-keyed flows (flow) and the struct-field stores
// (fieldStores) it contains, and marks the fields whose stores cannot be trusted (openFields).
// scope is the top-level declaration root belongs to; sig is the signature of the function
// root is the body of, or nil for a non-function declaration.
//
// With "type App struct{ kv pb.KVServer }":
//
//	return &kvServer{}                  in func() pb.KVServer      -> flows[pb.KVServer] += *kvServer
//	return build()                      in func() (pb.KVServer, error), build() (pb.KVServer, error)
//	                                    -> the tuple is split result by result
//	a.kv = &kvServer{}                  -> fieldStores[App.kv] += &kvServer{}; flows[pb.KVServer] += *kvServer
//	a.kv, err = build()                 -> fieldStores[App.kv] += build() as result 0 of 2
//	kv := &kvServer{}                   ":=" gives kv the right-hand type: no flow, no store
//	p := &a.kv                          -> openFields[App.kv]      written through a pointer
//	for _, a.kv = range servers {}      -> openFields[App.kv]      written by range
//	type P struct{ fx.In; KV pb.KVServer }  -> openFields[P.KV]    populated by fx, not by stores
//	var kv pb.KVServer = &kvServer{}    -> flows[pb.KVServer] += *kvServer
//	var _ pb.KVServer = (*kvServer)(nil) -> nothing: a compile-time assertion, no value is kept
//	App{kv: &kvServer{}}                -> collectCompositeLitFlows
//	serve(&kvServer{}), pb.KVServer(x)  -> collectCallFlows
//
// Return statements are matched against the innermost enclosing function: a function literal's
// body is visited with its own signature pushed on sigs. The walk is a single ast.Inspect, so
// one pass over the program fills the whole index.
func (ix *registrationIndex) collectFlows(info *types.Info, scope ast.Node, sig *types.Signature, root ast.Node) {
	sigs := []*types.Signature{sig}
	var visit func(n ast.Node) bool
	visit = func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncLit:
			if litSig, ok := info.TypeOf(x).(*types.Signature); ok && x.Body != nil {
				sigs = append(sigs, litSig)
				ast.Inspect(x.Body, visit)
				sigs = sigs[:len(sigs)-1]
				return false
			}
		case *ast.ReturnStmt:
			cur := sigs[len(sigs)-1]
			if cur == nil {
				break
			}
			res := cur.Results()
			if res.Len() == len(x.Results) {
				for i, e := range x.Results {
					ix.flow(res.At(i).Type(), info.TypeOf(e))
				}
			} else if len(x.Results) == 1 {
				if tup, ok := info.TypeOf(x.Results[0]).(*types.Tuple); ok && tup.Len() == res.Len() {
					for i := 0; i < tup.Len(); i++ {
						ix.flow(res.At(i).Type(), tup.At(i).Type())
					}
				}
			}
		case *ast.AssignStmt:
			if x.Tok != token.ASSIGN {
				break
			}
			for i, lhs := range x.Lhs {
				key, ok := selectedField(info, lhs)
				if !ok {
					continue
				}
				switch {
				case len(x.Lhs) == len(x.Rhs):
					ix.fieldStores[key] = append(ix.fieldStores[key], fieldStore{info: info, scope: scope, expr: x.Rhs[i], index: -1})
				case len(x.Rhs) == 1:
					ix.fieldStores[key] = append(ix.fieldStores[key], fieldStore{info: info, scope: scope, expr: x.Rhs[0], index: i, numResults: len(x.Lhs)})
				default:
					ix.openFields[key] = true
				}
			}
			if len(x.Lhs) == len(x.Rhs) {
				for i := range x.Lhs {
					ix.flow(info.TypeOf(x.Lhs[i]), info.TypeOf(x.Rhs[i]))
				}
			} else if len(x.Rhs) == 1 {
				if tup, ok := info.TypeOf(x.Rhs[0]).(*types.Tuple); ok && tup.Len() == len(x.Lhs) {
					for i := range x.Lhs {
						ix.flow(info.TypeOf(x.Lhs[i]), tup.At(i).Type())
					}
				}
			}
		case *ast.UnaryExpr:
			if x.Op == token.AND {
				if key, ok := selectedField(info, x.X); ok {
					ix.openFields[key] = true
				}
			}
		case *ast.RangeStmt:
			for _, target := range []ast.Expr{x.Key, x.Value} {
				if target == nil {
					continue
				}
				if key, ok := selectedField(info, target); ok {
					ix.openFields[key] = true
				}
			}
		case *ast.StructType:
			st, ok := info.TypeOf(x).(*types.Struct)
			if !ok {
				break
			}
			for i := 0; i < st.NumFields(); i++ {
				if st.Field(i).Embedded() && isFxInType(st.Field(i).Type()) {
					for j := 0; j < st.NumFields(); j++ {
						ix.openFields[fieldKey(st, st.Field(j).Name())] = true
					}
					break
				}
			}
		case *ast.ValueSpec:
			if x.Type != nil && len(x.Values) == len(x.Names) {
				for i, v := range x.Values {
					// "var _ I = (*T)(nil)" asserts that T implements I; no value is kept.
					if x.Names[i].Name != "_" {
						ix.flow(info.TypeOf(x.Type), info.TypeOf(v))
					}
				}
			}
		case *ast.CompositeLit:
			ix.collectCompositeLitFlows(info, scope, x)
		case *ast.CallExpr:
			ix.collectCallFlows(info, x)
		}
		return true
	}
	ast.Inspect(root, visit)
}

// collectCompositeLitFlows records the flows and field stores a composite literal creates.
//
//	App{kv: &kvServer{}}                   -> fieldStores[App.kv] += &kvServer{}; flows[pb.KVServer] += *kvServer
//	App{&kvServer{}, logger}               -> positional: field 0, then field 1
//	[]pb.KVServer{&kvServer{}, &dbKV{}}    -> flows[pb.KVServer] += *kvServer, *dbKV
//	[2]pb.KVServer{1: &dbKV{}}             -> flows[pb.KVServer] += *dbKV       keyed element
//	map[string]pb.KVServer{"a": &dbKV{}}   -> flows[pb.KVServer] += *dbKV       values only
//	[]App{{kv: &dbKV{}}}                   -> the inner literal's type is elided in the source
//	                                          and taken from the type checker
//
// Pointers to literals (&App{...}) are literals wrapped in a unary expression, so they are
// visited the same way.
func (ix *registrationIndex) collectCompositeLitFlows(info *types.Info, scope ast.Node, lit *ast.CompositeLit) {
	t := info.TypeOf(lit)
	if t == nil {
		return
	}
	switch u := t.Underlying().(type) {
	case *types.Struct:
		store := func(field *types.Var, value ast.Expr) {
			ix.flow(field.Type(), info.TypeOf(value))
			key := fieldKey(u, field.Name())
			ix.fieldStores[key] = append(ix.fieldStores[key], fieldStore{info: info, scope: scope, expr: value, index: -1})
		}
		for i, el := range lit.Elts {
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				key, ok := kv.Key.(*ast.Ident)
				if !ok {
					continue
				}
				for j := 0; j < u.NumFields(); j++ {
					if u.Field(j).Name() == key.Name {
						store(u.Field(j), kv.Value)
					}
				}
			} else if i < u.NumFields() {
				store(u.Field(i), el)
			}
		}
	case *types.Slice:
		for _, el := range lit.Elts {
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				el = kv.Value
			}
			ix.flow(u.Elem(), info.TypeOf(el))
		}
	case *types.Array:
		for _, el := range lit.Elts {
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				el = kv.Value
			}
			ix.flow(u.Elem(), info.TypeOf(el))
		}
	case *types.Map:
		for _, el := range lit.Elts {
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				ix.flow(u.Elem(), info.TypeOf(kv.Value))
			}
		}
	}
}

// collectCallFlows records the flows a call expression creates: each argument into its
// parameter type, a conversion's operand into the converted-to type, and the fx.Annotate form.
//
//	serve(&kvServer{})            func serve(kv pb.KVServer)      -> flows[pb.KVServer] += *kvServer
//	serveAll(&kvServer{}, &dbKV{}) func serveAll(kvs ...pb.KVServer) -> flows[pb.KVServer] += *kvServer, *dbKV
//	serveAll(kvs...)              kvs already has type []pb.KVServer: nothing per element
//	pb.KVServer(x)                conversion                     -> flows[pb.KVServer] += type of x
//	fx.Annotate(newKV, fx.As(new(pb.KVServer)))   func newKV() *kvServer
//	                              -> flows[pb.KVServer] += *kvServer: fx provides newKV's result as pb.KVServer
//	fx.Annotate(newKV, fx.As(new(pb.KVServer), new(io.Closer)))
//	                              -> one flow per interface that the result type implements
//	srv.Get(ctx, req)             a method call: arguments flow into interface-typed parameters
//	                              like any other call
//
// A conversion is told apart from a call by info.Types[call.Fun].IsType(). For a variadic
// callee, arguments past the last fixed parameter flow into the slice's element type unless the
// call spreads a slice with "...".
func (ix *registrationIndex) collectCallFlows(info *types.Info, call *ast.CallExpr) {
	if tv, ok := info.Types[call.Fun]; ok && tv.IsType() {
		// A conversion I(x).
		if len(call.Args) == 1 {
			ix.flow(tv.Type, info.TypeOf(call.Args[0]))
		}
		return
	}
	sig, _ := info.TypeOf(call.Fun).(*types.Signature)
	if sig == nil {
		return
	}
	numParams := sig.Params().Len()
	for i, arg := range call.Args {
		switch {
		case i < numParams-1 || (i < numParams && !sig.Variadic()):
			ix.flow(sig.Params().At(i).Type(), info.TypeOf(arg))
		case sig.Variadic() && numParams > 0 && call.Ellipsis == token.NoPos:
			if sl, ok := sig.Params().At(numParams - 1).Type().(*types.Slice); ok {
				ix.flow(sl.Elem(), info.TypeOf(arg))
			}
		}
	}
	// fx.Annotate(f, fx.As(new(I))): f's results are provided as I.
	if !isFxFunc(typeutil.StaticCallee(info, call), "Annotate") || len(call.Args) < 2 {
		return
	}
	provided, _ := info.TypeOf(call.Args[0]).(*types.Signature)
	if provided == nil {
		return
	}
	for _, arg := range call.Args[1:] {
		as, ok := arg.(*ast.CallExpr)
		if !ok || !isFxFunc(typeutil.StaticCallee(info, as), "As") {
			continue
		}
		for _, target := range as.Args {
			ptr, ok := info.TypeOf(target).(*types.Pointer)
			if !ok || !isInterfaceType(ptr.Elem()) {
				continue
			}
			iface := ptr.Elem().Underlying().(*types.Interface)
			for i := 0; i < provided.Results().Len(); i++ {
				if rt := provided.Results().At(i).Type(); types.Implements(rt, iface) {
					ix.flow(ptr.Elem(), rt)
				}
			}
		}
	}
}
