package finder

// Registration-rooted inbound detection.
//
// An RPC handler is a method that a server in this binary dispatches to. A server learns its
// handlers from registration, so detection starts at the registration and follows types:
//
//  1. A registrar is a generated function with one of the signature shapes the RPC code
//     generators emit (see registrarShapeOf). Its handler parameter's type is the server
//     interface.
//  2. A registration site is (a) a call of a registrar, (b) a use of a registrar as a function
//     value, for example fx.Provide(fooserver.New), or (c) a call, from hand-written code, of a
//     generated fx registrar: a generated function whose returned closure takes a parameter
//     struct with a field of a server-interface type. In (b) and (c) the handler arrives by its
//     type, which is how fx wires values.
//  3. The handler type is the static type of the handler argument. If that type is an interface,
//     the argument is resolved to concrete types by following the value where the syntax shows
//     it: the return statements of a statically called constructor, the only assignment of a
//     local variable, or the expressions stored into a struct field. Anything else is resolved
//     through type-keyed flows ("an expression of static type A is used where interface I is
//     expected").
//  4. The handlers are the server interface's methods, selected from the registered type's
//     method set. A method promoted from an embedded interface field is resolved through the
//     values of that field, in the same way.
//
// Only syntax and types are used: no SSA and no call graph.

import (
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"strconv"
	"strings"

	rpcshieldconst "github.com/uber-research/rpcshield/go/constant"
	fty "github.com/uber-research/rpcshield/go/finder/types"
	"golang.org/x/tools/go/packages"
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

// _generatedMarker matches the comment lines that mark a generated file: the Go convention
// ("// Code generated ... DO NOT EDIT."), the same line without its ending, which some
// generators split over several lines, and the "@generated" line the thriftrw and YARPC
// generators emit.
var _generatedMarker = regexp.MustCompile(`^// Code generated |^// @generated`)

// isGeneratedFile reports whether a marker comment precedes the file's package clause.
func isGeneratedFile(file *ast.File) bool {
	for _, group := range file.Comments {
		if group.Pos() > file.Package {
			break
		}
		for _, c := range group.List {
			if _generatedMarker.MatchString(c.Text) {
				return true
			}
		}
	}
	return false
}

// registrar is a generated server registration function.
type registrar struct {
	fn *types.Func
	// handlerParam is the index of the parameter that receives the handler.
	handlerParam int
	// server is the server interface: the type of the handler parameter.
	server       *types.Named
	endpointType fty.EndpointType
}

// registeredHandler is a handler method found from a registration site.
type registeredHandler struct {
	fn        *types.Func
	registrar *registrar
	// site is the position of the registration.
	site token.Pos
}

type funcDeclInfo struct {
	decl *ast.FuncDecl
	info *types.Info
}

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

// registrationIndex holds the program facts registration-rooted detection needs.
type registrationIndex struct {
	fset *token.FileSet
	// generated is the set of generated files.
	generated map[*token.File]bool
	// registrars maps a generated registration function to its description.
	registrars map[*types.Func]*registrar
	// fxRegistrars maps a generated fx registration function to the registrars whose server
	// interfaces its closure takes as parameter-struct fields.
	fxRegistrars map[*types.Func][]*registrar
	// flows maps an interface type (by its type string) to the types of the expressions used
	// where that interface is expected.
	flows map[string]*typeSet
	// fieldStores maps a struct field (see fieldKey) to the expressions stored into it.
	fieldStores map[string][]fieldStore
	// openFields is the set of struct fields whose values cannot be read off the stores: the
	// field's address is taken, or its struct is populated by fx (it embeds fx.In or dig.In).
	openFields map[string]bool
	// decls maps a function to its declaration.
	decls map[*types.Func]funcDeclInfo
}

// fieldKey identifies a field by its struct type and name. Struct types that are identical, and
// so convertible or assignable to each other, share their keys.
func fieldKey(st *types.Struct, name string) string {
	return types.TypeString(st, nil) + "." + name
}

// fieldKeyOf returns the key of the field reached from a value of type recv through the field
// index path. ok is false if the path does not end at a field, or if the field's struct is an
// instantiated generic type, whose stores are not tracked.
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

// typeSet is an insertion-ordered set of types, keyed by type string.
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

// typeKey returns a string that identifies t. Strings are used instead of typeutil.Map so that
// the index does not depend on how the x/tools version in use hashes newer type kinds. A type
// declared inside a function carries its declaration position, since its name is not unique in
// its package.
func typeKey(t types.Type) string {
	t = types.Unalias(t)
	key := types.TypeString(t, nil)
	if named, ok := t.(*types.Named); ok && named.Obj().Pkg() != nil && named.Obj().Parent() != named.Obj().Pkg().Scope() {
		key += "@" + strconv.Itoa(int(named.Obj().Pos()))
	}
	return key
}

func isInterfaceType(t types.Type) bool {
	if _, ok := types.Unalias(t).(*types.TypeParam); ok {
		return false
	}
	_, ok := t.Underlying().(*types.Interface)
	return ok
}

// stripVendor removes a vendor directory prefix from a package path.
func stripVendor(path string) string {
	if i := strings.LastIndex(path, "/vendor/"); i >= 0 {
		return path[i+len("/vendor/"):]
	}
	return strings.TrimPrefix(path, "vendor/")
}

// isNamedType reports whether t is the named type pkgPath.name, ignoring vendoring.
func isNamedType(t types.Type, pkgPath, name string) bool {
	n, ok := types.Unalias(t).(*types.Named)
	return ok && n.Obj().Pkg() != nil && n.Obj().Name() == name && stripVendor(n.Obj().Pkg().Path()) == pkgPath
}

const (
	_yarpcTransportPkg = "go.uber.org/yarpc/api/transport"
	_yarpcProtobufPkg  = "go.uber.org/yarpc/encoding/protobuf"
	_yarpcThriftPkg    = "go.uber.org/yarpc/encoding/thrift"
	_tchannelThriftPkg = "github.com/uber/tchannel-go/thrift"
	_grpcPkg           = "google.golang.org/grpc"
	_apacheThriftPkg   = "github.com/apache/thrift/lib/go/thrift"
)

// importsPackageTree reports whether imports has root or a package below it, such as the "v2"
// package of a YARPC encoding.
func importsPackageTree(imports map[string]bool, root string) bool {
	for path := range imports {
		if path == root || strings.HasPrefix(path, root+"/") {
			return true
		}
	}
	return false
}

// registrarShapeOf matches fn against the registration function shapes the RPC code generators
// emit. It returns the index of the handler parameter and the endpoint type.
//
//   - YARPC (protobuf and thrift): func(server I, ...) []transport.Procedure, in a package that
//     imports the YARPC protobuf or thrift encoding
//   - TChannel Thrift:             func(handler I) thrift.TChanServer
//   - gRPC:                        func(s grpc.ServiceRegistrar | *grpc.Server, srv I)
//   - Apache Thrift:               func(handler I) P, where P implements thrift.TProcessor
func registrarShapeOf(fn *types.Func, imports map[string]bool, tProcessor *types.Interface) (handlerParam int, endpointType fty.EndpointType, ok bool) {
	sig, isSig := fn.Type().(*types.Signature)
	if !isSig || sig.Recv() != nil {
		return 0, "", false
	}
	params, results := sig.Params(), sig.Results()
	if results.Len() >= 1 && params.Len() >= 1 {
		if sl, isSlice := types.Unalias(results.At(0).Type()).(*types.Slice); isSlice && isNamedType(sl.Elem(), _yarpcTransportPkg, "Procedure") {
			switch {
			case importsPackageTree(imports, _yarpcProtobufPkg):
				return 0, fty.TypeGRPC, true
			case importsPackageTree(imports, _yarpcThriftPkg):
				return 0, fty.TypeThrift, true
			}
			return 0, "", false
		}
		if isNamedType(results.At(0).Type(), _tchannelThriftPkg, "TChanServer") {
			return 0, fty.TypeThriftTChannel, true
		}
	}
	if params.Len() == 2 && results.Len() == 0 {
		first := params.At(0).Type()
		if p, isPtr := types.Unalias(first).(*types.Pointer); isPtr {
			if isNamedType(p.Elem(), _grpcPkg, "Server") {
				return 1, fty.TypeGRPC, true
			}
		} else if isNamedType(first, _grpcPkg, "ServiceRegistrar") {
			return 1, fty.TypeGRPC, true
		}
	}
	if tProcessor != nil && params.Len() == 1 && results.Len() == 1 && types.Implements(results.At(0).Type(), tProcessor) {
		return 0, fty.TypeThrift, true
	}
	return 0, "", false
}

// newRegistrationIndex collects generated files, registrars, fx registrars, type-keyed flows and
// function declarations from the loaded program.
func newRegistrationIndex(allPkgs []*packages.Package) *registrationIndex {
	ix := &registrationIndex{
		generated:    make(map[*token.File]bool),
		registrars:   make(map[*types.Func]*registrar),
		fxRegistrars: make(map[*types.Func][]*registrar),
		flows:        make(map[string]*typeSet),
		fieldStores:  make(map[string][]fieldStore),
		openFields:   make(map[string]bool),
		decls:        make(map[*types.Func]funcDeclInfo),
	}
	var tProcessor *types.Interface
	for _, pkg := range allPkgs {
		if ix.fset == nil && pkg.Fset != nil {
			ix.fset = pkg.Fset
		}
		for _, file := range pkg.Syntax {
			if isGeneratedFile(file) {
				ix.generated[pkg.Fset.File(file.Pos())] = true
			}
		}
		if pkg.Types != nil && stripVendor(pkg.PkgPath) == _apacheThriftPkg {
			if tn, ok := pkg.Types.Scope().Lookup("TProcessor").(*types.TypeName); ok {
				tProcessor, _ = tn.Type().Underlying().(*types.Interface)
			}
		}
	}
	if ix.fset == nil {
		return ix
	}

	// Registrars: generated package-level functions of a known shape whose handler parameter is
	// a named interface with at least one method.
	servers := make(map[*types.TypeName]*registrar)
	for _, pkg := range allPkgs {
		if pkg.Types == nil {
			continue
		}
		imports := make(map[string]bool)
		for _, imp := range pkg.Types.Imports() {
			imports[stripVendor(imp.Path())] = true
		}
		scope := pkg.Types.Scope()
		for _, name := range scope.Names() {
			fn, ok := scope.Lookup(name).(*types.Func)
			if !ok || !ix.generated[ix.fset.File(fn.Pos())] {
				continue
			}
			param, endpointType, ok := registrarShapeOf(fn, imports, tProcessor)
			if !ok {
				continue
			}
			server, ok := types.Unalias(fn.Type().(*types.Signature).Params().At(param).Type()).(*types.Named)
			if !ok {
				continue
			}
			if iface, ok := server.Underlying().(*types.Interface); !ok || iface.NumMethods() == 0 {
				continue
			}
			r := &registrar{fn: fn, handlerParam: param, server: server, endpointType: endpointType}
			ix.registrars[fn] = r
			if _, seen := servers[server.Obj()]; !seen {
				servers[server.Obj()] = r
			}
		}
	}

	for _, pkg := range allPkgs {
		info := pkg.TypesInfo
		if info == nil {
			continue
		}
		for _, file := range pkg.Syntax {
			generated := ix.generated[pkg.Fset.File(file.Pos())]
			for _, decl := range file.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok {
					ix.collectFlows(info, decl, nil, decl)
					continue
				}
				fn, _ := info.Defs[fd.Name].(*types.Func)
				if fn == nil || fd.Body == nil {
					continue
				}
				ix.decls[fn] = funcDeclInfo{decl: fd, info: info}
				sig, _ := fn.Type().(*types.Signature)
				ix.collectFlows(info, fd, sig, fd.Body)
				if generated && fd.Recv == nil {
					ix.collectFxRegistrar(info, fn, fd, servers)
				}
			}
		}
	}
	return ix
}

// collectFxRegistrar records fn as an fx registrar if its body contains a closure with a
// parameter struct that has a field of a server-interface type.
func (ix *registrationIndex) collectFxRegistrar(info *types.Info, fn *types.Func, fd *ast.FuncDecl, servers map[*types.TypeName]*registrar) {
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		lit, ok := n.(*ast.FuncLit)
		if !ok {
			return true
		}
		sig, _ := info.TypeOf(lit).(*types.Signature)
		if sig == nil {
			return true
		}
		for i := 0; i < sig.Params().Len(); i++ {
			st, ok := sig.Params().At(i).Type().Underlying().(*types.Struct)
			if !ok {
				continue
			}
			for j := 0; j < st.NumFields(); j++ {
				if named, ok := types.Unalias(st.Field(j).Type()).(*types.Named); ok {
					if r := servers[named.Obj()]; r != nil {
						ix.fxRegistrars[fn] = append(ix.fxRegistrars[fn], r)
					}
				}
			}
		}
		return true
	})
}

// flow records that an expression of type src is used where the interface type dst is expected.
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

// isFxInType reports whether t is fx.In or dig.In, the marker fx parameter structs embed.
func isFxInType(t types.Type) bool {
	return isNamedType(t, "go.uber.org/fx", "In") || isNamedType(t, "go.uber.org/dig", "In")
}

// selectedField returns the key of the struct field e selects, if e is a field selector.
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

// collectFlows records, for root, the type-keyed flows (arguments, returns, assignments, variable
// declarations, composite literals, conversions and fx.Annotate(f, fx.As(new(I)))) and the
// stores into struct fields. scope is the top-level declaration root belongs to; sig is the
// signature of the function root is the body of, or nil.
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

func isFxFunc(fn *types.Func, name string) bool {
	return fn != nil && fn.Pkg() != nil && fn.Name() == name && stripVendor(fn.Pkg().Path()) == "go.uber.org/fx"
}

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

// concreteTypes returns the non-interface types that reach the interface type t through
// type-keyed flows.
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
// declaration e appears in.
//
//   - A non-interface expression has its static type.
//   - An interface-typed call of a statically known function is resolved through that function's
//     return statements.
//   - An interface-typed local variable that is assigned once and never has its address taken is
//     resolved through the assigned expression.
//   - An interface-typed struct field is resolved through the expressions stored into it, unless
//     its address is taken or fx populates its struct.
//   - Anything else is resolved by type.
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

// fieldTypes resolves the struct field key, of interface type t, through the expressions stored
// into it. ok is false if the field has no visible store or is open (see openFields).
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

// localVarTypes resolves the local variable v through its only assignment in scope. ok is false
// if v is not a local variable, is assigned more than once, or has its address taken.
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
// function with numResults unnamed results through the function's return statements. ok is
// false if the call is not of that form.
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

// resolveMethod returns the concrete methods that a call of the interface method m on a value of
// type t runs. A method promoted from an embedded interface field is resolved through the values
// of that field (see fieldTypes), or through the concrete types that flow into the field's
// interface type if the field's stores cannot be used. visited holds the types already resolved
// for m.
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

// handlersOf returns the hand-written methods of t that implement r's server interface.
func (ix *registrationIndex) handlersOf(t types.Type, r *registrar, site token.Pos) []registeredHandler {
	var out []registeredHandler
	iface := r.server.Underlying().(*types.Interface)
	for i := 0; i < iface.NumMethods(); i++ {
		for _, fn := range ix.resolveMethod(t, iface.Method(i), make(map[string]bool)) {
			// Methods declared in generated files are client stubs (TChannel and Apache Thrift
			// use one interface for both sides), Unimplemented* defaults and decorators.
			if fn.Pkg() == nil || ix.generated[ix.fset.File(fn.Pos())] || isForwardCompatMarkerMethod(fn) {
				continue
			}
			out = append(out, registeredHandler{fn: fn, registrar: r, site: site})
		}
	}
	return out
}

// registeredHandlers returns the handler methods reachable from the registration sites in
// allPkgs. A handler is kept if its registration site or the handler itself is in a package
// accepted by inCodebase.
func (ix *registrationIndex) registeredHandlers(allPkgs []*packages.Package, inCodebase func(pkgPath string) bool) []registeredHandler {
	var out []registeredHandler
	seen := make(map[*types.Func]bool)
	add := func(sitePkg string, hs []registeredHandler) {
		for _, h := range hs {
			if seen[h.fn] || !(inCodebase(sitePkg) || inCodebase(h.fn.Pkg().Path())) {
				continue
			}
			seen[h.fn] = true
			out = append(out, h)
		}
	}
	for _, pkg := range allPkgs {
		info := pkg.TypesInfo
		if info == nil {
			continue
		}
		for _, file := range pkg.Syntax {
			generated := ix.generated[pkg.Fset.File(file.Pos())]
			for _, decl := range file.Decls {
				// Registrations inside an fx registrar run only when the fx registrar is used;
				// they are reached through the calls of that fx registrar.
				if fd, ok := decl.(*ast.FuncDecl); ok {
					if fn, ok := info.Defs[fd.Name].(*types.Func); ok && ix.fxRegistrars[fn] != nil {
						continue
					}
				}
				called := make(map[*ast.Ident]bool)
				ast.Inspect(decl, func(n ast.Node) bool {
					switch x := n.(type) {
					case *ast.CallExpr:
						switch fun := ast.Unparen(x.Fun).(type) {
						case *ast.Ident:
							called[fun] = true
						case *ast.SelectorExpr:
							called[fun.Sel] = true
						}
						callee := typeutil.StaticCallee(info, x)
						if callee == nil {
							return true
						}
						if rs := ix.fxRegistrars[callee]; rs != nil && !generated {
							for _, r := range rs {
								for _, t := range ix.concreteTypes(r.server) {
									add(pkg.PkgPath, ix.handlersOf(t, r, x.Pos()))
								}
							}
							return true
						}
						if r := ix.registrars[callee]; r != nil && r.handlerParam < len(x.Args) {
							for _, t := range ix.exprTypes(info, decl, x.Args[r.handlerParam], 0) {
								add(pkg.PkgPath, ix.handlersOf(t, r, x.Pos()))
							}
						}
					case *ast.Ident:
						// A registrar used as a function value: its handler arrives by type.
						fn, ok := info.Uses[x].(*types.Func)
						if !ok || called[x] {
							return true
						}
						if r := ix.registrars[fn]; r != nil {
							for _, t := range ix.concreteTypes(r.server) {
								add(pkg.PkgPath, ix.handlersOf(t, r, x.Pos()))
							}
						}
					}
					return true
				})
			}
		}
	}
	return out
}

// registrationInbounds returns the inbound points found from registration sites. The codebase is
// the set of packages under the configured codebase prefix; without a prefix it is codebasePkgs,
// the packages the entry package's path selects.
func (f *Finder) registrationInbounds(allPkgs, codebasePkgs []*packages.Package, pkgMap map[string]*packages.Package) []fty.InboundPoint {
	inCodebaseSet := make(map[string]bool, len(codebasePkgs))
	for _, pkg := range codebasePkgs {
		inCodebaseSet[pkg.PkgPath] = true
	}
	isInfra := func(pkgPath string) bool {
		for _, prefix := range f.infraPkgPrefixes {
			if strings.HasPrefix(pkgPath, prefix) {
				return true
			}
		}
		return false
	}
	inCodebase := func(pkgPath string) bool {
		if f.codebasePkgPrefix == "" {
			return inCodebaseSet[pkgPath]
		}
		return strings.HasPrefix(pkgPath, f.codebasePkgPrefix) && !isInfra(pkgPath)
	}

	ix := newRegistrationIndex(allPkgs)
	handlers := ix.registeredHandlers(allPkgs, inCodebase)
	f.logger.Infow("Found registration sites", "registrars", len(ix.registrars), "fx_registrars", len(ix.fxRegistrars), "handlers", len(handlers))

	var out []fty.InboundPoint
	for _, h := range handlers {
		pkg := pkgMap[h.fn.Pkg().Path()]
		if pkg == nil || isInfra(pkg.PkgPath) {
			continue
		}
		f.logger.Debugw("Found registered handler", "func", h.fn.FullName(), "registrar", h.registrar.fn.FullName(), "site", ix.fset.Position(h.site).String())
		out = append(out, fty.InboundPoint{
			Pkg:           pkg,
			Func:          h.fn,
			Service:       f.currentService,
			Type:          h.registrar.endpointType,
			CanonicalName: canonicalEndpoint(f.registrationServiceName(h.registrar.server, pkgMap), h.fn.Name()),
		})
	}
	return out
}

// registrationServiceName returns the canonical service name for a server interface: the name
// the generated package declares where the package follows the gogoproto/thriftrw layout, and
// the interface's package path otherwise.
func (f *Finder) registrationServiceName(server *types.Named, pkgMap map[string]*packages.Package) string {
	path := server.Obj().Pkg().Path()
	ifacePkg := pkgMap[path]
	if ifacePkg == nil || !rpcshieldconst.IsRPCGeneratedPkg(path) {
		return path
	}
	if rpcshieldconst.IsThriftSubpackage(path) {
		if i := strings.LastIndex(path, "/"); i < 0 || pkgMap[path[:i]] == nil {
			return path
		}
	}
	if name, err := f.canonicalServiceName(ifacePkg, pkgMap); err == nil {
		return name
	}
	return path
}
