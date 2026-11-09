package finder

// Registration-rooted inbound detection.
//
// An RPC handler is a method that a server in this binary dispatches to. A server learns its
// handlers from registration, so detection starts at the registration and follows types:
//
//  1. A registrar is a generated function with one of the signature shapes the RPC code
//     generators emit (registration_shape.go). Its handler parameter's type is the server
//     interface.
//  2. A registration site is (a) a call of a registrar, (b) a use of a registrar as a function
//     value, for example fx.Provide(fooserver.New), or (c) a call, from hand-written code, of a
//     generated fx registrar: a generated function whose returned closure takes a parameter
//     struct with a field of a server-interface type. In (b) and (c) the handler arrives by its
//     type, which is how fx wires values.
//  3. The handler type is the static type of the handler argument. If that type is an interface,
//     the argument is resolved to concrete types by following the value where the syntax shows
//     it: the return statements of a statically called constructor, the only assignment of a
//     local variable, or the expressions stored into a struct field (registration_resolve.go).
//     Anything else is resolved through type-keyed flows ("an expression of static type A is
//     used where interface I is expected"), gathered in one pass over the program
//     (registration_flows.go).
//  4. The handlers are the server interface's methods, selected from the registered type's
//     method set. A method promoted from an embedded interface field is resolved through the
//     values of that field, in the same way.
//
// Only syntax and types are used: no SSA and no call graph. This file holds the index and the
// steps 1, 2 and 4; finder/README.md section 2.4 describes the rule and its measured effect.

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	rpcshieldconst "github.com/uber-research/rpcshield/go/constant"
	fty "github.com/uber-research/rpcshield/go/finder/types"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/types/typeutil"
)

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
	// flows maps an interface type (by typeKey) to the types of the expressions used where that
	// interface is expected.
	flows map[string]*typeSet
	// fieldStores maps a struct field (by fieldKey) to the expressions stored into it.
	fieldStores map[string][]fieldStore
	// openFields is the set of struct fields whose values cannot be read off the stores: the
	// field's address is taken, or its struct is populated by fx (it embeds fx.In or dig.In).
	openFields map[string]bool
	// decls maps a function to its declaration.
	decls map[*types.Func]funcDeclInfo
}

// newRegistrationIndex builds the index in three passes over the loaded program.
//
//  1. Generated files (isGeneratedFile), and the Apache Thrift TProcessor interface if the
//     program contains that package.
//  2. Registrars: package-level functions declared in generated files whose signature matches
//     registrarShapeOf and whose handler parameter is a named interface with at least one method.
//     "func RegisterKVServer(s grpc.ServiceRegistrar, srv KVServer)" in kv_grpc.pb.go becomes
//     the registrar of server KVServer; the same function in a hand-written file does not. One
//     server interface may have several registrars (TChannel and YARPC both wrap a thriftrw
//     interface); servers keeps the first for collectFxRegistrar.
//  3. Every function declaration with a body: its declaration (for returnedTypes), the flows
//     and field stores in it (collectFlows), and, for generated package-level functions, whether
//     it is an fx registrar (collectFxRegistrar). Non-function declarations (package-level vars)
//     contribute flows too.
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

// handlersOf returns the hand-written methods of t that implement r's server interface, one
// registeredHandler per method, in the interface's method order.
//
//	type kvServer struct{ pb.UnimplementedKVServer }
//	func (s *kvServer) Get(...)
//	handlersOf(*kvServer, RegisterKVServer)       -> [Get]; Put resolves to the generated
//	                                                 Unimplemented method and is dropped
//	handlersOf(*tchanKVClient, NewTChanKVServer)  -> []: TChannel and Apache Thrift use one
//	                                                 interface for both sides, and the generated
//	                                                 client's methods are not handlers
//	mustEmbedUnimplementedKVServer                -> dropped: a protoc-gen-go-grpc marker, never
//	                                                 an RPC
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
//
// Three kinds of site are recognized, in every top-level declaration of every package:
//
//	pb.RegisterKVServer(s, srv)                 (a) registrar call: srv is resolved with exprTypes
//	fx.Provide(kvserver.New)                    (b) registrar used as a value: the handler arrives
//	                                                by type, so every type that flows into the
//	                                                server interface is registered
//	fx.Provide(kvpb.NewFxKVYARPCProcedures())   (c) call, from hand-written code, of a generated
//	                                                fx registrar: as (b), for each registrar its
//	                                                closure wraps
//
// Not sites: the body of an fx registrar itself (its registrar call runs only when the fx
// registrar is used, and is attributed to the calls of kind (c)); a call of an fx registrar from
// generated code; the callee identifier of a call of kind (a), which would otherwise also match
// (b). An identifier is told to be a callee because the call expression is visited before its
// function expression.
//
// Handlers are de-duplicated by method; the first site found keeps the attribution.
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
//
//	codebasePkgPrefix ""                   handlers whose site or declaration is in codebasePkgs
//	codebasePkgPrefix "go.etcd.io/etcd"    handlers whose site or declaration is under the
//	                                       prefix and not in an infra package
//
// Each handler becomes one InboundPoint. Its canonical name pairs the service name of the server
// interface's package with the method: (*kvServer).Get registered by pb.RegisterKVServer gets
// canonicalEndpoint(registrationServiceName(pb.KVServer), "Get"). Handlers declared in infra
// packages are dropped even when their registration site is in the codebase.
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

// registrationServiceName returns the canonical service name for a server interface.
//
//	gogoproto/kv/kvpb.KVYARPCServer                            gogoproto layout
//	        -> the service name canonicalServiceName reads from package kvpb
//	thriftrw/kv/kvserver.Interface                             thriftrw "server" subpackage
//	        -> the name read from the parent package thriftrw/kv, if that package is loaded
//	google.golang.org/grpc/health/grpc_health_v1.HealthServer  no gogoproto/thriftrw layout
//	        -> the package path itself
//
// The package path is the fallback whenever the interface's package is not loaded, does not
// follow a generated layout, or canonicalServiceName fails on it.
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
