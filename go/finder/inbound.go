package finder

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"strings"

	"github.com/uber-research/rpcshield/go/common/utils"
	"github.com/uber-research/rpcshield/go/constant"
	rpcshieldconst "github.com/uber-research/rpcshield/go/constant"
	httpfinder "github.com/uber-research/rpcshield/go/finder/http"
	fty "github.com/uber-research/rpcshield/go/finder/types"
	"github.com/uber-research/rpcshield/go/grail"
	"github.com/uber-research/rpcshield/go/staticanalyzer/asthelper"
	"go.uber.org/zap"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/types/typeutil"
)

const _httpInboundFinderEnabled = true

// implStruct is the struct type that implements the declared service interface.
type implStruct struct {
	iface        *types.Interface
	endpointType fty.EndpointType
	pkg          *packages.Package
	t            types.Type

	// generic marks implStructs found via findGenericGRPCServer/findGenericThriftServer -- their
	// interface isn't declared in a gogoproto/thriftrw package, so canonical naming can't walk
	// that convention and instead falls back to the interface's raw package path (mirroring
	// genericGRPCThriftOutbound's naming for the outbound side).
	generic bool
}

// String returns the string representation of the implStruct.
func (i implStruct) String() string {
	return i.t.String()
}

func (f *Finder) isBlockedFile(fset *token.FileSet, pos token.Pos) bool {
	return utils.IsGlueFile(fset, pos, f.codebasePkgPrefix)
}

// Inbound returns the slice of functions that implement the declared service endpoints. The order
// of the functions in the slice is unspecified.
func (f *Finder) Inbound(entryPkg *packages.Package, allPkgs []*packages.Package, ssaProg *ssa.Program) ([]fty.InboundPoint, error) {
	f.logger.Infow("Finding inbound functions", "entry_package", entryPkg.PkgPath, "num_packages", len(allPkgs))

	codebase, err := fty.NewCodebase(f.logger, entryPkg, allPkgs, f.keepIBPkgs)
	if err != nil {
		return nil, err
	}

	codebasePkgs := codebase.CodebaseOnly
	// Filter out infra packages. Although technically these could contain inbounds of the services, they belong to
	//infra teams and are available to almost all services in a monorepo. Any violations in these packages are non-actionable for
	// the service owners.
	codebasePkgs = slices.DeleteFunc(codebasePkgs, func(pkg *packages.Package) bool {
		return slices.ContainsFunc(f.infraPkgPrefixes, func(prefix string) bool {
			return strings.HasPrefix(pkg.PkgPath, prefix)
		})
	})
	f.logger.Infow("Found codebase packages", "num_packages", len(codebasePkgs))

	ifaces, err := f.serverInterfaces(codebasePkgs)
	if err != nil {
		return nil, fmt.Errorf("finding server interfaces: %w", err)
	}
	f.logger.Infow("Found proto/thrift server interfaces", "num_interfaces", len(ifaces))

	inbounds := make(map[*types.Func]fty.InboundPoint)
	// For each server interface, we search through all available packages and find out the struct
	// definitions that implement the interface. We then collect all the methods of the struct that
	// implement the interface. This would help catch multiple structs that implement the server
	// interfaces (although it is not common in practice).
	var implStructs []implStruct
	var visitedTypes typeutil.Map
	for _, pkg := range codebasePkgs {
		// We only care about structs implemented in the internal codebase.
		if !strings.HasPrefix(pkg.PkgPath, f.codebasePkgPrefix) {
			continue
		}
		for _, obj := range pkg.TypesInfo.Defs {
			if obj == nil {
				continue
			}
			t := obj.Type()
			if t == types.Typ[types.Invalid] {
				continue
			}
			// Skip the types that we have already analyzed to avoid duplicate work - important
			// for fast results since we may have tons of objects (that have same types) in the
			// `.Defs` map.
			if r := visitedTypes.At(t); r != nil && r.(bool) {
				continue
			}

			// Skip types in glue files.
			if f.isBlockedFile(pkg.Fset, obj.Pos()) {
				continue
			}

			// Skip types that are not deeply structs - they cannot implement the interface.
			if _, ok := asthelper.UnwrapPtr(t).Underlying().(*types.Struct); !ok {
				continue
			}
			for iface, endpointType := range ifaces {
				// Check if either the type or its pointer type implements the interface.
				// This is needed because methods with pointer receivers only make the pointer
				// type implement the interface, not the value type.
				ptrType := types.NewPointer(t)
				implementsInterface := types.Implements(t, iface) || types.Implements(ptrType, iface)

				if !implementsInterface {
					continue
				}

				// Use the pointer type if that's what implements the interface
				implType := t
				if !types.Implements(t, iface) && types.Implements(ptrType, iface) {
					implType = ptrType
				}
				implStructs = append(implStructs, implStruct{
					iface:        iface,
					endpointType: endpointType,
					pkg:          pkg,
					t:            implType,
				})
				// Keep on checking for next interface since there are mega server types that
				// simply implement multiple server interfaces, and we would like to collect all.
			}
			visitedTypes.Set(t, true)
		}
	}
	implStructs = f.filterImplStructs(implStructs)

	// TChannel servers have a different signature for us to match, so we separate them out.
	// Note that we do not need to filter out the TChan servers, because at the construction
	// site of the TChan server, we have evidence of the concrete struct -> interface flows
	// for us to directly connect the two.
	tchanServers, err := f.findTChanServer(allPkgs)
	if err != nil {
		return nil, fmt.Errorf("finding TChan servers: %w", err)
	}
	implStructs = append(implStructs, tchanServers...)
	f.logger.Infow("Found TChan servers", "num_servers", len(tchanServers))

	if f.enableGenericGRPCThriftDetection {
		grpcServers, err := f.findGenericGRPCServer(allPkgs)
		if err != nil {
			return nil, fmt.Errorf("finding generic gRPC servers: %w", err)
		}
		implStructs = append(implStructs, grpcServers...)
		f.logger.Infow("Found generic gRPC servers", "num_servers", len(grpcServers))

		thriftServers, err := f.findGenericThriftServer(allPkgs)
		if err != nil {
			return nil, fmt.Errorf("finding generic Thrift servers: %w", err)
		}
		implStructs = append(implStructs, thriftServers...)
		f.logger.Infow("Found generic Thrift servers", "num_servers", len(thriftServers))
	}

	for _, impl := range implStructs {
		// We have found a struct that implements the interface. Collect its implementing
		// methods as inbound endpoints.
		funcObjs, err := implFuncsFor(impl.iface, impl.t)
		if err != nil {
			return nil, fmt.Errorf("finding methods for type %q: %w", impl.t.String(), err)
		}

		ifacePkg, ok := codebase.PkgMap[impl.iface.Method(0).Pkg().Path()]
		if !ok {
			return nil, fmt.Errorf("could not find package for interface %q", impl.iface.String())
		}
		var canonicalServiceName string
		if impl.generic {
			// Generic gRPC/Thrift interfaces aren't declared under a gogoproto/thriftrw
			// package, so canonicalServiceName's directory-walking convention doesn't apply --
			// fall back to the interface's raw package path, mirroring
			// genericGRPCThriftOutbound's naming for the outbound side.
			canonicalServiceName = ifacePkg.PkgPath
		} else {
			var err error
			canonicalServiceName, err = f.canonicalServiceName(ifacePkg, codebase.PkgMap)
			if err != nil {
				return nil, fmt.Errorf("finding canonical service name: %w", err)
			}
		}

		// There could be type aliases and type embedding such that different types
		// implementing the interface could point to the same set of functions. So we
		// use a map for deduplication (note that types.Object is canonical, so using
		// them as map keys is OK).
		for _, funcObj := range funcObjs {
			inbounds[funcObj] = fty.InboundPoint{
				Pkg:           impl.pkg,
				Func:          funcObj,
				Service:       f.currentService,
				Type:          impl.endpointType,
				CanonicalName: canonicalEndpoint(canonicalServiceName, funcObj.Name()),
			}
		}
	}

	result := make([]fty.InboundPoint, 0, len(inbounds))
	for _, inbound := range inbounds {
		result = append(result, inbound)
	}

	// NOTE: Kafka inbound handling is temporarily disabled based on user feedback.
	// User feedback indicates that kafka fail-close behavior is expected since kafka
	// upstream needs such errors to be exposed for automatic retries. We can consider
	// adding this back after more conversations with developers and the kafka team.
	//
	// kafkaHandlers, err := findKafkaHandler(f.currentService, allPkgs, codebase.PkgMap, f.logger, f.codebasePkgPrefix, f.kafkaConsumerProxyPkgPath)
	// if err != nil {
	// 	return nil, fmt.Errorf("finding Kafka handlers: %w", err)
	// }
	// result = append(result, kafkaHandlers...)
	// f.logger.Infow("Found Kafka handlers", "num_handlers", len(kafkaHandlers))

	if _httpInboundFinderEnabled {
		hf := httpfinder.NewInboundFinder(
			f.logger,
			[]httpfinder.MuxProvider{
				httpfinder.NewGorillaMuxProvider(
					f.logger,
					f.currentService,
					codebase,
				),
				httpfinder.NewServeMuxProvider(
					f.logger,
					f.currentService,
					codebase,
				),
				httpfinder.NewGinProvider(
					f.logger,
					f.currentService,
					codebase,
				),
			},
		)
		httpHandlers, err := hf.Find(f.currentService, ssaProg)
		if err != nil {
			return nil, fmt.Errorf("finding HTTP handlers: %w", err)
		}

		result = append(result, httpHandlers...)
		f.logger.Infow("Found HTTP handlers", "num_handlers", len(httpHandlers))
	}

	return result, nil
}

// Returns the RPC server interfaces (protobuf or thrift) in the given packages. The order of the
// interfaces is unspecified.
func (f *Finder) serverInterfaces(allPkgs []*packages.Package) (map[*types.Interface]fty.EndpointType, error) {
	type ifaceEntry struct {
		iface        *types.Interface
		endpointType fty.EndpointType
	}
	ifaces := make(map[string]ifaceEntry)
	for _, pkg := range allPkgs {
		// The service interfaces will always be used (e.g., by type aliasing
		// `type Handler = pb.XXYARPCServer` or by direct uses `func New() pb.XXYARPCServer`), so
		// we just need to search through the use maps.
		for _, obj := range pkg.TypesInfo.Uses {
			typeName, ok := obj.(*types.TypeName)
			if !ok {
				continue
			}
			var endpointType fty.EndpointType
			switch {
			case isGRPCServer(typeName):
				endpointType = fty.TypeGRPC
			case isThriftServer(typeName):
				endpointType = fty.TypeThrift
			default:
				continue
			}

			// Dedup the server interfaces that we have already seen.
			qualifiedName := qualifiedTypeName(typeName)
			if _, ok := ifaces[qualifiedName]; ok {
				continue
			}

			iface, ok := obj.Type().Underlying().(*types.Interface)
			if !ok {
				continue
			}
			if iface.NumMethods() == 0 {
				// Empty IDL service definitions (`service Foo {}` in a .thrift
				// file, or a .proto with no rpc entries) generate zero-method
				// Go interfaces. Every type trivially satisfies types.Implements
				// for them, so accepting one here would flood implStructs with
				// meaningless matches and later panic at inbound.go's
				// impl.iface.Method(0) call when deriving the canonical service
				// name. An IDL with no RPC entries has no endpoints to detect.
				f.logger.Debugw("Skipping zero-method server interface", "interface", qualifiedName, "type", endpointType, "in", pkg.PkgPath)
				continue
			}
			f.logger.Debugw("Found server interface", "interface", qualifiedName, "type", endpointType, "in", pkg.PkgPath)
			ifaces[qualifiedName] = ifaceEntry{iface: iface, endpointType: endpointType}
		}
	}

	result := make(map[*types.Interface]fty.EndpointType, len(ifaces))
	for _, e := range ifaces {
		result[e.iface] = e.endpointType
	}
	return result, nil
}

// filterImplStructs filters the structs that implement the interface using some heuristics:
//
// We bias towards structs implemented in packages with "handler" in the name, which has a much
// higher chance of being the real IBs. This would help filter out "controller" and "gateway"
// structs that also implement the interface (even though they are not supposed to per best practices).
func (f *Finder) filterImplStructs(implStructs []implStruct) []implStruct {
	if len(implStructs) <= 1 {
		return implStructs
	}
	// Check if there are any structs in the "handler" packages, and remove others if found.
	var handlerStructs []implStruct
	for _, impl := range implStructs {
		if slices.Contains(strings.Split(impl.pkg.PkgPath, "/"), "handler") {
			handlerStructs = append(handlerStructs, impl)
		}
	}
	if len(handlerStructs) > 0 && len(handlerStructs) != len(implStructs) {
		f.logger.Infow("Filtered out non-handler structs, see debug log for details", "before", len(implStructs), "after", len(handlerStructs))
		f.logger.Debugw("Filtered out non-handler structs", "handler_structs", fmt.Sprintf("%s", handlerStructs), "impl_structs", fmt.Sprintf("%s", implStructs))
		implStructs = handlerStructs
	}

	if len(implStructs) != 1 {
		f.logger.Warnw("Multiple structs implementing the interface", "impl_structs", fmt.Sprintf("%s", implStructs))
	}

	return implStructs
}

// findTChanServer finds the TChannel servers in the given packages. Specifically, it
// finds the calls to <thriftrw>.NewTChan<...>(<handler>), then returns the implStructs of the
// handler types (parameter is the interface type, and the real passed in argument is the
// struct type that implements the interface).
func (f *Finder) findTChanServer(allPkgs []*packages.Package) ([]implStruct, error) {
	var implStructs []implStruct

	for _, pkg := range allPkgs {
		// tchanServerMap maps interface types to their implementing structs to avoid
		// duplicate entries. We use typesutil.Map to deduplicate interface types since
		// they can't be used as map keys directly.
		// This would be a <iface> -> <struct> -> true map, since a particular interface
		// can be implemented by multiple structs.
		tchanServerMap := &typeutil.Map{}

		for _, file := range pkg.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				// Look for the <thriftrw>.NewTChan<...>(<handler>) calls.
				if n == nil {
					return true
				}
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if len(call.Args) != 1 {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				obj := pkg.TypesInfo.ObjectOf(sel.Sel)
				if obj == nil || obj.Pkg() == nil {
					return true
				}
				if !isTChannelConstructor(obj) {
					return true
				}
				// Now, find the formal parameter of the NewTChan<...> function, which
				// is the interface type that the handler implements.
				sig, ok := obj.Type().(*types.Signature)
				if !ok {
					return true
				}
				if sig.Params().Len() != 1 {
					return true
				}
				iface, ok := sig.Params().At(0).Type().Underlying().(*types.Interface)
				if !ok {
					return true
				}
				// Now, find the actual handler argument, which is the struct type that
				// implements the interface.
				t := pkg.TypesInfo.TypeOf(call.Args[0])
				if _, ok := asthelper.UnwrapPtr(t).Underlying().(*types.Struct); !ok {
					return true
				}

				// Put them in the map for deduplication purposes (since there could be
				// multiple NewTChan<...> function calls in the codebase that are the same).
				if r := tchanServerMap.At(iface); r == nil {
					tchanServerMap.Set(iface, &typeutil.Map{})
				}
				tchanServerMap.At(iface).(*typeutil.Map).Set(t, true)
				return true
			})
		}
		// Iterate through the collected map and collect the implStructs.
		tchanServerMap.Iterate(func(iface types.Type, value any) {
			for _, t := range value.(*typeutil.Map).Keys() {
				implStructs = append(implStructs, implStruct{
					iface:        iface.(*types.Interface),
					endpointType: fty.TypeThriftTChannel,
					pkg:          pkg,
					t:            t,
				})
			}
		})
	}

	return implStructs, nil
}

// isGenericGRPCServerRegisterFunc returns true if obj is a "RegisterXxxServer" function whose
// first parameter is google.golang.org/grpc.ServiceRegistrar (the interface both *grpc.Server
// and test registrars implement) -- the shape protoc-gen-go-grpc generates for every service,
// independent of package name.
func isGenericGRPCServerRegisterFunc(obj types.Object) bool {
	if !strings.HasPrefix(obj.Name(), "Register") || !strings.HasSuffix(obj.Name(), "Server") {
		return false
	}
	sig, ok := obj.Type().(*types.Signature)
	if !ok || sig.Params().Len() != 2 {
		return false
	}
	named, ok := asthelper.UnwrapPtr(sig.Params().At(0).Type()).(*types.Named)
	if !ok || named.Obj().Pkg() == nil {
		return false
	}
	return named.Obj().Pkg().Path() == "google.golang.org/grpc" &&
		(named.Obj().Name() == "ServiceRegistrar" || named.Obj().Name() == "Server")
}

// findGenericGRPCServer finds standard grpc-go server registrations: calls of the form
// RegisterXxxServer(registrar, impl), where the second argument's type is the struct that
// implements the generated XxxServer interface (the first formal parameter's type). Unlike
// serverInterfaces (which pattern-matches on gogoproto/YARPCServer naming), this anchors on the
// well-known Register*Server/grpc.ServiceRegistrar call-site shape, mirroring
// findTChanServer's call-site-based approach, so it works on arbitrary OSS package names.
func (f *Finder) findGenericGRPCServer(allPkgs []*packages.Package) ([]implStruct, error) {
	var implStructs []implStruct

	declPkgs := make(map[string]*packages.Package, len(allPkgs))
	for _, pkg := range allPkgs {
		declPkgs[pkg.PkgPath] = pkg
	}

	for _, pkg := range allPkgs {
		if !strings.HasPrefix(pkg.PkgPath, f.codebasePkgPrefix) {
			// Mirrors outbound.go's codebase-prefix scoping: without it, this scan also finds
			// server registrations inside a dependency's own internals -- e.g. thanos pulls in
			// go.opentelemetry.io/collector, whose own pdata/pmetric/pmetricotlp package
			// registers an internal-only gRPC bridge server (rawMetricsServer) purely for that
			// dependency's own use, never reachable from thanos's own main(). Treating every
			// dependency's own plumbing as an inbound point produces both false positives and,
			// worse, RTA roots with no path back to this program's actual entry point (see
			// rta/srta/impl.go: such a root is never even added to the call graph, producing a
			// hard "function not found in the call graph" error rather than a wrong-but-harmless
			// result).
			continue
		}
		grpcServerMap := &typeutil.Map{}

		for _, file := range pkg.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				if n == nil {
					return true
				}
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) != 2 {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				obj := pkg.TypesInfo.ObjectOf(sel.Sel)
				if obj == nil || obj.Pkg() == nil || !isGenericGRPCServerRegisterFunc(obj) {
					return true
				}
				sig, ok := obj.Type().(*types.Signature)
				if !ok || sig.Params().Len() != 2 {
					return true
				}
				iface, ok := sig.Params().At(1).Type().Underlying().(*types.Interface)
				if !ok {
					return true
				}
				t := resolveConcreteImplType(declPkgs, pkg, call.Args[1], pkg.TypesInfo.TypeOf(call.Args[1]))
				if t == nil {
					return true
				}
				if r := grpcServerMap.At(iface); r == nil {
					grpcServerMap.Set(iface, &typeutil.Map{})
				}
				grpcServerMap.At(iface).(*typeutil.Map).Set(t, true)
				return true
			})
		}
		grpcServerMap.Iterate(func(iface types.Type, value any) {
			for _, t := range value.(*typeutil.Map).Keys() {
				implStructs = append(implStructs, implStruct{
					iface:        iface.(*types.Interface),
					endpointType: fty.TypeGRPC,
					pkg:          pkg,
					t:            t,
					generic:      true,
				})
			}
		})
	}

	return implStructs, nil
}

// resolveConcreteImplType resolves expr's dynamic implementing type when its static type t is
// already a concrete struct (the common case) or an interface (idiomatic Go constructors --
// "xxx.NewXxxServer(...)" -- return the generated XxxServiceServer interface rather than the
// unexported concrete struct they build, e.g. argo-workflows'
// RegisterWorkflowServiceServer(grpcServer, workflowServer), where workflowServer was assigned
// from workflow.NewWorkflowServer(...) returning workflowpkg.WorkflowServiceServer). Unlike
// outbound.go's resolveConcreteClientType (which scans the interface's own declaring package --
// valid because protoc-gen-go-grpc/thrift always co-locates a generated client interface with its
// unexported concrete struct in the same generated package), the concrete type implementing an
// inbound server interface is arbitrary user code that can live in any package, so there is no
// single package to scan. Instead, when expr is itself a call to a constructor function, this
// looks at that function's own top-level return statement(s) to recover the concrete type it
// actually builds, which the call-site's static (interface) type erases. Returns nil if t is
// already non-struct/non-interface, or no concrete return type could be resolved.
func resolveConcreteImplType(declPkgs map[string]*packages.Package, exprPkg *packages.Package, expr ast.Expr, t types.Type) types.Type {
	if _, ok := asthelper.UnwrapPtr(t).Underlying().(*types.Struct); ok {
		return t
	}
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return nil
	}
	var calleeIdent *ast.Ident
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		calleeIdent = fn
	case *ast.SelectorExpr:
		calleeIdent = fn.Sel
	default:
		return nil
	}
	callee, ok := exprPkg.TypesInfo.Uses[calleeIdent].(*types.Func)
	if !ok {
		return nil
	}
	funcDecl, declPkg := funcDeclFor(declPkgs, callee)
	if funcDecl == nil || funcDecl.Body == nil {
		return nil
	}

	var concrete types.Type
	ast.Inspect(funcDecl.Body, func(n ast.Node) bool {
		if concrete != nil {
			return false
		}
		if _, ok := n.(*ast.FuncLit); ok {
			// Don't attribute a nested closure's return statements to the constructor itself.
			return false
		}
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return true
		}
		retT := declPkg.TypesInfo.TypeOf(ret.Results[0])
		if retT == nil {
			return true
		}
		if _, ok := asthelper.UnwrapPtr(retT).Underlying().(*types.Struct); ok {
			concrete = retT
			return false
		}
		return true
	})
	return concrete
}

// funcDeclFor finds the *ast.FuncDecl and declaring *packages.Package for fn by looking it up in
// declPkgs (keyed by package path -- callers typically build this once from allPkgs). Returns
// (nil, nil) if fn has no home package, its package wasn't loaded, or no matching FuncDecl is
// found (e.g. fn is a pure interface method with no body anywhere -- see
// isAbstractPromotedMethod).
func funcDeclFor(declPkgs map[string]*packages.Package, fn *types.Func) (*ast.FuncDecl, *packages.Package) {
	if fn.Pkg() == nil {
		return nil, nil
	}
	declPkg, ok := declPkgs[fn.Pkg().Path()]
	if !ok || declPkg.TypesInfo == nil {
		return nil, nil
	}
	for _, file := range declPkg.Syntax {
		for _, decl := range file.Decls {
			if fd, ok := decl.(*ast.FuncDecl); ok && declPkg.TypesInfo.Defs[fd.Name] == fn {
				return fd, declPkg
			}
		}
	}
	return nil, nil
}

// isGenericThriftProcessorConstructor returns true if obj is a "NewXxxProcessor" constructor
// from a package importing github.com/apache/thrift/lib/go/thrift -- the shape Apache Thrift's
// Go codegen produces for every service's processor, independent of package/service name.
func isGenericThriftProcessorConstructor(obj types.Object, pkg *packages.Package) bool {
	if !strings.HasPrefix(obj.Name(), "New") || !strings.HasSuffix(obj.Name(), "Processor") {
		return false
	}
	for _, imp := range pkg.Imports {
		if imp.PkgPath == "github.com/apache/thrift/lib/go/thrift" {
			return true
		}
	}
	return false
}

// findGenericThriftServer finds standard Apache Thrift server registrations: calls of the form
// NewXxxProcessor(handler), where the argument's type is the struct that implements the
// generated XxxHandler-shaped interface (the constructor's sole formal parameter type). Mirrors
// findTChanServer's call-site-based approach.
func (f *Finder) findGenericThriftServer(allPkgs []*packages.Package) ([]implStruct, error) {
	var implStructs []implStruct

	declPkgs := make(map[string]*packages.Package, len(allPkgs))
	for _, pkg := range allPkgs {
		declPkgs[pkg.PkgPath] = pkg
	}

	for _, pkg := range allPkgs {
		if !strings.HasPrefix(pkg.PkgPath, f.codebasePkgPrefix) {
			// See the identical comment in findGenericGRPCServer.
			continue
		}
		thriftServerMap := &typeutil.Map{}

		for _, file := range pkg.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				if n == nil {
					return true
				}
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) != 1 {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				obj := pkg.TypesInfo.ObjectOf(sel.Sel)
				if obj == nil || obj.Pkg() == nil {
					return true
				}
				declPkg, ok := declPkgs[obj.Pkg().Path()]
				if !ok || !isGenericThriftProcessorConstructor(obj, declPkg) {
					return true
				}
				sig, ok := obj.Type().(*types.Signature)
				if !ok || sig.Params().Len() != 1 {
					return true
				}
				iface, ok := sig.Params().At(0).Type().Underlying().(*types.Interface)
				if !ok {
					return true
				}
				t := resolveConcreteImplType(declPkgs, pkg, call.Args[0], pkg.TypesInfo.TypeOf(call.Args[0]))
				if t == nil {
					return true
				}
				if r := thriftServerMap.At(iface); r == nil {
					thriftServerMap.Set(iface, &typeutil.Map{})
				}
				thriftServerMap.At(iface).(*typeutil.Map).Set(t, true)
				return true
			})
		}
		thriftServerMap.Iterate(func(iface types.Type, value any) {
			for _, t := range value.(*typeutil.Map).Keys() {
				implStructs = append(implStructs, implStruct{
					iface:        iface.(*types.Interface),
					endpointType: fty.TypeThrift,
					pkg:          pkg,
					t:            t,
					generic:      true,
				})
			}
		})
	}

	return implStructs, nil
}

// findKafkaHandler finds the Kafka handler in the given packages. Specifically, it
// finds all handler functions that implement the configured Kafka consumer proxy client's
// MessageHandlerFunc type (see config.Config.KafkaConsumerProxyPkgPath).
func findKafkaHandler(currentService grail.Service, allPkgs []*packages.Package, pkgMap map[string]*packages.Package, logger *zap.SugaredLogger, codebasePkgPrefix string, kafkaConsumerProxyPkgPath string) ([]fty.InboundPoint, error) {
	var messageHandlerFuncType types.Type
	// Look for the MessageHandlerFunc type in the messaging-consumer-go package
	if kafkaPkg, ok := pkgMap[kafkaConsumerProxyPkgPath]; ok {
		for _, obj := range kafkaPkg.TypesInfo.Defs {
			if obj == nil {
				continue
			}

			typeName, ok := obj.(*types.TypeName)
			if !ok {
				continue
			}

			if isKafkaMessageHandler(typeName, kafkaConsumerProxyPkgPath) {
				messageHandlerFuncType = typeName.Type()
				break
			}
		}
	}

	// It is OK if we cannot find the message handler function type -- it means that the
	// service simply does not use Kafka Consumer Proxy (i.e., it does not depend on
	// the messaging-consumer-go package).
	if messageHandlerFuncType == nil {
		return nil, nil
	}

	// Now find all implementations of this type in the service codebase.
	var inboundPoints []fty.InboundPoint
	for _, pkg := range allPkgs {
		// restrict to codebase packages. It avoids counting the same handler twice when a
		// generated (glue) package re-exports a Def from the codebase package that owns it.
		if !strings.HasPrefix(pkg.PkgPath, codebasePkgPrefix) {
			continue
		}

		// Look for function declarations in the Defs map that match the MessageHandlerFunc signature
		for id, obj := range pkg.TypesInfo.Defs {
			if obj == nil {
				continue
			}

			funcObj, ok := obj.(*types.Func)
			if !ok {
				continue
			}

			// Normally, devs define the kafka handler as a method of a struct, so we
			// skip any standalone functions since they are more likely to be just a
			// helper function.
			recv := funcObj.Type().(*types.Signature).Recv()
			if recv == nil {
				continue
			}

			// Skip if the function is from an interface.
			if _, ok := recv.Type().Underlying().(*types.Interface); ok {
				continue
			}

			// Check if the function is a Kafka message handler
			funcType := funcObj.Type()
			if types.AssignableTo(funcType, messageHandlerFuncType) {
				inboundPoints = append(inboundPoints, fty.InboundPoint{
					Pkg:     pkg,
					Func:    funcObj,
					Service: currentService,
					// TODO: it is not clear how to get the canonical name for the kafka handler.
					// The canonical name usually consists of the service name and the kafka topic
					// name. However, the topic is usually loaded from config files, or constructed
					// from other parts of the codebase. DepFX is able to access this information
					// in runtime, but this poses challenges for static analysis.
					//
					// For now, we just use the function full name (package name + receiver type + function name) as the canonical name.
					CanonicalName: funcObj.FullName(),
				})

				// Log the position for debugging purposes.
				pos := pkg.Fset.Position(id.Pos())
				logger.Debugw("Found Kafka handler in Defs", "func", funcObj.Name(), "pos", pos)
			}
		}
	}

	return inboundPoints, nil
}

// implFuncsFor returns the functions that implement the given interface in the given struc type.
//
// A method that types.LookupFieldOrMethod resolves is not always a genuine implementation with an
// analyzable AST body: it may instead be promoted from an embedded interface-typed field (a
// delegating/decorator pattern -- e.g. thanos's limitedStoreServer, which embeds
// storepb.StoreServer and only overrides Series, forwarding Info/LabelNames/LabelValues straight
// through the embedded field) or satisfied purely by embedding an "Unsafe"/opt-out interface
// rather than the corresponding "Unimplemented" struct (protoc-gen-go-grpc's forward-compatibility
// pattern -- e.g. temporal's AdminHandler embeds adminservice.UnsafeAdminServiceServer, whose sole
// method mustEmbedUnimplementedAdminServiceServer() is itself only an abstract interface method,
// never a concrete stub, and is never actually invoked). In both cases the resolved *types.Func's
// receiver is an interface type, not t: there is no fixed callee to point at statically, since the
// real behavior (if any) depends on whatever concrete value flows into that interface field at
// runtime -- which is exactly what whole-program call-graph construction (RTA) already resolves
// for any real call through that field, and any concrete type providing a genuine implementation
// is independently discovered by this same scan if it is itself registered. isAbstractPromotedMethod
// filters these out rather than treating t as though it implements them.
func implFuncsFor(iface *types.Interface, t types.Type) ([]*types.Func, error) {
	var funcs []*types.Func
	for i := 0; i < iface.NumMethods(); i++ {
		method := iface.Method(i)
		// LookupFieldOrMethod's pkg argument is the package an unexported identifier must be
		// declared in to be visible/promotable -- it models Go's own selector-resolution rule
		// that an unexported name is only a valid selector from within its declaring package.
		// method's own declaring package (method.Pkg()) is the right context here, not t's
		// package: we are asking "does t provide the interface's own method M", and for an
		// unexported M that is only ever satisfiable by promoting a method declared in M's home
		// package (e.g. protoc-gen-go-grpc's "Unsafe"/"Unimplemented" opt-out pattern, where
		// AdminServiceServer embeds an unexported mustEmbedUnimplementedXxx() declared in the
		// generated pb.go package, not in the implementing struct's own package). Passing the
		// impl type's package here made LookupFieldOrMethod treat that promoted unexported
		// method as inaccessible and return nil, even though t genuinely satisfies the interface
		// (confirmed by the fact that this code compiles). For exported methods, method.Pkg()
		// vs. t's package makes no difference, since the visibility check is a no-op for
		// exported names.
		//
		// This does NOT weaken Go's sealed-interface protection. A type in package Pk2 can never
		// satisfy an interface declared in Pk1 that has an unexported method M by *declaring* M
		// itself -- an unexported name is scoped to its declaring package, so Pk2's own M is a
		// different identifier than Pk1's M, full stop. The only way Pk2's type can satisfy such
		// an interface at all is by embedding some type FROM Pk1 that already carries M (e.g.
		// embedding generated UnimplementedXxxServer or UnsafeXxxServer), so M always legitimately
		// "belongs to" Pk1 no matter which package embeds it. method.Pkg() simply asks the
		// question from that legitimate owning package's point of view instead of the (always
		// unauthorized, for an unexported cross-package name) embedding package's point of view --
		// it does not, and cannot, let Pk2 forge an implementation it isn't entitled to.
		obj, _, _ := types.LookupFieldOrMethod(t, false /* addressable */, method.Pkg(), method.Name())
		if obj == nil {
			return nil, fmt.Errorf("method %q not found in type %q", method.Name(), t.String())
		}
		funcObj, ok := obj.(*types.Func)
		if !ok {
			return nil, fmt.Errorf("method %q is not a function in type %q", method.Name(), t.String())
		}
		if isAbstractPromotedMethod(funcObj) {
			continue
		}
		if isForwardCompatMarkerMethod(funcObj) {
			continue
		}
		funcs = append(funcs, funcObj)
	}
	return funcs, nil
}

// isAbstractPromotedMethod returns true if fn has no concrete AST body reachable from the type it
// was looked up on -- detected by checking whether fn's receiver type is itself an interface. A
// method directly declared on (or promoted from an embedded concrete struct into) the impl type
// has a receiver equal to that concrete type; a method only reachable via promotion through an
// embedded interface-typed field keeps the interface as its receiver, since Go never synthesizes a
// concrete forwarding body for it -- the call compiles to a dynamic dispatch through that field.
//
// This is the safety net for the method.Pkg() lookup above: finding an object for M does not by
// itself mean M has code we can analyze. Embedding generated UnimplementedXxxServer (a struct)
// gives a real, if trivial, method body -- fn.Recv() is that concrete struct, so this returns
// false and the method is kept. Embedding UnsafeXxxServer (an interface, temporal's actual case
// for mustEmbedUnimplementedAdminServiceServer) gives only the interface's own abstract method --
// fn.Recv() is the interface itself, so this returns true and the method is dropped. Either way,
// nothing is fabricated: we only ever include a method once we've confirmed a concrete receiver
// backs it.
func isAbstractPromotedMethod(fn *types.Func) bool {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	_, isIface := asthelper.UnwrapPtr(sig.Recv().Type()).Underlying().(*types.Interface)
	return isIface
}

// isForwardCompatMarkerMethod returns true if fn is a protoc-gen-go-grpc forward-compatibility
// forcing method -- "mustEmbedUnimplementedXxxServer"/"mustEmbedUnimplementedXxxClient" -- a
// synthetic, always-empty, never-invoked method whose sole purpose is requiring implementers to
// embed one of the generated Unimplemented*/Unsafe* types, so that adding a new RPC to the .proto
// later can't silently break existing implementations at compile time. This name prefix is a
// stable protoc-gen-go-grpc codegen guarantee, and it can never collide with a real RPC method
// name (those come from the .proto file's own rpc declarations).
//
// This method can be concretely implemented -- a real AST body -- when the impl type embeds the
// generated Unimplemented*Server struct rather than the Unsafe*Server interface (vitess's
// UnimplementedVitessServer.mustEmbedUnimplementedVitessServer() {} is exactly this: a real,
// empty-bodied method), so isAbstractPromotedMethod alone does not catch it. An earlier, broader
// version of this check tried to generalize by testing whether the method's body contained any
// call expression at all, on the theory that a call-free function can never anchor a call path
// anyway -- but that incorrectly dropped genuine, intentionally-trivial RPC handlers too (e.g. a
// real one-line "return nil" handler in a test fixture is still a legitimate inbound point, even
// though it makes no further calls itself). Name-matching this one specific, guaranteed-synthetic
// codegen convention is the correct, narrow signal instead of a general "no calls" heuristic.
func isForwardCompatMarkerMethod(fn *types.Func) bool {
	return strings.HasPrefix(fn.Name(), "mustEmbedUnimplemented")
}

// qualifiedTypeName returns the fully qualified name of the given type. For example,
// "github.com/foo/bar.MyType".
func qualifiedTypeName(t *types.TypeName) string {
	return t.Pkg().Path() + "." + t.Name()
}

// isGRPCServer returns true if the given type is a gRPC server type.
// Specifically, the type would end in "YARPCServer" (e.g., "MyServiceYARPCServer"), and the type
// would be from the generated "gogoproto/..." package.
func isGRPCServer(t *types.TypeName) bool {
	return t.Pkg() != nil && strings.HasPrefix(t.Pkg().Path(), rpcshieldconst.GogoprotoPkgPrefix) && strings.HasSuffix(t.Name(), "YARPCServer")
}

// isThriftServer returns true if the given type is a Thrift server type.
// Specifically, the type would be named "Interface", and the type would be from the generated
// "thriftrw/..." package, where the package name would end in "server", e.g., "myserviceserver".
func isThriftServer(t *types.TypeName) bool {
	return t.Pkg() != nil && strings.HasPrefix(t.Pkg().Path(), rpcshieldconst.ThriftrwPkgPrefix) && strings.HasSuffix(t.Pkg().Path(), "server") && t.Name() == "Interface"
}

// isTChannelConstructor returns true if the given object is a TChannel constructor.
// Specifically, the object would be named "NewTChan<...>", and the package would be from the
// "thriftrw/..." package.
func isTChannelConstructor(obj types.Object) bool {
	return obj.Pkg() != nil && strings.HasPrefix(obj.Pkg().Path(), constant.ThriftrwPkgPrefix) && strings.HasPrefix(obj.Name(), "NewTChan")
}

// isKafkaMessageHandler returns true if the given type is a Kafka message handler type.
// Specifically, the type would be named "MessageHandlerFunc" and would be from a package
// that contains Kafka-related functionality.
func isKafkaMessageHandler(t types.Object, kafkaConsumerProxyPkgPath string) bool {
	return t.Pkg() != nil && t.Pkg().Path() == kafkaConsumerProxyPkgPath && t.Name() == "MessageHandlerFunc"
}
