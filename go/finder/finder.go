package finder

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strings"

	rpcshieldconst "github.com/uber-research/rpcshield/go/constant"
	"github.com/uber-research/rpcshield/go/finder/servicemapping"
	"github.com/uber-research/rpcshield/go/grail"
	"github.com/uber-research/rpcshield/go/staticanalyzer/asthelper"
	"go.uber.org/zap"
	"golang.org/x/tools/go/packages"
)

// Finder finds the source and sink functions for a particular service.
type Finder struct {
	logger         *zap.SugaredLogger
	currentService grail.Service
	serviceMapper  servicemapping.ServiceMapper
	keepIBPkgs     map[string]bool

	// codebasePkgPrefix restricts inbound/outbound scanning to packages whose path has this
	// prefix (e.g. "example.internal" in the monorepo). Empty matches every package.
	codebasePkgPrefix string

	// additionalHTTPClientTypes lists extra "pkgpath.TypeName" strings recognized as wrapped
	// HTTP clients for outbound detection, on top of the always-recognized "net/http.Client"
	// (e.g. the monorepo adds "example.internal/go-common.git/x/net/xhttp.Client").
	additionalHTTPClientTypes []string

	// kafkaConsumerProxyPkgPath is the fully qualified package path of the Kafka consumer proxy's
	// MessageHandlerFunc type (see config.Config.KafkaConsumerProxyPkgPath). Empty disables Kafka
	// handler detection.
	kafkaConsumerProxyPkgPath string

	// infraPkgPrefixes lists package-path prefixes to skip when finding inbounds (see
	// config.Config.InfraPkgPrefixes). Empty skips nothing.
	infraPkgPrefixes []string

	// enableGenericGRPCThriftDetection turns on detection of standard google.golang.org/grpc and
	// Apache Thrift client/server shapes, on top of the always-on YARPC-based detection (see
	// config.Config.EnableGenericGRPCThriftDetection).
	enableGenericGRPCThriftDetection bool

	// disableRegistrationInbounds turns off registration-rooted inbound detection (see
	// registration.go), which is on by default.
	disableRegistrationInbounds bool

	// canonicalServiceNameCache is a cache for the canonical service name for a given
	// (gogoproto or thriftrw) package path.
	canonicalServiceNameCache map[string]string
}

// New creates a new Finder. No logging will be done if logger is nil. codebasePkgPrefix
// restricts inbound/outbound scanning to packages whose path has this prefix; pass "" to
// consider every loaded package part of the codebase (the right default outside the monorepo,
// which uses "example.internal"). kafkaConsumerProxyPkgPath and infraPkgPrefixes correspond to
// config.Config.KafkaConsumerProxyPkgPath/InfraPkgPrefixes; pass "" and nil to disable Kafka
// handler detection and infra-package skipping, respectively. enableGenericGRPCThriftDetection
// corresponds to config.Config.EnableGenericGRPCThriftDetection; pass false to only recognize
// YARPC-based gRPC/Thrift shapes (the monorepo default). additionalHTTPClientTypes lists
// extra "pkgpath.TypeName" wrapped-HTTP-client types to recognize for outbound detection, beyond
// "net/http.Client".
func New(currentService grail.Service, serviceMapper servicemapping.ServiceMapper, logger *zap.SugaredLogger, keepIBPkgs map[string]bool, codebasePkgPrefix string, kafkaConsumerProxyPkgPath string, infraPkgPrefixes []string, enableGenericGRPCThriftDetection bool, additionalHTTPClientTypes ...string) *Finder {
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}

	if keepIBPkgs == nil {
		keepIBPkgs = make(map[string]bool)
	}

	return &Finder{
		logger:                           logger,
		currentService:                   currentService,
		serviceMapper:                    serviceMapper,
		canonicalServiceNameCache:        make(map[string]string),
		keepIBPkgs:                       keepIBPkgs,
		codebasePkgPrefix:                codebasePkgPrefix,
		kafkaConsumerProxyPkgPath:        kafkaConsumerProxyPkgPath,
		infraPkgPrefixes:                 infraPkgPrefixes,
		enableGenericGRPCThriftDetection: enableGenericGRPCThriftDetection,
		additionalHTTPClientTypes:        additionalHTTPClientTypes,
	}
}

// DisableRegistrationInbounds turns off registration-rooted inbound detection, which is on by
// default: handlers are also found from the registration calls that hand them to a server (see
// registration.go and config.Config.DisableRegistrationInboundDetection).
func (f *Finder) DisableRegistrationInbounds() {
	f.disableRegistrationInbounds = true
}

// canonicalServiceName returns the canonical service name for the given generated package
// (gogoproto or thriftrw) with memorization for faster lookups.
func (f *Finder) canonicalServiceName(ifacePkg *packages.Package, pkgMap map[string]*packages.Package) (string, error) {
	// The interface definitions for thriftrw are actually located one level deeper than where the
	// service meta information is located. For example, client interface is defined in
	// "example.internal/infra/lottery/lottery/lotteryclient", where the service meta information
	// is defined in "example.internal/infra/lottery/lottery". So here we trim the last element
	// of the package path to get the service package path.
	//
	// However, we only do that for the client, server, and fx packages, because for TChannel
	// interfaces, the interface definitions are located in the same package as the service meta
	// information.
	if rpcshieldconst.IsThriftSubpackage(ifacePkg.PkgPath) {
		parts := strings.Split(ifacePkg.PkgPath, "/")
		parts = parts[:len(parts)-1]
		ifacePkg = pkgMap[strings.Join(parts, "/")]
	}

	if n, ok := f.canonicalServiceNameCache[ifacePkg.PkgPath]; ok {
		return n, nil
	}

	var name string
	if strings.HasPrefix(ifacePkg.PkgPath, rpcshieldconst.GogoprotoPkgPrefix) {
		name = canonicalServiceNameForGogoproto(ifacePkg)
	} else if strings.HasPrefix(ifacePkg.PkgPath, rpcshieldconst.ThriftrwPkgPrefix) {
		name = canonicalServiceNameForThriftrw(ifacePkg)
	}

	if name == "" {
		return "", fmt.Errorf("cannot find canonical service name in package %q", ifacePkg.PkgPath)
	}

	f.canonicalServiceNameCache[ifacePkg.PkgPath] = name
	return name, nil
}

// canonicalServiceNameForGogoproto returns the canonical service name for the given gogoproto
// package where the service is defined, it returns an empty string if we cannot find the
// canonical service name.
func canonicalServiceNameForGogoproto(ifacePkg *packages.Package) string {
	// In the gogoproto package, there is a global variable XXXReflectionMeta. For example:
	// var CffDemoReflectionMeta = reflection.ServerMeta{
	//	ServiceName:     "uber.infra.progsys.cffdemo.CffDemo",
	//	FileDescriptors: yarpcFileDescriptorClosure90ac5faa711f4771,
	// }
	// So we look through the ASTs to first find the variable declaration, extract the value
	// expression, and then extract the (constant) value for the "ServiceName" field for the
	// canonical service name and then lower it.
	for _, file := range ifacePkg.Syntax {
		for _, decl := range file.Decls {
			genDecl, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range genDecl.Specs {
				valueSpec, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, value := range valueSpec.Values {
					compositeLit, ok := value.(*ast.CompositeLit)
					if !ok {
						continue
					}
					// Now we have a composite literal from a global variable declaration, check
					// if it is of type reflection.ServerMeta.
					typ := ifacePkg.TypesInfo.TypeOf(compositeLit)
					namedType, ok := typ.(*types.Named)
					if !ok ||
						namedType.Obj().Pkg() == nil ||
						namedType.Obj().Pkg().Path() != "go.uber.org/yarpc/encoding/protobuf/reflection" ||
						namedType.Obj().Name() != "ServerMeta" {
						continue
					}

					// Extract the constant value for "ServiceName" field.
					for _, elt := range compositeLit.Elts {
						kv, ok := elt.(*ast.KeyValueExpr)
						if !ok {
							continue
						}
						if ident, ok := kv.Key.(*ast.Ident); ok && ident.Name == "ServiceName" {
							v, ok := ifacePkg.TypesInfo.Types[kv.Value]
							if !ok {
								continue
							}
							return strings.ToLower(constant.StringVal(v.Value))
						}
					}
				}
			}
		}
	}

	return ""
}

// canonicalServiceNameForThriftrw returns the canonical service name for the given thriftrw
// package where the service is defined, it returns an empty string if we cannot find the
// canonical service name.
func canonicalServiceNameForThriftrw(ifacePkg *packages.Package) string {
	// In the thriftrw package, there is a global variable ThriftModule. For example:
	// var ThriftModule = &thriftreflect.ThriftModule{
	//	Name:     "lottery",
	//	Package:  "thriftrw/example.internal/infra/lottery/lottery",
	//	FilePath: "example.internal/infra/lottery/lottery.thrift",
	//	SHA1:     "835ff2d004c0aec361937f465de810541324fb30",
	//	Raw:      rawIDL,
	// }
	// where the canonical service name is just the "Name" field in lower case.
	for _, file := range ifacePkg.Syntax {
		for _, decl := range file.Decls {
			genDecl, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range genDecl.Specs {
				valueSpec, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, value := range valueSpec.Values {
					unary, ok := value.(*ast.UnaryExpr)
					if !ok || unary.Op != token.AND {
						continue
					}
					compositeLit, ok := unary.X.(*ast.CompositeLit)
					if !ok {
						continue
					}
					// Now we have a composite literal from a global variable declaration, check
					// if it is of type thriftreflect.ThriftModule.
					typ := asthelper.UnwrapPtr(ifacePkg.TypesInfo.TypeOf(value))
					namedType, ok := typ.(*types.Named)
					if !ok ||
						namedType.Obj().Pkg() == nil ||
						namedType.Obj().Pkg().Path() != "go.uber.org/thriftrw/thriftreflect" ||
						namedType.Obj().Name() != "ThriftModule" {
						continue
					}

					// Extract the constant value for "Name" field.
					for _, elt := range compositeLit.Elts {
						kv, ok := elt.(*ast.KeyValueExpr)
						if !ok {
							continue
						}
						if ident, ok := kv.Key.(*ast.Ident); ok && ident.Name == "Name" {
							if v, ok := ifacePkg.TypesInfo.Types[kv.Value]; ok {
								return strings.ToLower(constant.StringVal(v.Value))
							}
						}
					}
				}
			}
		}
	}

	return ""
}

// canonicalEndpoint returns the canonical endpoint name for the canonical service name and method name.
func canonicalEndpoint(serviceName, methodName string) string {
	return fmt.Sprintf("%s__%s", strings.ToLower(serviceName), strings.ToLower(methodName))
}
