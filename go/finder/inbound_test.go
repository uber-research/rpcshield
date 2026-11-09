package finder

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/uber-research/rpcshield/go/finder/servicemapping"
	fty "github.com/uber-research/rpcshield/go/finder/types"
	"github.com/uber-research/rpcshield/go/grail"
	"github.com/uber-research/rpcshield/go/loader"
	"github.com/uber-research/rpcshield/go/rpcshieldtest"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

func TestFinder_FindInbounds(t *testing.T) {
	t.Parallel()

	inboundService := grail.Service{Name: "rpcshielddemo", Tier: -1}
	mapper := servicemapping.New([]grail.Service{{Name: "lottery", Tier: 5}}, nil /* provider */, nil /* logger */)
	finder := New(inboundService, mapper, nil /* logger */, nil /* keepIBPkgs */, "" /* codebasePkgPrefix: match everything outside the monorepo */, "" /* kafkaConsumerProxyPkgPath */, nil /* infraPkgPrefixes */, false /* enableGenericGRPCThriftDetection */)

	testPkg := rpcshieldtest.LoadrpcshieldDemoPackages()
	entryPkg, allPkgs, ssaProg := testPkg.Entry, testPkg.All, testPkg.SSAProg

	inbounds, err := finder.Inbound(entryPkg, allPkgs, ssaProg)
	require.NoError(t, err)
	require.NotEmpty(t, inbounds)

	type InboundRepr struct {
		PkgPath       string
		FullFuncName  string
		CanonicalName string
		Type          fty.EndpointType
	}

	expected := []InboundRepr{
		{
			PkgPath:       "github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/handler",
			FullFuncName:  "(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/handler.handler).Create",
			CanonicalName: "rpcshielddemo.rpcshielddemo__create",
			Type:          fty.TypeGRPC,
		},
		{
			PkgPath:       "github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/handler",
			FullFuncName:  "(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/handler.handler).Get",
			CanonicalName: "rpcshielddemo.rpcshielddemo__get",
			Type:          fty.TypeGRPC,
		},
		{
			PkgPath:       "github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/handler/thrifthandler",
			FullFuncName:  "(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/handler/thrifthandler.handler).Create",
			CanonicalName: "simpleservice__create",
			Type:          fty.TypeThrift,
		},
		{
			PkgPath:       "github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/handler",
			FullFuncName:  "(github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/handler.valueReceiverHandler).Create",
			CanonicalName: "rpcshielddemo.rpcshielddemo__create",
			Type:          fty.TypeGRPC,
		},
		{
			PkgPath:       "github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/handler",
			FullFuncName:  "(*github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo/pkg/nopservice.Server).Get",
			CanonicalName: "rpcshielddemo.rpcshielddemo__get",
			Type:          fty.TypeGRPC,
		},
	}

	got := make([]InboundRepr, 0, len(inbounds))
	for _, point := range inbounds {
		got = append(got, InboundRepr{PkgPath: point.Pkg.PkgPath, FullFuncName: point.Func.FullName(), CanonicalName: point.CanonicalName, Type: point.Type})
	}
	require.ElementsMatch(t, expected, got)
}

// genericGRPCThriftInbounds runs inbound detection on the genericgrpcthrift example app with
// generic gRPC/Thrift detection on; configure adjusts the Finder before the run.
func genericGRPCThriftInbounds(t *testing.T, configure func(*Finder)) []inboundRepr {
	inboundService := grail.Service{Name: "genericgrpcthrift", Tier: -1}
	mapper := servicemapping.New(nil /* services */, nil /* provider */, nil /* logger */)
	finder := New(inboundService, mapper, nil /* logger */, nil /* keepIBPkgs */, "" /* codebasePkgPrefix */, "" /* kafkaConsumerProxyPkgPath */, nil /* infraPkgPrefixes */, true /* enableGenericGRPCThriftDetection */)
	configure(finder)

	entryPkg, allPkgs, err := loader.LoadWithGoPath("rpcshield", []string{"exampleapps", "outbounds", "genericgrpcthrift", "genericgrpcthrift-anal"}, "github.com/uber-research/rpcshield/go/exampleapps/outbounds/genericgrpcthrift")
	require.NoError(t, err)

	ssaProg, _ := ssautil.AllPackages(allPkgs, ssa.InstantiateGenerics|ssa.GlobalDebug)
	ssaProg.Build()

	inbounds, err := finder.Inbound(entryPkg, allPkgs, ssaProg)
	require.NoError(t, err)

	got := make([]inboundRepr, 0, len(inbounds))
	for _, point := range inbounds {
		got = append(got, inboundRepr{PkgPath: point.Pkg.PkgPath, FullFuncName: point.Func.FullName(), CanonicalName: point.CanonicalName, Type: point.Type})
	}
	return got
}

type inboundRepr struct {
	PkgPath       string
	FullFuncName  string
	CanonicalName string
	Type          fty.EndpointType
}

// _genericGRPCThriftImplementers are the handlers the implements-based rules find in the
// genericgrpcthrift example app: types that implement a whole server interface.
var _genericGRPCThriftImplementers = []inboundRepr{
	{
		PkgPath:       "github.com/uber-research/rpcshield/go/exampleapps/outbounds/genericgrpcthrift",
		FullFuncName:  "(github.com/uber-research/rpcshield/go/exampleapps/outbounds/genericgrpcthrift.fooServerImpl).Foo",
		CanonicalName: "github.com/uber-research/rpcshield/go/exampleapps/outbounds/genericgrpcthrift/pb__foo",
		Type:          fty.TypeGRPC,
	},
	{
		PkgPath:       "github.com/uber-research/rpcshield/go/exampleapps/outbounds/genericgrpcthrift",
		FullFuncName:  "(github.com/uber-research/rpcshield/go/exampleapps/outbounds/genericgrpcthrift.barHandlerImpl).Bar",
		CanonicalName: "github.com/uber-research/rpcshield/go/exampleapps/outbounds/genericgrpcthrift/pb__bar",
		Type:          fty.TypeThrift,
	},
}

// _genericGRPCThriftRegisteredOnly are the handlers only the registration-rooted rule finds:
// partial implementations composed into one handler that reaches its registration through an
// interface-typed local variable.
var _genericGRPCThriftRegisteredOnly = []inboundRepr{
	{
		PkgPath:       "github.com/uber-research/rpcshield/go/exampleapps/outbounds/genericgrpcthrift",
		FullFuncName:  "(github.com/uber-research/rpcshield/go/exampleapps/outbounds/genericgrpcthrift.bazPart).Baz",
		CanonicalName: "github.com/uber-research/rpcshield/go/exampleapps/outbounds/genericgrpcthrift/pb__baz",
		Type:          fty.TypeGRPC,
	},
	{
		PkgPath:       "github.com/uber-research/rpcshield/go/exampleapps/outbounds/genericgrpcthrift",
		FullFuncName:  "(*github.com/uber-research/rpcshield/go/exampleapps/outbounds/genericgrpcthrift.quxPart).Qux",
		CanonicalName: "github.com/uber-research/rpcshield/go/exampleapps/outbounds/genericgrpcthrift/pb__qux",
		Type:          fty.TypeGRPC,
	},
}

// TestFinder_FindInbounds_GenericGRPCThrift checks the default configuration: the handlers the
// implements-based rules find plus the ones only registration finds.
func TestFinder_FindInbounds_GenericGRPCThrift(t *testing.T) {
	t.Parallel()

	got := genericGRPCThriftInbounds(t, func(*Finder) {})
	require.ElementsMatch(t, append(append([]inboundRepr{}, _genericGRPCThriftImplementers...), _genericGRPCThriftRegisteredOnly...), got)
}

// TestFinder_FindInbounds_GenericGRPCThrift_RegistrationDisabled checks that turning
// registration-rooted detection off leaves exactly the implements-based rules' handlers.
func TestFinder_FindInbounds_GenericGRPCThrift_RegistrationDisabled(t *testing.T) {
	t.Parallel()

	got := genericGRPCThriftInbounds(t, func(f *Finder) { f.DisableRegistrationInbounds() })
	require.ElementsMatch(t, _genericGRPCThriftImplementers, got)
}

// Tests requiring Go SDK in runtime need a real `go` binary on PATH -- see
// modelfx/model_test.go's goSDKBinDir for the pattern this mirrors.
func TestMain(m *testing.M) {
	goBin := goSDKBinDir()
	os.Setenv("PATH", goBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if os.Getenv("GOCACHE") == "" {
		if dir, err := os.MkdirTemp("", "finder-gocache"); err == nil {
			os.Setenv("GOCACHE", dir)
		}
	}
	os.Exit(m.Run())
}

func goSDKBinDir() string {
	runfilesRoot := os.Getenv("RUNFILES_DIR")
	if runfilesRoot == "" {
		runfilesRoot = os.Getenv("TEST_SRCDIR")
	}
	if runfilesRoot != "" {
		if goBin := filepath.Join(runfilesRoot, "go_sdk", "bin", "go"); fileExists(goBin) {
			return filepath.Dir(goBin)
		}
	}
	return filepath.Join(runtime.GOROOT(), "bin")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
