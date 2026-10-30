package http

import (
	"go/types"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uber-research/rpcshield/go/common/mapper"
	fty "github.com/uber-research/rpcshield/go/finder/types"
	"github.com/uber-research/rpcshield/go/grail"
	"github.com/uber-research/rpcshield/go/loader"
	"go.uber.org/zap"
)

func TestHTTPInboundFinder__Gorilla(t *testing.T) {
	t.Parallel()

	logger := zap.NewExample().Sugar()
	dummyService := grail.Service{Name: "gorilla-testdata", Tier: 1}

	ssaProg, entryPkg, allPkgs, err := loader.LoadSSAWithGoPath(
		"rpcshield",
		[]string{"exampleapps", "gorillahttp", "gorillahttp-anal"},
		"github.com/uber-research/rpcshield/go/exampleapps/gorillahttp",
	)
	require.NoError(t, err)

	codebase, err := fty.NewCodebase(logger, entryPkg, allPkgs, map[string]bool{} /* keepPkgs */)
	if err != nil {
		t.Fatalf("Failed to make codebase object. Reason: %v", err)
	}

	muxProviders := []MuxProvider{
		NewGorillaMuxProvider(
			logger,
			dummyService,
			codebase,
		),
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
		{
			PkgPath:       "github.com/uber-research/rpcshield/go/exampleapps/gorillahttp",
			FullFuncName:  "github.com/uber-research/rpcshield/go/exampleapps/gorillahttp.homeHandler",
			CanonicalName: "/",
		},
		{
			PkgPath:       "github.com/uber-research/rpcshield/go/exampleapps/gorillahttp",
			FullFuncName:  "github.com/uber-research/rpcshield/go/exampleapps/gorillahttp.setupRoutes$1",
			CanonicalName: "/debug",
		},
		{
			PkgPath:       "github.com/uber-research/rpcshield/go/exampleapps/gorillahttp",
			FullFuncName:  "github.com/uber-research/rpcshield/go/exampleapps/gorillahttp.homeHandler",
			CanonicalName: "/debug/wrapped",
		},
		{
			PkgPath:       "github.com/uber-research/rpcshield/go/exampleapps/gorillahttp",
			FullFuncName:  "github.com/uber-research/rpcshield/go/exampleapps/gorillahttp.setupRoutes$2",
			CanonicalName: "/debug/wrapped/closure",
		},
		{
			PkgPath:       "github.com/uber-research/rpcshield/go/exampleapps/gorillahttp",
			FullFuncName:  "github.com/uber-research/rpcshield/go/exampleapps/gorillahttp.setupRoutes$3",
			CanonicalName: "/local/clos0",
		},
		{
			PkgPath:       "github.com/uber-research/rpcshield/go/exampleapps/gorillahttp",
			FullFuncName:  "github.com/uber-research/rpcshield/go/exampleapps/gorillahttp.setupRoutes$3",
			CanonicalName: "/local/clos1",
		},
		{
			PkgPath:       "github.com/uber-research/rpcshield/go/exampleapps/gorillahttp",
			FullFuncName:  "(*github.com/uber-research/rpcshield/go/exampleapps/gorillahttp.CustomHandler1).Create",
			CanonicalName: "/create_iface",
		},
		{
			PkgPath:       "github.com/uber-research/rpcshield/go/exampleapps/gorillahttp",
			FullFuncName:  "(*github.com/uber-research/rpcshield/go/exampleapps/gorillahttp.CustomHandler2).Create",
			CanonicalName: "/create_iface",
		},
		{
			PkgPath:       "github.com/uber-research/rpcshield/go/exampleapps/gorillahttp",
			FullFuncName:  "(*github.com/uber-research/rpcshield/go/exampleapps/gorillahttp.CustomHandler1).Delete",
			CanonicalName: "/delete_iface",
		},
		{
			PkgPath:       "github.com/uber-research/rpcshield/go/exampleapps/gorillahttp",
			FullFuncName:  "(*github.com/uber-research/rpcshield/go/exampleapps/gorillahttp.CustomHandler2).Delete",
			CanonicalName: "/delete_iface",
		},
		{
			PkgPath:       "github.com/uber-research/rpcshield/go/exampleapps/gorillahttp",
			FullFuncName:  "(*github.com/uber-research/rpcshield/go/exampleapps/gorillahttp.CustomHandler1).Create",
			CanonicalName: "/create",
		},
		{
			PkgPath:       "github.com/uber-research/rpcshield/go/exampleapps/gorillahttp",
			FullFuncName:  "(*github.com/uber-research/rpcshield/go/exampleapps/gorillahttp.CustomHandler1).Delete",
			CanonicalName: "/delete",
		},
		{
			PkgPath:       "github.com/uber-research/rpcshield/go/exampleapps/gorillahttp",
			FullFuncName:  "github.com/uber-research/rpcshield/go/exampleapps/gorillahttp.pingHandler",
			CanonicalName: "/api/v2/ping",
		},
		{
			PkgPath:       "github.com/uber-research/rpcshield/go/exampleapps/gorillahttp",
			FullFuncName:  "github.com/uber-research/rpcshield/go/exampleapps/gorillahttp.pingHandler",
			CanonicalName: "<unknown>",
		},
		{
			PkgPath:       "github.com/uber-research/rpcshield/go/exampleapps/gorillahttp",
			FullFuncName:  "github.com/uber-research/rpcshield/go/exampleapps/gorillahttp.setupRoutes$4",
			CanonicalName: "/mystery/handler",
		},
		{
			PkgPath:       "github.com/uber-research/rpcshield/go/exampleapps/gorillahttp",
			FullFuncName:  "github.com/uber-research/rpcshield/go/exampleapps/gorillahttp.setupRoutes$5",
			CanonicalName: "<unknown>",
		},
		{
			PkgPath:       "github.com/uber-research/rpcshield/go/exampleapps/gorillahttp",
			FullFuncName:  "github.com/uber-research/rpcshield/go/exampleapps/gorillahttp.makeHandler$1",
			CanonicalName: "/builder/create",
		},
		{
			PkgPath:       "github.com/uber-research/rpcshield/go/exampleapps/gorillahttp",
			FullFuncName:  "github.com/uber-research/rpcshield/go/exampleapps/gorillahttp.pingHandler",
			CanonicalName: "/more/ping",
		},
		{
			PkgPath:       "github.com/uber-research/rpcshield/go/exampleapps/gorillahttp",
			FullFuncName:  "github.com/uber-research/rpcshield/go/exampleapps/gorillahttp.pingHandler",
			CanonicalName: "/some/more/ping",
		},
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

func TestHTTPInboundFinder__ServeMux(t *testing.T) {
	t.Parallel()

	logger := zap.NewExample().Sugar()
	dummyService := grail.Service{Name: "servemux-testdata", Tier: 1}

	ssaProg, entryPkg, allPkgs, err := loader.LoadSSAWithGoPath(
		"rpcshield",
		[]string{"exampleapps", "servemuxhttp", "servemuxhttp-anal"},
		"github.com/uber-research/rpcshield/go/exampleapps/servemuxhttp",
	)
	require.NoError(t, err)

	codebase, err := fty.NewCodebase(logger, entryPkg, allPkgs, map[string]bool{} /* keepPkgs */)
	if err != nil {
		t.Fatalf("Failed to make codebase object. Reason: %v", err)
	}

	muxProviders := []MuxProvider{
		NewServeMuxProvider(logger, dummyService, codebase),
	}
	hf := NewInboundFinder(logger, muxProviders)
	ibs, err := hf.Find(dummyService, ssaProg)
	require.NoError(t, err)

	type InboundRepr struct {
		PkgPath       string
		FullFuncName  string
		CanonicalName string
	}

	const pkg = "github.com/uber-research/rpcshield/go/exampleapps/servemuxhttp"
	expected := []InboundRepr{
		{PkgPath: pkg, FullFuncName: pkg + ".homeHandler", CanonicalName: "/"},
		{PkgPath: pkg, FullFuncName: pkg + ".pingHandler", CanonicalName: "/ping"},
		{PkgPath: pkg, FullFuncName: pkg + ".setupRoutes$1", CanonicalName: "/closure"},
		{PkgPath: pkg, FullFuncName: pkg + ".pingHandler", CanonicalName: "GET /items"},
		// Handle(pattern, http.HandlerFunc(wrapLogger(homeHandler))) unwraps to homeHandler.
		{PkgPath: pkg, FullFuncName: pkg + ".homeHandler", CanonicalName: "/wrapped"},
		// Registered via delegation to addMoreRoutes(mux).
		{PkgPath: pkg, FullFuncName: pkg + ".pingHandler", CanonicalName: "/more/ping"},
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

func TestHTTPInboundFinder__Gin(t *testing.T) {
	t.Parallel()

	logger := zap.NewExample().Sugar()
	dummyService := grail.Service{Name: "gin-testdata", Tier: 1}

	ssaProg, entryPkg, allPkgs, err := loader.LoadSSAWithGoPath(
		"rpcshield",
		[]string{"exampleapps", "ginhttp", "ginhttp-anal"},
		"github.com/uber-research/rpcshield/go/exampleapps/ginhttp",
	)
	require.NoError(t, err)

	codebase, err := fty.NewCodebase(logger, entryPkg, allPkgs, map[string]bool{} /* keepPkgs */)
	if err != nil {
		t.Fatalf("Failed to make codebase object. Reason: %v", err)
	}

	muxProviders := []MuxProvider{
		NewGinProvider(logger, dummyService, codebase),
	}
	hf := NewInboundFinder(logger, muxProviders)
	ibs, err := hf.Find(dummyService, ssaProg)
	require.NoError(t, err)

	type InboundRepr struct {
		PkgPath       string
		FullFuncName  string
		CanonicalName string
	}

	const pkg = "github.com/uber-research/rpcshield/go/exampleapps/ginhttp"
	expected := []InboundRepr{
		{PkgPath: pkg, FullFuncName: pkg + ".homeHandler", CanonicalName: "/"},
		{PkgPath: pkg, FullFuncName: pkg + ".pingHandler", CanonicalName: "/submit"},
		{PkgPath: pkg, FullFuncName: pkg + ".setupRoutes$1", CanonicalName: "/closure"},
		{PkgPath: pkg, FullFuncName: pkg + ".pingHandler", CanonicalName: "/any"},
		{PkgPath: pkg, FullFuncName: pkg + ".pingHandler", CanonicalName: "/put"},
		// Middleware precedes the endpoint; only the terminal handler is recorded.
		{PkgPath: pkg, FullFuncName: pkg + ".homeHandler", CanonicalName: "/mw"},
		// Sub-group route: detected, but the "/v1" group prefix is not prepended
		// (documented limitation).
		{PkgPath: pkg, FullFuncName: pkg + ".pingHandler", CanonicalName: "/users"},
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

func TestFind_NilSSAProgram(t *testing.T) {
	t.Parallel()

	// This test verifies that Find returns an error when given a nil SSA program
	logger := zap.NewExample().Sugar()
	muxProviders := []MuxProvider{}

	finder := NewInboundFinder(logger, muxProviders)
	service := grail.Service{Name: "test-service"}

	// Act
	inbounds, err := finder.Find(service, nil)

	// Assert
	assert.Nil(t, inbounds, "should return nil inbounds when SSA program is nil")
	assert.Error(t, err, "should return an error when SSA program is nil")
	assert.Contains(t, err.Error(), "ssa program is nil", "error message should indicate the nil program")
}
func TestFind_EmptyCodebase(t *testing.T) {
	t.Parallel()

	logger := zap.NewExample().Sugar()
	dummyService := grail.Service{Name: "gorilla-testdata", Tier: 1}

	ssaProg, entryPkg, allPkgs, err := loader.LoadSSAWithGoPath(
		"rpcshield",
		[]string{"exampleapps", "gorillahttp", "gorillahttp-anal"},
		"github.com/uber-research/rpcshield/go/exampleapps/gorillahttp",
	)
	require.NoError(t, err)

	codebase, err := fty.NewCodebase(logger, entryPkg, allPkgs, map[string]bool{} /* keepPkgs */)
	if err != nil {
		t.Fatalf("Failed to make codebase object. Reason: %v", err)
	}

	// With codebase package info: handlers defined in the service codebase resolve.
	muxProviders := []MuxProvider{
		NewGorillaMuxProvider(
			logger,
			dummyService,
			codebase,
		),
	}
	hf := NewInboundFinder(logger, muxProviders)

	ibs, err := hf.Find(dummyService, ssaProg)
	require.NoError(t, err)
	numWith := len(ibs)

	// Without codebase packages: handler resolution is scoped to the service
	// codebase, so an empty codebase yields fewer (no) inbounds. The provider
	// snapshots the codebase scope at construction, so build a fresh one.
	codebase.CodebaseOnly = nil
	emptyProviders := []MuxProvider{
		NewGorillaMuxProvider(
			logger,
			dummyService,
			codebase,
		),
	}
	hfEmpty := NewInboundFinder(logger, emptyProviders)

	ibs, err = hfEmpty.Find(dummyService, ssaProg)
	require.NoError(t, err)
	numWithout := len(ibs)

	require.True(t, numWith > numWithout)
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

// loader.LoadSSAWithGoPath shells out to `go list` via golang.org/x/tools/go/packages, which
// resolves the `go` binary via the process's PATH. Under bazel test sandboxing the inherited PATH
// won't contain a working `go`, so TestMain fixes it up before any test runs (see goSDKBinDir above).
func TestMain(m *testing.M) {
	goBin := goSDKBinDir()
	pathOverride := goBin + string(os.PathListSeparator) + os.Getenv("PATH")
	os.Setenv("PATH", pathOverride)
	if os.Getenv("GOCACHE") == "" {
		if dir, err := os.MkdirTemp("", "finderhttp-gocache"); err == nil {
			os.Setenv("GOCACHE", dir)
		}
	}
	os.Exit(m.Run())
}
