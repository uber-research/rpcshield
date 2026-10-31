package rpcshield

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	bazelmock "mock/github.com/uber-research/rpcshield/go/bazel/bazelmock"
	utilsmock "mock/github.com/uber-research/rpcshield/go/common/utils/utilsmock"
	genaimock "mock/github.com/uber-research/rpcshield/go/genai/genaimock"

	"github.com/sashabaranov/go-openai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uber-research/rpcshield/go/common/edgeinfo"
	"github.com/uber-research/rpcshield/go/common/mapper"
	"github.com/uber-research/rpcshield/go/common/pkgdeps"
	"github.com/uber-research/rpcshield/go/constant"
	"github.com/uber-research/rpcshield/go/finder"
	"github.com/uber-research/rpcshield/go/finder/servicemapping"
	fty "github.com/uber-research/rpcshield/go/finder/types"
	"github.com/uber-research/rpcshield/go/grail"
	"github.com/uber-research/rpcshield/go/graph"
	"github.com/uber-research/rpcshield/go/output"
	"github.com/uber-research/rpcshield/go/query"
	"github.com/uber-research/rpcshield/go/rpcshieldtest"
	"github.com/uber-research/rpcshield/go/rta/rtatest"
	"github.com/uber-research/rpcshield/go/staticanalyzer/asthelper"
	"go.uber.org/mock/gomock"
	"go.uber.org/zap"
	"golang.org/x/tools/go/packages"
)

var _defaultDriverOptions = DriverOptions{
	SkipOBTierFilter: false,
	Analyzers: map[constant.AnalyzerKind]bool{
		constant.CacheAnalyzerKind: true,
		constant.Predefined:        true,
		constant.SCCP:              true,
		constant.SSA:               true,
		constant.AST:               true,
		constant.LLM:               true,
	},
	CSV:           true,
	HTML:          true,
	RTAFlavor:     "prta_kumo_nonblocking",
	RTANumWorkers: "64",
	KeepIBPkgs:    map[string]bool{},
}

// _rpcshieldDemoAllPathsCount is the number of canonical call paths TestDriver_AnalyzeCallPaths_Corner_Cases
// discovers when loading every rpcshielddemo inbound/non-HTTP-outbound pair (matches graph package's
// own _rpcshieldDemoAllPaths, computed by graph_test.go's TestCCT against the same fixture).
const _rpcshieldDemoAllPathsCount = 11

func TestDriver_Run(t *testing.T) {
	t.Parallel()

	// We have a real example service (exampleapps/rpcshielddemo) in this workspace, and our test
	// go_test rule depends on the go_path rule from the real service codebase. So, we can just mock
	// the GoPathWrapper to return the lifted Go path for the real service for testing purposes. The
	// only extra work we need to do is to write the deploy config file, which is needed by the
	// driver to find the bazel targets (we cannot really depend on it unfortunately, see comments on
	// _deployConfig for more details).
	//
	// Since these config files do not change often, we just inline the content here and write it to
	// the temp dir in tests. The bazel_targets entry only needs to parse to the fixture's real Go
	// import path (see findPackageFromTarget) -- it does not need to correspond to a real Bazel
	// target, since LiftGoPath is mocked to return the already-built go_path directory directly.
	const deployConfig = `
schema_version: 2.0.0
service_name: rpcshielddemo
service_type: go_standard
go_standard:
  bazel_targets:
    - //src/github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo:rpcshielddemo
applications:
  - udeploy_app_id: 'rpcshielddemo'
    app_type: command_line
    command_line:
      run_cmd: /home/udocker/rpcshielddemo/rpcshielddemo
    health_check: http_system
env_vars:
  - name: UBER_CONFIG_DIR
    value: "exampleapps/rpcshielddemo/config"
`

	workspace := t.TempDir()
	pinocchioDir := filepath.Join(workspace, "udeploy", "pinocchio", "rpcshielddemo")
	err := os.MkdirAll(pinocchioDir, 0755)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(pinocchioDir, "production.yaml"), []byte(deployConfig), 0666)
	require.NoError(t, err)

	goPathDir, err := filepath.Abs("exampleapps/rpcshielddemo/rpcshielddemo-anal")
	require.NoError(t, err)
	ctrl := gomock.NewController(t)
	runner := utilsmock.NewMockRunner(ctrl)
	gp := bazelmock.NewMockGoPathWrapper(ctrl)
	gp.EXPECT().LiftGoPath(gomock.Any(), gomock.Any()).Return(goPathDir, nil, nil)
	aiClient := genaimock.NewMockClient(ctrl)

	// Create mock return for flamegraph call.
	runner.EXPECT().Run(gomock.Any()).DoAndReturn(func(cmd *exec.Cmd) error {
		return nil
	}).AnyTimes()

	// Mock the rpcshielddemo service to be of tier 2 and the callee "lottery" service to be tier 3
	// (lower than rpcshielddemo) such that rpcshield will analyze call chains between them.
	allServices := []grail.Service{{Name: "lottery", Tier: 3}, {Name: "rpcshielddemo", Tier: 2}}
	lotteryService := grail.Service{Name: "lottery", Tier: 3}
	clientTypeToService := servicemapping.ServiceMapping{}
	clientTypeToService.AddMappings(
		servicemapping.FullyQualifiedType{PkgPath: "thriftrw/lottery/lotteryclient", Name: "Interface"},
		&servicemapping.ServiceWithIDLInfo{Service: lotteryService},
	)
	serviceMapper := servicemapping.New(allServices, clientTypeToService, nil /* logger */)
	driver := NewDriver(workspace, runner, gp, serviceMapper, aiClient, allServices, nil /* productionTrafficRecords */, nil /* logger */, _defaultDriverOptions)

	// We intentionally only list the fields that are possible / interesting to assert.
	expectedRunMetrics := map[string]int{
		_targetCount: 1,
	}
	result, err := driver.Run(context.Background(), "rpcshielddemo")
	require.NoError(t, err)
	// PkgCount and SSAPkgCount will change frequently as the dependencies evolve. So we only check
	// that they are greater than 0.
	require.Greater(t, int(result.RunMetrics[_pkgCount]), 0)
	require.Greater(t, int(result.RunMetrics[_ssaPkgCount]), 0)
	require.Greater(t, int(result.RunMetrics[_inboundCount]), 0)
	require.Greater(t, int(result.RunMetrics[_outboundCount]), 0)
	require.Equal(t, Success, result.Status)

	for k, v := range expectedRunMetrics {
		require.Contains(t, result.RunMetrics, k)
		require.Equal(t, v, int(result.RunMetrics[k]))
	}
	require.NotEmpty(t, result.Inbounds)
	require.NotEmpty(t, result.Outbounds)

	// Check HTML file.
	require.NotEmpty(t, result.HTMLFilePath)
	content, err := os.ReadFile(result.HTMLFilePath)
	require.NoError(t, err)
	require.NotEmpty(t, content)

	// Check CSV file
	rowCnt := int(result.RunMetrics["csv_rows_written"])
	require.NotZero(t, rowCnt)

	// Check the CSV file content
	require.NotEmpty(t, result.CSVFilePath)
	content, err = os.ReadFile(result.CSVFilePath)
	require.NoError(t, err)
	reader := csv.NewReader(strings.NewReader(string(content)))
	records, err := reader.ReadAll()
	require.NoError(t, err)
	require.Equalf(t, rowCnt, len(records), "Number of rows written to CSV file does not match the actual number of rows in the file")

	// Get index of `path_reports` column
	pathReportsIdx := -1
	for i, header := range records[0] {
		if header == "path_reports" {
			pathReportsIdx = i
			break
		}
	}
	require.NotEqual(t, -1, pathReportsIdx, "Expected 'path_reports' column in the CSV file")

	// Unmarshal JSON path reports
	for i := 1; i < len(records); i++ {
		var report output.Report
		err := json.Unmarshal([]byte(records[i][pathReportsIdx]), &report)
		require.NoError(t, err)
		require.NotEmpty(t, report)
		for _, pathResult := range report.PathResults {
			for _, edge := range pathResult.Edges {
				require.NotContainsf(t, edge.Filepath, constant.CFFGenSuffix, "Filepath should not contain `%s`", constant.CFFGenSuffix)
				require.NotContainsf(t, edge.SourceGraphLink, constant.CFFGenSuffix, "SourceGraphLink should not contain `%s`", constant.CFFGenSuffix)
				if strings.Contains(strings.ToLower(edge.Caller), "annotation") {
					if strings.Contains(strings.ToLower(edge.Caller), "suppressfailclose") {
						require.Equalf(t, constant.FailCloseSuppressed, edge.AnalyzerOutput.Status, "Expected status to be FailCloseSuppressed")
						require.Equalf(t, constant.Annotation, edge.AnalyzerOutput.Source, "Expected source to be Annotation")
						require.Equalf(t, constant.FailCloseSuppressed, pathResult.Status, "Expected path status to be FailCloseSuppressed")
					} else if strings.Contains(strings.ToLower(edge.Caller), "failclose") {
						require.Equalf(t, constant.FailClose, edge.AnalyzerOutput.Status, "Expected status to be FailClose")
						require.Equalf(t, constant.Annotation, edge.AnalyzerOutput.Source, "Expected source to be Annotation")
					} else if strings.Contains(strings.ToLower(edge.Caller), "failopen") {
						require.Equalf(t, constant.FailOpen, edge.AnalyzerOutput.Status, "Expected status to be FailOpen")
						require.Equalf(t, constant.Annotation, edge.AnalyzerOutput.Source, "Expected source to be Annotation")
						require.Equalf(t, constant.FailOpen, pathResult.Status, "Expected path status to be FailOpen")
					}
				}
			}
		}
	}
}

// TestDriver_RunOnGoPath confirms RunOnGoPath produces an equivalent result to Run's normal
// service-name/pinocchio/Bazel-target-resolution pipeline, when given the same underlying
// already-lifted GOPATH directory directly -- no pinocchio YAML, no GoPathWrapper mock needed.
func TestDriver_RunOnGoPath(t *testing.T) {
	t.Parallel()

	workspace := t.TempDir()
	goPathDir, err := filepath.Abs("exampleapps/rpcshielddemo/rpcshielddemo-anal")
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	runner := utilsmock.NewMockRunner(ctrl)
	aiClient := genaimock.NewMockClient(ctrl)
	runner.EXPECT().Run(gomock.Any()).DoAndReturn(func(cmd *exec.Cmd) error {
		return nil
	}).AnyTimes()

	lotteryService := grail.Service{Name: "lottery", Tier: 3}
	clientTypeToService := servicemapping.ServiceMapping{}
	clientTypeToService.AddMappings(
		servicemapping.FullyQualifiedType{PkgPath: "thriftrw/lottery/lotteryclient", Name: "Interface"},
		&servicemapping.ServiceWithIDLInfo{Service: lotteryService},
	)
	serviceMapper := servicemapping.New([]grail.Service{lotteryService}, clientTypeToService, nil /* logger */)
	// No GoPathWrapper mock: RunOnGoPath bypasses GoPathWrapper.LiftGoPath entirely, so nil is fine.
	driver := NewDriver(workspace, runner, nil /* GoPathWrapper */, serviceMapper, aiClient, nil /* AllServices */, nil /* productionTrafficRecords */, nil /* logger */, _defaultDriverOptions)

	curService := grail.Service{Name: "rpcshielddemo", Tier: 2}
	targets := []string{"//src/github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo:rpcshielddemo"}
	result, err := driver.RunOnGoPath(context.Background(), curService, targets, goPathDir, nil /* cdeps */)
	require.NoError(t, err)
	require.Equal(t, Success, result.Status)
	require.Greater(t, int(result.RunMetrics[_pkgCount]), 0)
	require.Greater(t, int(result.RunMetrics[_ssaPkgCount]), 0)
	require.Greater(t, int(result.RunMetrics[_inboundCount]), 0)
	require.Greater(t, int(result.RunMetrics[_outboundCount]), 0)
	require.Equal(t, 1, int(result.RunMetrics[_targetCount]))
	require.NotEmpty(t, result.Inbounds)
	require.NotEmpty(t, result.Outbounds)
}

// TestDriver_RunOnPackages confirms RunOnPackages produces an equivalent result to RunOnGoPath,
// when given the already-loaded packages directly -- skipping loader.LoadAll as well.
func TestDriver_RunOnPackages(t *testing.T) {
	t.Parallel()

	workspace := t.TempDir()
	testPkg := rpcshieldtest.LoadrpcshieldDemoPackages()

	ctrl := gomock.NewController(t)
	runner := utilsmock.NewMockRunner(ctrl)
	aiClient := genaimock.NewMockClient(ctrl)
	runner.EXPECT().Run(gomock.Any()).DoAndReturn(func(cmd *exec.Cmd) error {
		return nil
	}).AnyTimes()

	lotteryService := grail.Service{Name: "lottery", Tier: 3}
	clientTypeToService := servicemapping.ServiceMapping{}
	clientTypeToService.AddMappings(
		servicemapping.FullyQualifiedType{PkgPath: "thriftrw/lottery/lotteryclient", Name: "Interface"},
		&servicemapping.ServiceWithIDLInfo{Service: lotteryService},
	)
	serviceMapper := servicemapping.New([]grail.Service{lotteryService}, clientTypeToService, nil /* logger */)
	driver := NewDriver(workspace, runner, nil /* GoPathWrapper */, serviceMapper, aiClient, nil /* AllServices */, nil /* productionTrafficRecords */, nil /* logger */, _defaultDriverOptions)

	curService := grail.Service{Name: "rpcshielddemo", Tier: 2}
	targets := []string{"//src/github.com/uber-research/rpcshield/go/exampleapps/rpcshielddemo:rpcshielddemo"}
	result, err := driver.RunOnPackages(context.Background(), curService, targets, testPkg.All)
	require.NoError(t, err)
	require.Equal(t, Success, result.Status)
	require.Greater(t, int(result.RunMetrics[_pkgCount]), 0)
	require.Greater(t, int(result.RunMetrics[_ssaPkgCount]), 0)
	require.Greater(t, int(result.RunMetrics[_inboundCount]), 0)
	require.Greater(t, int(result.RunMetrics[_outboundCount]), 0)
	require.NotEmpty(t, result.Inbounds)
	require.NotEmpty(t, result.Outbounds)
}

func TestUseBazelLoader(t *testing.T) {
	t.Parallel()
	bazelLoaderServices := []string{"service-0002", "service-0012"}
	r1 := useBazelLoader("aaa", bazelLoaderServices, "")
	require.False(t, r1)
	r2 := useBazelLoader("service-0002", bazelLoaderServices, "")
	require.True(t, r2)
	r3 := useBazelLoader("aaa", bazelLoaderServices, "bazel")
	require.True(t, r3)
	r4 := useBazelLoader("service-0002", bazelLoaderServices, "gopath")
	require.False(t, r4)
}

func TestDiagnostics(t *testing.T) {
	t.Parallel()

	testPkg := rpcshieldtest.LoadrpcshieldDemoPackages()
	entryPkg, allPkgs, ssaProg := testPkg.Entry, testPkg.All, testPkg.SSAProg
	require.NotNil(t, entryPkg)
	require.Greater(t, len(allPkgs), 0)
	// Dump diagnostics.
	workspace := t.TempDir()
	ctrl := gomock.NewController(t)
	runner := utilsmock.NewMockRunner(ctrl)
	gp := bazelmock.NewMockGoPathWrapper(ctrl)

	serviceMapper := servicemapping.New([]grail.Service{{Name: "lottery", Tier: 5}}, nil /* provider */, nil /* logger */)
	aiClient := genaimock.NewMockClient(ctrl)
	d := NewDriver(workspace, runner, gp, serviceMapper, aiClient, []grail.Service{}, nil /* productionTrafficRecords */, nil /* logger */, _defaultDriverOptions)
	numPackageWoErrors, numPackagesWithErrors := d.dumpPackageDiagnostics(allPkgs)
	assert.Greater(t, numPackageWoErrors, 0)
	assert.Equal(t, 0, numPackagesWithErrors)
	// The demo app builds a binary, so the SSA program it produces has a main package.
	assert.Greater(t, len(d.getMain(ssaProg)), 0)
}

// TestDumpPackageDiagnosticsMatchesSSA pins the equivalence the pre-SSA check relies on: a package
// is broken exactly when ssautil.AllPackages declines to create an SSA package for it.
func TestDumpPackageDiagnosticsMatchesSSA(t *testing.T) {
	t.Parallel()

	testPkg := rpcshieldtest.LoadrpcshieldDemoPackages()
	allPkgs, ssaProg := testPkg.All, testPkg.SSAProg
	require.Greater(t, len(allPkgs), 0)

	d := &Driver{Logger: zap.NewNop().Sugar()}
	fromSSA := 0
	for _, p := range allPkgs {
		if ssaProg.Package(p.Types) == nil {
			fromSSA++
		}
	}
	_, fromFields := d.dumpPackageDiagnostics(allPkgs)
	assert.Equal(t, fromSSA, fromFields)
}

func TestDumpPackageDiagnostics_PackagesWithErrors(t *testing.T) {
	t.Parallel()

	workspace := t.TempDir()
	ctrl := gomock.NewController(t)
	runner := utilsmock.NewMockRunner(ctrl)
	gp := bazelmock.NewMockGoPathWrapper(ctrl)

	serviceMapper := servicemapping.New([]grail.Service{{Name: "lottery", Tier: 5}}, nil /* provider */, nil /* logger */)
	aiClient := genaimock.NewMockClient(ctrl)
	d := NewDriver(workspace, runner, gp, serviceMapper, aiClient, []grail.Service{}, nil /* productionTrafficRecords */, nil /* logger */, _defaultDriverOptions)

	// Package with error
	pkgWithError := &packages.Package{
		Name:    "pkgWithError",
		PkgPath: "path/to/pkgWithError",
		Errors: []packages.Error{
			{Msg: "some error"},
		},
		TypesInfo: &types.Info{
			Types: make(map[ast.Expr]types.TypeAndValue),
		},
	}

	// Package without error
	typesPkgWithoutError := types.NewPackage("path/to/pkgWithoutError", "pkgWithoutError")
	pkgWithoutError := &packages.Package{
		Name:    "pkgWithoutError",
		PkgPath: "path/to/pkgWithoutError",
		Types:   typesPkgWithoutError,
		TypesInfo: &types.Info{
			Types: make(map[ast.Expr]types.TypeAndValue),
		},
	}

	pkgs := []*packages.Package{pkgWithError, pkgWithoutError}

	// Call the function
	packageWoErrors, packagesWithErrors := d.dumpPackageDiagnostics(pkgs)

	// Assert the outputs
	assert.Equal(t, 1, packagesWithErrors, "Expected one package with errors")
	assert.Equal(t, 1, packageWoErrors, "Expected one package without errors")
}

func TestDumpPackageDiagnostics_AllPackagesWithErrors(t *testing.T) {
	t.Parallel()

	workspace := t.TempDir()
	ctrl := gomock.NewController(t)
	runner := utilsmock.NewMockRunner(ctrl)
	gp := bazelmock.NewMockGoPathWrapper(ctrl)

	serviceMapper := servicemapping.New([]grail.Service{{Name: "lottery", Tier: 5}}, nil /* provider */, nil /* logger */)
	aiClient := genaimock.NewMockClient(ctrl)
	d := NewDriver(workspace, runner, gp, serviceMapper, aiClient, []grail.Service{}, nil /* productionTrafficRecords */, nil /* logger */, _defaultDriverOptions)

	// Packages with errors
	pkgWithError1 := &packages.Package{
		Name:    "pkgWithError1",
		PkgPath: "path/to/pkgWithError1",
		Errors: []packages.Error{
			{Msg: "error 1"},
		},
		TypesInfo: &types.Info{
			Types: make(map[ast.Expr]types.TypeAndValue),
		},
	}

	pkgWithError2 := &packages.Package{
		Name:    "pkgWithError2",
		PkgPath: "path/to/pkgWithError2",
		Errors: []packages.Error{
			{Msg: "error 2"},
		},
		TypesInfo: &types.Info{
			Types: make(map[ast.Expr]types.TypeAndValue),
		},
	}

	pkgs := []*packages.Package{pkgWithError1, pkgWithError2}

	// Call the function
	packageWoErrors, packagesWithErrors := d.dumpPackageDiagnostics(pkgs)

	// Assert the outputs
	assert.Equal(t, 2, packagesWithErrors, "Expected two packages with errors")
	assert.Equal(t, 0, packageWoErrors, "Expected zero packages without errors")
}

// TestDumpPackageDiagnostics_IllTyped covers the package that type-checked far enough to get a
// types.Package but was poisoned by an ill-typed dependency. ssautil.AllPackages skips it, so the
// pre-SSA check has to count it as broken.
func TestDumpPackageDiagnostics_IllTyped(t *testing.T) {
	t.Parallel()

	workspace := t.TempDir()
	ctrl := gomock.NewController(t)
	runner := utilsmock.NewMockRunner(ctrl)
	gp := bazelmock.NewMockGoPathWrapper(ctrl)

	serviceMapper := servicemapping.New([]grail.Service{{Name: "lottery", Tier: 5}}, nil /* provider */, nil /* logger */)
	aiClient := genaimock.NewMockClient(ctrl)
	d := NewDriver(workspace, runner, gp, serviceMapper, aiClient, []grail.Service{}, nil /* productionTrafficRecords */, nil /* logger */, _defaultDriverOptions)

	poisoned := &packages.Package{
		Name:      "poisoned",
		PkgPath:   "path/to/poisoned",
		Types:     types.NewPackage("path/to/poisoned", "poisoned"),
		IllTyped:  true,
		TypesInfo: &types.Info{Types: make(map[ast.Expr]types.TypeAndValue)},
	}
	healthy := &packages.Package{
		Name:      "healthy",
		PkgPath:   "path/to/healthy",
		Types:     types.NewPackage("path/to/healthy", "healthy"),
		TypesInfo: &types.Info{Types: make(map[ast.Expr]types.TypeAndValue)},
	}

	packageWoErrors, packagesWithErrors := d.dumpPackageDiagnostics([]*packages.Package{poisoned, healthy})

	assert.Equal(t, 1, packagesWithErrors, "Expected the ill-typed package to count as broken")
	assert.Equal(t, 1, packageWoErrors, "Expected one package without errors")
}

// Generated by AutoCover
func TestDriver_Run_ErrorFindingTargets_AutoCover(t *testing.T) {
	t.Parallel()

	// Test case where finding targets returns an error
	ctrl := gomock.NewController(t)
	runner := utilsmock.NewMockRunner(ctrl)
	gp := bazelmock.NewMockGoPathWrapper(ctrl)

	// Create a temporary directory for the test
	tempDir := t.TempDir()

	// Create a driver with the temporary directory as workspace
	serviceMapper := servicemapping.New([]grail.Service{{Name: "lottery", Tier: 5}}, nil /* provider */, nil /* logger */)
	aiClient := genaimock.NewMockClient(ctrl)
	driver := NewDriver(tempDir, runner, gp, serviceMapper, aiClient, []grail.Service{}, nil /* productionTrafficRecords */, nil /* logger */, _defaultDriverOptions)

	// Run the driver
	_, err := driver.Run(context.Background(), "non-existent-service")

	require.Error(t, err)
	require.Contains(t, err.Error(), "find targets")
}

// Generated by AutoCover
func TestDriver_Run_ErrorLoadingPackages_AutoCover(t *testing.T) {
	t.Parallel()

	// Test case where loading packages returns an error
	ctrl := gomock.NewController(t)
	runner := utilsmock.NewMockRunner(ctrl)
	gp := bazelmock.NewMockGoPathWrapper(ctrl)

	// Create a temporary directory for the test
	tempDir := t.TempDir()

	// Create the necessary directory structure and config file
	pinocchioDir := filepath.Join(tempDir, "udeploy", "pinocchio", "some-service")
	err := os.MkdirAll(pinocchioDir, 0755)
	require.NoError(t, err)

	configContent := `
schema_version: 2.0.0
service_name: some-service
service_type: go_standard
go_standard:
  bazel_targets:
    - //src/some/target:binary
`
	err = os.WriteFile(filepath.Join(pinocchioDir, "production.yaml"), []byte(configContent), 0666)
	require.NoError(t, err)

	// Create a driver with the temporary directory as workspace
	serviceMapper := servicemapping.New([]grail.Service{{Name: "lottery", Tier: 5}}, nil /* provider */, nil /* logger */)
	aiClient := genaimock.NewMockClient(ctrl)
	driver := NewDriver(tempDir, runner, gp, serviceMapper, aiClient, []grail.Service{{Name: "some-service", Tier: 1}}, nil /* productionTrafficRecords */, nil /* logger */, _defaultDriverOptions)

	// resolveTargetImportPath runs `bazel query 'labels("embed", TARGET)'` once per target before
	// the GOPATH-lift path; the mock returns an error so the resolver falls back to the dir-based
	// derivation and the rest of the test proceeds as before.
	runner.EXPECT().Run(gomock.Any()).Return(errors.New("mock: no bazel"))
	// Mock LiftGoPath to return a valid path
	gp.EXPECT().LiftGoPath(gomock.Any(), gomock.Any()).Return("/path/to/invalid/gopath", nil, nil)

	// Run the driver
	_, err = driver.Run(context.Background(), "some-service")

	require.Error(t, err)
	require.Contains(t, err.Error(), "load all packages")
}

// Generated by AutoCover
func TestDriver_Run_ErrorScenarios_AutoCover(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		setup          func(*testing.T, *Driver, *bazelmock.MockGoPathWrapper)
		expectedErrMsg string
	}{
		{
			name: "Error lifting GOPATH",
			setup: func(t *testing.T, d *Driver, gp *bazelmock.MockGoPathWrapper) {
				pinocchioDir := filepath.Join(d.WorkspaceRoot, "udeploy", "pinocchio", "some-service")
				require.NoError(t, os.MkdirAll(pinocchioDir, 0755))
				require.NoError(t, os.WriteFile(filepath.Join(pinocchioDir, "production.yaml"), []byte(`
go_standard:
  bazel_targets:
    - //src/some/target:binary
`), 0666))
				gp.EXPECT().LiftGoPath(gomock.Any(), gomock.Any()).Return("", nil, errors.New("lift error"))
			},
			expectedErrMsg: "lift GOPATH",
		},
	}

	ctrl := gomock.NewController(t)
	serviceMapper := servicemapping.New([]grail.Service{{Name: "lottery", Tier: 5}}, nil /* provider */, nil /* logger */)
	aiClient := genaimock.NewMockClient(ctrl)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tempDir := t.TempDir()

			ctrl := gomock.NewController(t)
			runner := utilsmock.NewMockRunner(ctrl)
			// resolveTargetImportPath runs `bazel query 'labels("embed", TARGET)'` per target before
			// dispatching to either loader; the mock returns an error so the resolver falls back to
			// the dir-based derivation. AnyTimes: scenarios that fail before the target loop never
			// reach the resolver.
			runner.EXPECT().Run(gomock.Any()).Return(errors.New("mock: no bazel")).AnyTimes()
			gp := bazelmock.NewMockGoPathWrapper(ctrl)

			allServices := []grail.Service{{Name: "some-service", Tier: 2}}
			driver := NewDriver(tempDir, runner, gp, serviceMapper, aiClient, allServices, nil /* productionTrafficRecords */, nil /* logger */, _defaultDriverOptions)
			tt.setup(t, driver, gp)

			_, err := driver.Run(context.Background(), "some-service")

			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErrMsg)
		})
	}
}

func TestDriver_AnalyzeCallPaths_Corner_Cases(t *testing.T) {
	t.Parallel()

	// ----------------------------------------------------------------------
	// Common Setup: Load packages, build SSA, build paths.
	// ----------------------------------------------------------------------
	testPkg := rpcshieldtest.LoadrpcshieldDemoPackages()
	entryPkg, allPkgs, ssaProg, ssaPkgs := testPkg.Entry, testPkg.All, testPkg.SSAProg, testPkg.SSAPkgs
	require.NotNil(t, entryPkg)
	require.Greater(t, len(allPkgs), 0)

	SSAASTBidirMap := mapper.SSAToASTMap(allPkgs, ssaPkgs, ssaProg)
	SigASTBidirMap := mapper.SignatureToASTMap(allPkgs)

	logger := zap.NewNop().Sugar()
	inboundService := grail.Service{Name: "rpcshielddemo", Tier: -1}
	lotteryService := grail.Service{Name: "lottery", Tier: 5}
	clientTypeToService := servicemapping.ServiceMapping{}
	clientTypeToService.AddMappings(
		servicemapping.FullyQualifiedType{PkgPath: "thriftrw/lottery/lotteryclient", Name: "Interface"},
		&servicemapping.ServiceWithIDLInfo{Service: lotteryService},
	)
	serviceMapper := servicemapping.New([]grail.Service{lotteryService}, clientTypeToService, logger)
	f := finder.New(inboundService, serviceMapper, logger, map[string]bool{} /* keepIBPkgs */, "" /* codebasePkgPrefix */, "" /* kafkaConsumerProxyPkgPath */, nil /* infraPkgPrefixes */, false /* enableGenericGRPCThriftDetection */)

	inbounds, err := f.Inbound(entryPkg, allPkgs, ssaProg)
	require.NoError(t, err)
	require.NotEmpty(t, inbounds)

	outbounds, _, err := f.Outbound(entryPkg, allPkgs)
	var filteredOutbounds []fty.OutboundPoint
	for _, ob := range outbounds {
		if ob.Type != fty.TypeHTTP {
			filteredOutbounds = append(filteredOutbounds, ob)
		}
	}
	outbounds = filteredOutbounds
	require.NoError(t, err)
	require.NotEmpty(t, outbounds)

	b := graph.NewBuilder(logger, allPkgs, ssaProg, ssaPkgs, SSAASTBidirMap, SigASTBidirMap, true,
		entryPkg, inbounds, outbounds, true, graph.DefaultSerialGraphConfig())
	paths, buildResult, err := b.Build()
	require.NoError(t, err)
	require.NotNil(t, buildResult)
	require.Len(t, paths, _rpcshieldDemoAllPathsCount)

	// ----------------------------------------------------------------------
	// Helper: copy the call paths so we can manipulate them without
	// affecting subsequent tests.
	// ----------------------------------------------------------------------
	copyPaths := func(original []*graph.CallPath) []*graph.CallPath {
		copied := make([]*graph.CallPath, len(original))
		for i := range original {
			pathClone := *original[i] // shallow copy
			edgeClones := make([]*edgeinfo.EdgeInfo, len(pathClone.Edges))
			for j, e := range pathClone.Edges {
				edgeCopy := *e
				edgeClones[j] = &edgeCopy
			}
			pathClone.Edges = edgeClones
			copied[i] = &pathClone
		}
		return copied
	}

	// ----------------------------------------------------------------------
	// Helper: copy allPkgs so manipulations don't affect other sub-tests.
	// ----------------------------------------------------------------------
	copyAllPkgs := func(pkgs []*packages.Package) []*packages.Package {
		pkgCopy := make([]*packages.Package, len(pkgs))
		copy(pkgCopy, pkgs)
		return pkgCopy
	}

	// ----------------------------------------------------------------------
	// Helper: run the analysis with a given slice of packages and return
	// all error messages from all edges.
	// ----------------------------------------------------------------------
	runAndCollectErrorsWithPkgs := func(pkgs []*packages.Package, callPaths []*graph.CallPath) []string {
		// Create a new Driver instance for each test case to avoid data races
		d := &Driver{
			SSAASTBidirMap:               SSAASTBidirMap,
			opts:                         _defaultDriverOptions,
			simplifiedToDetailedInbound:  make(map[output.EndPoint]fty.InboundPoint),
			simplifiedToDetailedOutbound: make(map[output.EndPoint]fty.OutboundPoint),
			timestampCache:               make(map[string]string),
			Logger:                       zap.NewNop().Sugar(),
		}
		results := d.analyzeCallPaths(pkgs, callPaths)
		var allErrors []string
		for _, r := range results {
			for _, pr := range r.PathResults {
				for _, e := range pr.Edges {
					allErrors = append(allErrors, e.Errors...)
				}
			}
		}
		return allErrors
	}

	tests := []struct {
		name           string
		manipulatePath func(paths []*graph.CallPath, allPkgs []*packages.Package) ([]*graph.CallPath, []*packages.Package)
		expectedError  string
	}{
		{
			name: "caller package not present in allPkgs slice",
			manipulatePath: func(paths []*graph.CallPath, allPkgs []*packages.Package) ([]*graph.CallPath, []*packages.Package) {
				pathsCopy := copyPaths(paths)
				allPkgsCopy := copyAllPkgs(allPkgs)

				if len(pathsCopy[0].Edges) > 0 {
					callerPkgPath := pathsCopy[0].Edges[0].Edge.Caller.Func.Pkg.Pkg.Path()
					var newAllPkgs []*packages.Package
					for _, p := range allPkgsCopy {
						if p.PkgPath != callerPkgPath {
							newAllPkgs = append(newAllPkgs, p)
						}
					}
					return pathsCopy, newAllPkgs
				}
				return pathsCopy, allPkgsCopy
			},
			expectedError: "package not found",
		},
		{
			name: "missing site on first edge",
			manipulatePath: func(paths []*graph.CallPath, allPkgs []*packages.Package) ([]*graph.CallPath, []*packages.Package) {
				pathsCopy := copyPaths(paths)
				allPkgsCopy := copyAllPkgs(allPkgs)

				if len(pathsCopy[0].Edges) > 0 {
					pathsCopy[0].Edges[0].Edge.Site = nil
				}
				return pathsCopy, allPkgsCopy
			},
			expectedError: "no site found for edge",
		},
		{
			name: "caller package is nil on second edge",
			manipulatePath: func(paths []*graph.CallPath, allPkgs []*packages.Package) ([]*graph.CallPath, []*packages.Package) {
				pathsCopy := copyPaths(paths)
				allPkgsCopy := copyAllPkgs(allPkgs)

				if len(pathsCopy[0].Edges) > 1 {
					pathsCopy[0].Edges[1].Edge.Caller.Func.Pkg = nil
				}
				return pathsCopy, allPkgsCopy
			},
			expectedError: "caller package is nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modifiedPaths, modifiedPkgs := tt.manipulatePath(paths, allPkgs)
			allErrors := runAndCollectErrorsWithPkgs(modifiedPkgs, modifiedPaths)
			require.True(t, slices.ContainsFunc(allErrors, func(s string) bool {
				return strings.Contains(s, tt.expectedError)
			}), "Expected '%s' error, but got %v", tt.expectedError, allErrors)
		})
	}
}

func TestDriver_LLM(t *testing.T) {
	t.Parallel()

	// Load the rpcshielddemo service.
	testPkg := rpcshieldtest.LoadrpcshieldDemoPackages()
	entryPkg, allPkgs := testPkg.Entry, testPkg.All
	require.NotNil(t, entryPkg)
	require.Greater(t, len(allPkgs), 0)

	ctrl := gomock.NewController(t)
	aiClient := genaimock.NewMockClient(ctrl)
	aiClient.EXPECT().CreateChatCompletion(gomock.Any(), gomock.Any()).Return(openai.ChatCompletionResponse{
		Choices: []openai.ChatCompletionChoice{{Message: openai.ChatCompletionMessage{Content: " blah blah blah blah \n <result> fail-close </result>"}}},
	}, nil)
	d := &Driver{AIClient: aiClient, opts: _defaultDriverOptions, Logger: zap.NewNop().Sugar()}

	// Create a dummy LLM input pair (caller, callee) from entry package.
	var caller *ast.FuncDecl
	for _, f := range entryPkg.Syntax {
		for _, decl := range f.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok {
				caller = fn
				break
			}
		}
	}
	require.NotNil(t, caller, "could not find a function in the rpcshielddemo entry package")
	callee := &ast.CallExpr{
		Fun:      &ast.Ident{Name: "lottery"},
		Lparen:   0,
		Args:     nil,
		Ellipsis: 0,
		Rparen:   0,
	}
	calleeObj := &types.Func{}
	astContext := &asthelper.ASTContext{
		PkgInfo: &pkgdeps.Info{
			Pkg:  entryPkg,
			Deps: nil,
		},
		FuncLitFuncMap:  nil,
		IdentFuncLitMap: nil,
	}

	out, err := d.runLLMAnalyzer(caller, callee, calleeObj, astContext)
	require.NoError(t, err)
	require.Equal(t, constant.FailClose, out.Status)

	// Test case where the LLM API returns an error.
	_, err = d.runLLMAnalyzer(caller, callee, nil, astContext)
	require.Error(t, err)
}

func TestDriver_LogResults_ErrorCase(t *testing.T) {
	t.Parallel()

	// Test case to trigger the conditional code where there is an error in the results
	var results []output.PathResult
	results = append(results, output.PathResult{
		Edges: []*output.EdgeWrapper{{
			Caller:          "caller",
			Callee:          "callee",
			SourceGraphLink: "sourceGraphLink",
			Errors:          []string{"some error"},
		}},
	})

	report := output.Report{
		Inbound: output.EndPoint{
			Service: grail.Service{
				Name: "InboundService",
				Tier: 1,
			},
			APIName: "InboundAPI",
		},
		Outbound: output.EndPoint{
			Service: grail.Service{
				Name: "OutboundService",
				Tier: 5,
			},
			APIName: "OutboundAPI",
		},
		PathResults: results,
		Status:      constant.FailClose,
	}

	d := &Driver{
		Logger: zap.NewNop().Sugar(),
	}
	d.logResults([]output.Report{report})
}

// Tests requiring Go SDK in runtime need rtatest.SetupGoSDK, mirroring the monorepo's
// testutil.RunWithGoSDK (see https://github.com/bazelbuild/rules_go/issues/2370).
func TestMain(m *testing.M) {
	rtatest.SetupGoSDK()
	os.Exit(m.Run())
}

type mockRunner struct {
	expected []expectedCall
}

type expectedCall struct {
	match   func(*exec.Cmd) bool  // check if cmd matches
	handler func(*exec.Cmd) error // handle the cmd (write stdout, etc)
	called  bool                  // track if we've already used this expectedCall
}

// Expect allows the test to register a matcher and a handler. The
// matcher returns true if cmd is the expected command. The handler
// does whatever is needed, including writing stdout/stderr or returning an error.
func (m *mockRunner) Expect(
	match func(*exec.Cmd) bool,
	handler func(*exec.Cmd) error,
) {
	m.expected = append(m.expected, expectedCall{
		match:   match,
		handler: handler,
	})
}

func (m *mockRunner) Run(cmd *exec.Cmd) error {
	for i := range m.expected {
		ec := &m.expected[i]
		if ec.match(cmd) && !ec.called {
			ec.called = true
			return ec.handler(cmd)
		}
	}
	return fmt.Errorf("unexpected command: %v", cmd.Args)
}

func TestDriver_getLastModifiedTimestamp_FileNotExist(t *testing.T) {
	runner := &mockRunner{}
	driver := &Driver{
		Logger: zap.NewNop().Sugar(),
	}
	_, err := driver.getLastModifiedTimestamp(runner, "SomeFunc", "/tmp/nonexistentfile.go", "/tmp")
	require.Error(t, err)
	require.Contains(t, err.Error(), "file does not exist")
}

func TestDriver_getLastModifiedTimestamp(t *testing.T) {
	tests := []struct {
		name      string
		setupMock func(m *mockRunner)
		wantErr   bool
	}{
		{
			name: "correct git log",
			setupMock: func(m *mockRunner) {
				// Return empty stdout from query -> no deps
				m.Expect(
					func(cmd *exec.Cmd) bool {
						return cmd.Args[0] == "git"
					},
					func(cmd *exec.Cmd) error {
						cmd.Stdout.Write([]byte("hash12312|afjsdkj|Feb 1 2025"))
						return nil
					},
				)
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := &mockRunner{}
			if tt.setupMock != nil {
				tt.setupMock(runner)
			}
			driver := &Driver{
				Logger: zap.NewNop().Sugar(),
			}
			tmpDir := t.TempDir()
			filePath := filepath.Join(tmpDir, "testfile.go")
			os.WriteFile(filePath, []byte("package main\nfunc SomeFunc() {}\n"), 0644)

			timestamp, err := driver.getLastModifiedTimestamp(runner, "SomeFunc", filePath, tmpDir)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.Equal(t, "Feb 1 2025", timestamp)
				assert.NoError(t, err)
			}

		})
	}
}

func TestDriver_queryTimestamp(t *testing.T) {
	tests := []struct {
		name      string
		setupMock func(m *mockRunner)
		wantErr   bool
	}{
		{
			name: "query timestamp",
			setupMock: func(m *mockRunner) {
				// Return empty stdout from query -> no deps
				m.Expect(
					func(cmd *exec.Cmd) bool {
						return cmd.Args[0] == "git"
					},
					func(cmd *exec.Cmd) error {
						cmd.Stdout.Write([]byte("hash12312|afjsdkj|Feb 1 2025"))
						return nil
					},
				)
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := &mockRunner{}
			if tt.setupMock != nil {
				tt.setupMock(runner)
			}
			driver := &Driver{
				Logger:         zap.NewNop().Sugar(),
				Runner:         runner,
				timestampCache: make(map[string]string),
			}
			tmpDir := t.TempDir()
			filePath := filepath.Join(tmpDir, "testfile.go")
			os.WriteFile(filePath, []byte("package main\nfunc SomeFunc() {}\n"), 0644)

			timestamp, err := driver.queryTimestamp(runner, "SomeFunc", "main.SomeFunc", filePath, tmpDir)
			driver.queryTimestamp(runner, "SomeFunc", "main.SomeFunc", filePath, tmpDir)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.Equal(t, "Feb 1 2025", timestamp)
				assert.NoError(t, err)
			}
		})
	}
}

func TestDriver_HTTP_OB_Resolving(t *testing.T) {
	t.Parallel()
	testPkg := rpcshieldtest.LoadrpcshieldDemoPackages()
	entryPkg, allPkgs, ssaProg, ssaPkgs := testPkg.Entry, testPkg.All, testPkg.SSAProg, testPkg.SSAPkgs
	require.NotNil(t, entryPkg)
	require.Greater(t, len(allPkgs), 0)

	SSAASTBidirMap := mapper.SSAToASTMap(allPkgs, ssaPkgs, ssaProg)
	SigASTBidirMap := mapper.SignatureToASTMap(allPkgs)

	logger := zap.NewNop().Sugar()
	inboundService := grail.Service{Name: "rpcshielddemo", Tier: -1}
	lotteryService := grail.Service{Name: "lottery", Tier: 5}
	clientTypeToService := servicemapping.ServiceMapping{}
	clientTypeToService.AddMappings(
		servicemapping.FullyQualifiedType{PkgPath: "thriftrw/lottery/lotteryclient", Name: "Interface"},
		&servicemapping.ServiceWithIDLInfo{Service: lotteryService},
	)
	serviceMapper := servicemapping.New([]grail.Service{lotteryService, {Name: "httpservicefoo", Tier: 5}}, clientTypeToService, logger)
	f := finder.New(inboundService, serviceMapper, logger, map[string]bool{} /* keepIBPkgs */, "" /* codebasePkgPrefix */, "" /* kafkaConsumerProxyPkgPath */, nil /* infraPkgPrefixes */, false /* enableGenericGRPCThriftDetection */)

	inbounds, err := f.Inbound(entryPkg, allPkgs, ssaProg)
	require.NoError(t, err)
	require.NotEmpty(t, inbounds)

	outbounds, _, err := f.Outbound(entryPkg, allPkgs)
	var filteredOutbounds []fty.OutboundPoint
	for _, ob := range outbounds {
		// only test HTTP outbound
		if ob.Type == fty.TypeHTTP {
			filteredOutbounds = append(filteredOutbounds, ob)
		}
	}
	outbounds = filteredOutbounds
	require.NoError(t, err)
	require.NotEmpty(t, outbounds)

	b := graph.NewBuilder(logger, allPkgs, ssaProg, ssaPkgs, SSAASTBidirMap, SigASTBidirMap, true,
		entryPkg, inbounds, outbounds, true, graph.DefaultSerialGraphConfig())
	paths, _, err := b.Build()
	require.NoError(t, err)
	driver := &Driver{
		SSAASTBidirMap:               SSAASTBidirMap,
		AllServices:                  []grail.Service{{Name: "rpcshielddemo", Tier: 2}, {Name: "httpservicefoo", Tier: 5}},
		opts:                         _defaultDriverOptions,
		simplifiedToDetailedInbound:  make(map[output.EndPoint]fty.InboundPoint),
		simplifiedToDetailedOutbound: make(map[output.EndPoint]fty.OutboundPoint),
		timestampCache:               make(map[string]string),
		Logger:                       zap.NewNop().Sugar(),
	}
	require.Greater(t, len(paths), 0)

	tests := []struct {
		name              string
		callerTier        int
		skipOBTierFilter  bool
		wantResolvedPaths int
	}{
		{name: "lower-tier caller retained with clipping", callerTier: 2, wantResolvedPaths: 3},
		{name: "same-tier caller filtered with clipping", callerTier: 5, wantResolvedPaths: 0},
		{name: "higher-tier caller filtered with clipping", callerTier: 6, wantResolvedPaths: 0},
		{name: "same-tier caller retained without clipping", callerTier: 5, skipOBTierFilter: true, wantResolvedPaths: 3},
		{name: "higher-tier caller retained without clipping", callerTier: 6, skipOBTierFilter: true, wantResolvedPaths: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			driver.opts.SkipOBTierFilter = tt.skipOBTierFilter
			resolvedPaths, _, _, _ := driver.resolveHTTPOutboundService(paths, grail.Service{Name: "rpcshielddemo", Tier: tt.callerTier})
			require.Len(t, resolvedPaths, tt.wantResolvedPaths)
			for _, path := range resolvedPaths {
				require.Equal(t, "httpservicefoo", path.Outbound.Service.Name)
			}
		})
	}
}

func TestDriver_ShouldSkipForMissingProdTraffic(t *testing.T) {
	t.Parallel()

	service := grail.Service{Name: "test-service"}
	missingInboundTraffic := []query.ProdServiceTrafficRecord{
		{
			ServiceName:      service.Name,
			AppearedAsCaller: true,
			AppearedAsCallee: false,
		},
	}
	missingOutboundTraffic := []query.ProdServiceTrafficRecord{
		{
			ServiceName:      service.Name,
			AppearedAsCaller: false,
			AppearedAsCallee: true,
		},
	}

	tests := []struct {
		name                      string
		records                   []query.ProdServiceTrafficRecord
		skipProdTrafficFilter     bool
		callGraphConstructionOnly bool
		want                      bool
	}{
		{
			name: "traffic present",
		},
		{
			name:    "missing inbound traffic",
			records: missingInboundTraffic,
			want:    true,
		},
		{
			name:    "missing outbound traffic",
			records: missingOutboundTraffic,
			want:    true,
		},
		{
			name:                  "gate disabled",
			records:               missingInboundTraffic,
			skipProdTrafficFilter: true,
		},
		{
			name:                      "call graph construction only",
			records:                   missingOutboundTraffic,
			callGraphConstructionOnly: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			driver := &Driver{
				ProdServiceTrafficRecords: tt.records,
				Logger:                    zap.NewNop().Sugar(),
				opts: DriverOptions{
					SkipProdTrafficFilter: tt.skipProdTrafficFilter,
					CGConstructionOnly:    tt.callGraphConstructionOnly,
				},
			}
			require.Equal(t, tt.want, driver.shouldSkipForMissingProdTraffic(service))
		})
	}
}

func TestEnrichReportMetrics(t *testing.T) {
	t.Parallel()
	d := &Driver{Logger: zap.NewNop().Sugar()}

	reports := []output.Report{
		{
			PathResults: []output.PathResult{
				{Status: constant.FailClose, IsAsync: false},
				{Status: constant.FailClose, IsAsync: true},
				{Status: constant.FailOpen, IsAsync: false},
				{Status: constant.FailOpen, IsAsync: true},
				{Status: constant.FailUnknown, IsAsync: false},
				{Status: constant.FailUnknown, IsAsync: true},
			},
		},
		{
			PathResults: []output.PathResult{
				{Status: constant.FailClose, IsAsync: false},
				{Status: constant.FailClose, IsAsync: false},
			},
		},
		{
			PathResults: nil, // empty
		},
	}

	d.enrichReportMetrics(reports, nil)

	// Report 0: one of each status × sync/async.
	r0 := reports[0].PathCounts
	assert.Equal(t, 2, r0.Total.FailClose)
	assert.Equal(t, 1, r0.Sync.FailClose)
	assert.Equal(t, 1, r0.Async.FailClose)
	assert.Equal(t, 2, r0.Total.FailOpen)
	assert.Equal(t, 1, r0.Sync.FailOpen)
	assert.Equal(t, 1, r0.Async.FailOpen)
	assert.Equal(t, 2, r0.Total.FailUnknown)
	assert.Equal(t, 1, r0.Sync.FailUnknown)
	assert.Equal(t, 1, r0.Async.FailUnknown)

	// Report 1: two sync fail-close.
	r1 := reports[1].PathCounts
	assert.Equal(t, 2, r1.Total.FailClose)
	assert.Equal(t, 2, r1.Sync.FailClose)
	assert.Equal(t, 0, r1.Async.FailClose)
	assert.Equal(t, 0, r1.Total.FailOpen)

	// Report 2: no paths, all zeros.
	r2 := reports[2].PathCounts
	assert.Equal(t, 0, r2.Total.FailClose)
	assert.Equal(t, 0, r2.Total.FailOpen)
	assert.Equal(t, 0, r2.Total.FailUnknown)
}

// newTestReport builds a synthetic report with a single call path of the given
// status, made up of edgeCount edges all attributed to the given analyzer kind.
func newTestReport(service string, status constant.Failness, isAsync bool, edgeCount int, kind constant.AnalyzerKind) output.Report {
	edges := make([]*output.EdgeWrapper, edgeCount)
	for i := range edges {
		edges[i] = &output.EdgeWrapper{
			Caller: fmt.Sprintf("caller%d", i),
			Callee: fmt.Sprintf("callee%d", i),
			AnalyzerOutput: output.AnalyzerOutput{
				Status:         status,
				Source:         kind,
				OriginalSource: kind,
			},
		}
	}
	return output.Report{
		Inbound:     output.EndPoint{Service: grail.Service{Name: service}},
		PathResults: []output.PathResult{{Edges: edges, Status: status, IsAsync: isAsync}},
		Status:      status,
	}
}

// TestDriver_AggregateReportMetrics pins down the aggregation invariant: each
// report contributes to the metrics exactly once, no matter how many targets
// the reports were collected from.
//
// Regression test for the aggregation block having lived inside the per-target
// loop while the `reports` slice accumulated across targets, which folded every
// earlier target's reports back in on each iteration and inflated the metrics
// (and the per-edge AnalyzerMetrics rows) quadratically in the target count.
func TestDriver_AggregateReportMetrics(t *testing.T) {
	t.Parallel()

	// Reports as they would be produced by two separate bazel targets of the
	// same service. The driver appends both sets into one slice and aggregates
	// the result once.
	targetAReports := []output.Report{
		newTestReport("svc", constant.FailOpen, false /* isAsync */, 2, constant.SSA),
		newTestReport("svc", constant.FailClose, true /* isAsync */, 3, constant.AST),
	}
	targetBReports := []output.Report{
		newTestReport("svc", constant.FailOpen, true /* isAsync */, 4, constant.SSA),
	}

	tests := []struct {
		name    string
		reports []output.Report

		wantAnalyzerMetricRows int
		wantAnalyzerCounts     map[string]int
		wantFailnessCounts     map[string]int
		wantCallPathLengths    CallPathLengths
	}{
		{
			name:                   "single target",
			reports:                targetAReports,
			wantAnalyzerMetricRows: 5, // 2 + 3 edges
			wantAnalyzerCounts:     map[string]int{"analyzer_ssa_count": 2, "analyzer_ast_count": 3},
			wantFailnessCounts:     map[string]int{"failopen_path_count": 1, "failclose_path_count": 1},
			wantCallPathLengths: CallPathLengths{
				FailOpenSync:   []CallPathLength{{Length: 2, FailOpenDistanceFromOutbound: 1}},
				FailCloseAsync: []CallPathLength{{Length: 3}},
			},
		},
		{
			name:                   "two targets aggregated once",
			reports:                append(append([]output.Report{}, targetAReports...), targetBReports...),
			wantAnalyzerMetricRows: 9, // 2 + 3 + 4 edges, counted once each
			wantAnalyzerCounts:     map[string]int{"analyzer_ssa_count": 6, "analyzer_ast_count": 3},
			wantFailnessCounts:     map[string]int{"failopen_path_count": 2, "failclose_path_count": 1},
			wantCallPathLengths: CallPathLengths{
				FailOpenSync:   []CallPathLength{{Length: 2, FailOpenDistanceFromOutbound: 1}},
				FailOpenAsync:  []CallPathLength{{Length: 4, FailOpenDistanceFromOutbound: 1}},
				FailCloseAsync: []CallPathLength{{Length: 3}},
			},
		},
		{
			name:                   "no reports",
			reports:                nil,
			wantAnalyzerMetricRows: 0,
			wantAnalyzerCounts:     map[string]int{},
			wantFailnessCounts:     map[string]int{},
			wantCallPathLengths:    CallPathLengths{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			d := NewDriver("" /* workspaceRoot */, nil /* runner */, nil /* gp */, nil /* mapper */, nil /* aiClient */, nil /* allServices */, nil /* prodServiceTrafficRecords */, nil /* logger */, _defaultDriverOptions)
			result := &Result{
				RunMetrics:      make(map[string]float64),
				FailnessMetrics: make(map[string]float64),
				CallPathLengths: &CallPathLengths{},
			}

			d.aggregateReportMetrics(result, tt.reports)

			// One metrics row per edge, never more.
			assert.Len(t, result.AnalyzerMetrics, tt.wantAnalyzerMetricRows)
			for name, want := range tt.wantAnalyzerCounts {
				assert.Equal(t, want, int(result.RunMetrics[name]), "run metric %q", name)
			}
			for name, want := range tt.wantFailnessCounts {
				assert.Equal(t, want, int(result.FailnessMetrics[name]), "failness metric %q", name)
			}
			assert.Equal(t, tt.wantCallPathLengths.FailOpenSync, result.CallPathLengths.FailOpenSync)
			assert.Equal(t, tt.wantCallPathLengths.FailOpenAsync, result.CallPathLengths.FailOpenAsync)
			assert.Equal(t, tt.wantCallPathLengths.FailCloseSync, result.CallPathLengths.FailCloseSync)
			assert.Equal(t, tt.wantCallPathLengths.FailCloseAsync, result.CallPathLengths.FailCloseAsync)
		})
	}
}
