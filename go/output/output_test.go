package output

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"mock/github.com/uber-research/rpcshield/go/output/outputmock"

	"github.com/stretchr/testify/require"
	"github.com/uber-research/rpcshield/go/constant"
	"github.com/uber-research/rpcshield/go/grail"
	"go.uber.org/mock/gomock"
)

func TestReport_Codec(t *testing.T) {
	t.Parallel()

	report := Report{
		Inbound: EndPoint{
			Service: grail.Service{
				Name:   "cff-demo",
				Tier:   1,
				GitURI: grail.GoCodeGitURI,
			},
			APIName: "uber.infra.progsys.cffdemo.cffdemo__create",
		},
		Outbound: EndPoint{
			Service: grail.Service{
				Name:   "lottery",
				Tier:   5,
				GitURI: grail.GoCodeGitURI,
			},
			APIName: "lottery.get",
		},
		PathResults: []PathResult{
			{
				Edges: []*EdgeWrapper{
					{
						Caller:          "UserService.CreateUser",
						Callee:          "DatabaseService.WriteToDB",
						Filepath:        "src/user_service/create_user.go",
						SourceGraphLink: "https://sourcegraph.com/repo/user_service/-/blob/create_user.go?L42",
						AnalyzerOutput: AnalyzerOutput{
							Status:         constant.FailClose,
							DiagnosticMsg:  "Potential SQL injection vulnerability.",
							Source:         constant.AST,
							OriginalSource: constant.AST,
						},
						Errors: []string{"LLM analyzer timed out"},
					},
				},
				Status: constant.FailClose,
			},
			{
				Edges: []*EdgeWrapper{
					{
						Caller:          "UserService.CreateUser",
						Callee:          "AuthService.ValidateSession",
						Filepath:        "/src/user_service/session.go",
						SourceGraphLink: "https://sourcegraph.com/repo/user_service/-/blob/session.go?L10",
						AnalyzerOutput: AnalyzerOutput{
							Status:         constant.FailClose,
							DiagnosticMsg:  "No issues detected.",
							Source:         constant.SSA,
							OriginalSource: constant.SSA,
						},
						Errors: []string{"AST error", "LLM error"},
					},
				},
				Status: constant.FailOpen,
			},
		},
		Status: constant.FailClose, // Aggregated status from PathResults
	}

	b, err := json.Marshal(report)
	require.NoError(t, err)
	require.NotEmpty(t, b)

	var decoded Report
	err = json.Unmarshal(b, &decoded)
	require.NoError(t, err)

	require.Equal(t, report, decoded)
}

func TestReport_Decode(t *testing.T) {
	t.Parallel()

	// Our decoding logic should gracefully handle any old formats of the report such that it will
	// not cause an error in UIS.
	//
	// The testcases here are retrieved from the internal analytics warehouse tables that store
	// production and staging report rows, for collecting historical formats
	// of the report to test our decoding logic.

	testdata := "testdata"

	var reports []string
	err := filepath.WalkDir(testdata, func(path string, d fs.DirEntry, err error) error {
		name := filepath.Base(path)
		if !strings.HasPrefix(name, "report") || filepath.Ext(name) != ".json" {
			return nil
		}
		reports = append(reports, path)
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, reports)

	reportObjs := make([]Report, 0, len(reports))
	for _, path := range reports {
		fp, err := os.Open(path)
		require.NoError(t, err)
		var report Report
		err = json.NewDecoder(fp).Decode(&report)
		require.NoErrorf(t, err, "should be able to decode old format of report, see %q", path)
		require.NotEmpty(t, report)
		if len(report.PathResults) == 0 || report.Status == constant.FailUnknown || report.Status == constant.FailUnknownWithError {
			require.Empty(t, report.Diagnostics())
		} else {
			require.NotEmpty(t, report.Diagnostics())
		}

		reportObjs = append(reportObjs, report)
	}

	// Test if the report has more than one call path
	multiplePathReport := Report{
		PathResults: []PathResult{
			reportObjs[0].PathResults[0],
			reportObjs[0].PathResults[0],
		},
		Status: constant.FailClose,
	}
	require.NotEmpty(t, multiplePathReport.Diagnostics())

	// Test if the report has more paths than the limit (_maxPathsInReport)
	manyPathReport := Report{
		PathResults: []PathResult{
			reportObjs[0].PathResults[0],
			reportObjs[0].PathResults[0],
			reportObjs[0].PathResults[0],
			reportObjs[0].PathResults[0],
			reportObjs[0].PathResults[0],
			reportObjs[0].PathResults[0],
			reportObjs[0].PathResults[0],
			reportObjs[0].PathResults[0],
			reportObjs[0].PathResults[0],
			reportObjs[0].PathResults[0],
		},
		Status: constant.FailClose,
	}
	s := manyPathReport.Diagnostics()
	require.NotEmpty(t, s)
	require.Contains(t, s, fmt.Sprintf("Selected %d of %d", _maxPathsInReport, len(manyPathReport.PathResults)))

	// Test edge case: if report is not FailClose
	failOpenReport := reportObjs[0]
	failOpenReport.Status = constant.FailOpen
	require.Empty(t, failOpenReport.Diagnostics())

	// Test edge case: if report is empty
	emptyReport := Report{}
	require.Empty(t, emptyReport.Diagnostics())

	// Test edge case: of report's PathResults has no SourceGraphLink
	noSourceGraphLinkReport := reportObjs[0]
	noSourceGraphLinkReport.PathResults[0].Edges[0].SourceGraphLink = ""
	require.NotEmpty(t, noSourceGraphLinkReport.Diagnostics())

	// Test edge case: if report has no FailClose paths
	var noFailClosePaths []PathResult
	for _, pathResult := range reportObjs[0].PathResults {
		noFailClosePaths = append(noFailClosePaths, PathResult{
			Edges:  pathResult.Edges,
			Status: constant.FailOpen,
		})
	}
	noFailCloseReport := reportObjs[0]
	noFailCloseReport.PathResults = noFailClosePaths
	require.Empty(t, noFailCloseReport.Diagnostics())

	// Test edge case: if report's PathResults has empty edges
	emptyEdgesReport := Report{
		PathResults: []PathResult{
			{
				Edges: nil,
			},
		},
		Status: constant.FailClose,
	}
	require.Empty(t, emptyEdgesReport.Diagnostics())
}

func TestAggregatedStatus(t *testing.T) {
	tests := []struct {
		name        string
		edgeResults []*EdgeWrapper
		expected    constant.Failness
	}{
		{
			name:        "No edges",
			edgeResults: []*EdgeWrapper{},
			expected:    constant.FailUnknownWithError,
		},
		{
			name: "Single edge FailClose",
			edgeResults: []*EdgeWrapper{
				{AnalyzerOutput: AnalyzerOutput{Status: constant.FailClose}},
			},
			expected: constant.FailClose,
		},
		{
			name: "Multiple edges with FailOpen",
			edgeResults: []*EdgeWrapper{
				{AnalyzerOutput: AnalyzerOutput{Status: constant.FailClose}},
				{AnalyzerOutput: AnalyzerOutput{Status: constant.FailOpen}},
			},
			expected: constant.FailOpen,
		},
		{
			name: "Multiple edges with FailUnknown",
			edgeResults: []*EdgeWrapper{
				{AnalyzerOutput: AnalyzerOutput{Status: constant.FailClose}},
				{AnalyzerOutput: AnalyzerOutput{Status: constant.FailUnknown}},
			},
			expected: constant.FailUnknown,
		},
		{
			name: "Multiple edges with FailUnknownWithError",
			edgeResults: []*EdgeWrapper{
				{AnalyzerOutput: AnalyzerOutput{Status: constant.FailClose}},
				{AnalyzerOutput: AnalyzerOutput{Status: constant.FailUnknownWithError}},
			},
			expected: constant.FailUnknownWithError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AggregatedStatus(tt.edgeResults)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestFlamegraph(t *testing.T) {
	t.Parallel()

	report := Report{
		// not setting Inbound and Outbound for this test since they are not used in Flamegraph.
		PathResults: []PathResult{
			{
				Edges: []*EdgeWrapper{
					{
						Caller: "C2",
						Callee: "Leaf",
					},
					{
						Caller: "C1",
						Callee: "C2",
					},
					{
						Caller: "Root",
						Callee: "C1",
					},
				},
			},
			{
				Edges: []*EdgeWrapper{
					{
						Caller: "D2",
						Callee: "Leaf",
					},
					{
						Caller: "D1",
						Callee: "D2",
					},
					{
						Caller: "Root",
						Callee: "D1",
					},
				},
			},
			{
				Edges: []*EdgeWrapper{
					{
						Caller: "E2",
						Callee: "Leaf",
					},
					{
						Caller: "E1",
						Callee: "E2",
					},
					{
						Caller: "Root",
						Callee: "E1",
					},
				},
			},
		},
	}

	ctrl := gomock.NewController(t)
	runner := outputmock.NewMockRunner(ctrl)
	runner.EXPECT().Run(gomock.Any()).DoAndReturn(func(cmd *exec.Cmd) error {
		return nil
	}).AnyTimes()
	_, err := report.FlamegraphSVG(runner, "")
	require.NoError(t, err)
}

func TestSortPathResults_Deterministic(t *testing.T) {
	t.Parallel()

	pathA := PathResult{
		Status: constant.FailClose,
		Edges: []*EdgeWrapper{
			{Caller: "svcA.handler", Callee: "svcB.get", Filepath: "a.go", CalleeLineNo: 10},
		},
	}
	pathB := PathResult{
		Status: constant.FailClose,
		Edges: []*EdgeWrapper{
			{Caller: "svcA.handler", Callee: "svcC.list", Filepath: "b.go", CalleeLineNo: 20},
		},
	}
	pathC := PathResult{
		Status: constant.FailOpen,
		Edges: []*EdgeWrapper{
			{Caller: "svcA.worker", Callee: "svcD.write", Filepath: "c.go", CalleeLineNo: 5},
		},
	}
	// Same edges as pathA but async: must sort to a distinct, stable position.
	pathAAsync := PathResult{
		Status:  constant.FailClose,
		IsAsync: true,
		Edges: []*EdgeWrapper{
			{Caller: "svcA.handler", Callee: "svcB.get", Filepath: "a.go", CalleeLineNo: 10},
		},
	}

	// Feed several different input permutations of the same set; every one must
	// produce the identical, canonical ordering.
	permutations := [][]PathResult{
		{pathA, pathB, pathC, pathAAsync},
		{pathAAsync, pathC, pathB, pathA},
		{pathC, pathA, pathAAsync, pathB},
		{pathB, pathAAsync, pathA, pathC},
	}

	var want []PathResult
	for i, perm := range permutations {
		r := Report{PathResults: make([]PathResult, len(perm))}
		copy(r.PathResults, perm)
		r.SortPathResults()
		got := r.PathResults

		if i == 0 {
			want = got
			continue
		}
		require.Equal(t, want, got, "permutation %d produced a different order", i)
	}

	// Sorting is idempotent.
	again := Report{PathResults: make([]PathResult, len(want))}
	copy(again.PathResults, want)
	again.SortPathResults()
	require.Equal(t, want, again.PathResults)
}

func TestSortPathResults_Empty(t *testing.T) {
	t.Parallel()

	// Must not panic on nil or empty path results.
	(&Report{}).SortPathResults()
	(&Report{PathResults: []PathResult{}}).SortPathResults()
}
