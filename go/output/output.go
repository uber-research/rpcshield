package output

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/bazelbuild/rules_go/go/runfiles"
	"github.com/uber-research/rpcshield/go/common/utils"
	"github.com/uber-research/rpcshield/go/constant"
	"github.com/uber-research/rpcshield/go/grail"
)

// FlamegraphPlRlocation is the runfiles-relative path (joined with the Bazel workspace name) to
// the flamegraph.pl script. It defaults to this package's location in a monorepo checkout; forks
// with a different repo layout (e.g. a flat top-level "output/" directory) should override it to
// match where flamegraph.pl actually lands in their own runfiles tree.
var FlamegraphPlRlocation = "src/github.com/uber-research/rpcshield/go/output/flamegraph.pl"

// _maxPathsInReport is the maximum number of paths to be reported in a Jira ticket between an inbound and an outbound.
const _maxPathsInReport = 3

// SyntheticID is the synthetic indicator string to inject into the report to indicate the success of the analysis.
const SyntheticID = "<synthetic-ID-indicating-success-of-analysis>"

// AnalyzerOutput stores the output of the analyzer
type AnalyzerOutput struct {
	Status         constant.Failness     `json:"status"`          // Fail-ness status of the caller-callee pair
	DiagnosticMsg  string                `json:"diagnostic_msg"`  // Diagnostic message explaining the reason for the fail-ness status
	Source         constant.AnalyzerKind `json:"source"`          // Source of the analyzer output (AST, SSA, LLM, Predefined, and Cache). This is only meant for our internal analytics.
	OriginalSource constant.AnalyzerKind `json:"original_source"` // In case of Source = Cache, OriginalSource gives the source of the original analysis (AST, SSA, LLM, Predefined). This is only meant for our internal analytics.
}

// EdgeWrapper wraps a callgraph.Edge with a link to SourceGraph file.
type EdgeWrapper struct {
	// Caller, callee are the names of the caller and callee functions.
	Caller string `json:"caller"`
	Callee string `json:"callee"`
	// Filepath is the path to the source file containing the caller.
	Filepath string `json:"file_path"`
	// SourceGraphLink points to the callee site within the caller's source code.
	SourceGraphLink string `json:"source_graph_link"`
	// AnalyzerOutput stores the analysis result from the analyzer.
	AnalyzerOutput AnalyzerOutput `json:"analyzer_output"`
	// Errors stores the slice of errors that occurred during the analysis for debugging purposes.
	Errors []string `json:"errors"`
	// CallerLastModifiedTimestamp keep the last modified timestamp of the calllee function of the edge.
	CallerLastModifiedTimestamp string `json:"caller_last_modified_timestamp"`
	// CalleeLineNo is the line number of the callee function.
	CalleeLineNo int `json:"callee_line_no,omitempty"`
	// CallerBeginLineNo is the line number of the first line of the caller function.
	CallerBeginLineNo int `json:"caller_begin_line_no,omitempty"`
	// CallerEndLineNo is the line number of the last line of the caller function.
	CallerEndLineNo int `json:"caller_end_line_no,omitempty"`
}

// PathResult is the result of rpcshield's analysis for a particular call path.
type PathResult struct {
	// Edges is the path from the inbound to the outbound, consisting analyzer output for each edge.
	// Note that the edges are stored in reverse order, i.e., from outbound to inbound.
	Edges []*EdgeWrapper `json:"edges"`
	// Status is the final fail-ness status of the path.
	Status constant.Failness `json:"status"`
	// IsAsync indicates if the path includes an async call.
	IsAsync bool `json:"is_async"`
}

// EndPoint represents a service endpoint.
type EndPoint struct {
	// Service is the service that the endpoint belongs to.
	Service grail.Service `json:"service"`
	// APIName is the name of the API that the endpoint represents.
	APIName string `json:"api_name"`
}

// Report is the output of rpcshield's analysis between a particular inbound and outbound pair.
type Report struct {
	// Unique identifier for the report
	ID string `json:"id"`
	// Inbound is the inbound point of the path.
	Inbound EndPoint `json:"inbound"`
	// Outbound is the outbound point of the path.
	Outbound EndPoint `json:"outbound"`
	// TotalPaths is the number of paths between the inbound and outbound.
	TotalPaths int `json:"total_paths"`
	// PathResults is the analysis result for all the paths between the inbound and outbound.
	// Note that PathResults may be a truncated list, if the number of paths exceeds constant.MaxPathsToStoreForQuadruple.
	PathResults []PathResult `json:"path_results"`
	// Status is the final fail-ness status for the inbound-outbound pair, aggregated from all the paths.
	Status constant.Failness `json:"status"`
	// Flamegraph is the SVG flamegraph of the path.
	Flamegraph template.HTML `json:"flamegraph"`
	// PermutationThresholdHit indicates whether the permutation threshold was hit for this IB-OB quadruple.
	PermutationThresholdHit bool `json:"permutation_threshold_hit"`
	// PathCounts holds per-IB-OB path count breakdowns by fail-ness and sync/async.
	PathCounts PathCounts `json:"path_counts"`
}

// FailnessCounts holds path counts for each fail-ness status.
type FailnessCounts struct {
	FailClose   int `json:"fail_close"`
	FailOpen    int `json:"fail_open"`
	FailUnknown int `json:"fail_unknown"`
}

// PathCounts holds per-IB-OB path count breakdown by total, sync, and async.
type PathCounts struct {
	Total FailnessCounts `json:"total"`
	Sync  FailnessCounts `json:"sync"`
	Async FailnessCounts `json:"async"`
}

// ReportSummary is a lightweight per-IB-OB summary for JSON output.
type ReportSummary struct {
	Inbound                 EndPoint          `json:"inbound"`
	Outbound                EndPoint          `json:"outbound"`
	Status                  constant.Failness `json:"status"`
	TotalPaths              int               `json:"total_paths"`
	PathCounts              PathCounts        `json:"path_counts"`
	PermutationThresholdHit bool              `json:"permutation_threshold_hit"`
}

// Merge merges the other report into the current report. Specifically, merge path results and status.
func (r *Report) Merge(otherReport Report) {
	r.PathResults = append(r.PathResults, otherReport.PathResults...)

	// Merge the status of the reports following the precedence order: FailClose > FailUnknownWithError > FailUnknown > FailOpen.
	// If at least one of the reports is FailClose, then the merged report status should be FailClose.
	r.Status = utils.MergeStatus(r.Status, otherReport.Status, constant.OrderMapFailClosePriority)
}

// SortPathResults orders the report's path results into a deterministic,
// canonical order.
//
// RPCShield enumerates call paths in a nondeterministic order: the ordering
// derives from Go map iteration during call-tree traversal. As a result, the
// subset of paths stored per inbound-outbound quadruple (capped by
// constant.MaxPathsToStoreForQuadruple) and the "first N paths" surfaced
// downstream (e.g. the paths listed in a Jira ticket via Report.Diagnostics)
// could vary between otherwise-identical runs. Sorting by a stable key derived
// from each path's status and edges restores run-to-run determinism.
func (r *Report) SortPathResults() {
	// Compute each path's sort key exactly once up front, so keys are not
	// recomputed on every comparison during the sort.
	type keyedPath struct {
		key  string
		path PathResult
	}
	decorated := make([]keyedPath, len(r.PathResults))
	for i, p := range r.PathResults {
		decorated[i] = keyedPath{key: p.sortKey(), path: p}
	}
	slices.SortFunc(decorated, func(a, b keyedPath) int {
		return strings.Compare(a.key, b.key)
	})
	for i, d := range decorated {
		r.PathResults[i] = d.path
	}
}

// sortKey builds a stable, canonical ordering key for the path result from its
// status and the sequence of caller->callee edges it traverses.
func (p PathResult) sortKey() string {
	var sb strings.Builder
	sb.WriteString(string(p.Status))
	if p.IsAsync {
		sb.WriteString("|async")
	}
	for _, e := range p.Edges {
		sb.WriteByte('|')
		sb.WriteString(e.Caller)
		sb.WriteByte('>')
		sb.WriteString(e.Callee)
		sb.WriteByte('@')
		sb.WriteString(e.Filepath)
		sb.WriteByte(':')
		sb.WriteString(strconv.Itoa(e.CalleeLineNo))
	}
	return sb.String()
}

// Diagnostics returns a string representation of the report.
func (r *Report) Diagnostics() string {
	if r.Status != constant.FailClose || len(r.PathResults) == 0 {
		return ""
	}

	// Collect FailClose paths only
	var failClosePaths []PathResult
	for _, pathResult := range r.PathResults {
		if pathResult.Status == constant.FailClose && len(pathResult.Edges) > 0 {
			failClosePaths = append(failClosePaths, pathResult)
		}
	}
	if len(failClosePaths) == 0 {
		return ""
	}

	sb := strings.Builder{}
	sb.WriteString("h1.Call path diagnostics:\n")

	limitMsg := ""
	originalNumPaths := len(failClosePaths)
	// Limit the number of paths to be reported for better readability.
	if len(failClosePaths) > _maxPathsInReport {
		failClosePaths = failClosePaths[:_maxPathsInReport]
		limitMsg = fmt.Sprintf("Selected %d of ", len(failClosePaths))
	}
	sb.WriteString(fmt.Sprintf("%s%d FailClose path(s) found between the two endpoints:\n\n", limitMsg, originalNumPaths))

	for i, path := range failClosePaths {
		sb.WriteString(fmt.Sprintf("h3. Path %d (outbound to inbound):\n", i+1))
		sb.WriteString(fmt.Sprintf("| |%s|\n", path.Edges[0].Callee))
		for j := 0; j < len(path.Edges); j++ {
			if len(path.Edges[j].SourceGraphLink) > 0 {
				sb.WriteString(fmt.Sprintf("|called by|[%s|%s]|\n", path.Edges[j].Caller, path.Edges[j].SourceGraphLink))
			} else {
				sb.WriteString(fmt.Sprintf("|called by|%s|\n", path.Edges[j].Caller))
			}
		}
	}

	// Add slack support channel message.
	sb.WriteString("\n\n**Please reach out to us at " +
		"[#rpcshield-support|https://uber.slack.com/archives/C08BC27QTLL] " +
		"if you think any FailClose path above is unclear or incorrect.*")

	return sb.String()
}

func getFlamegraphPlPath(ws string) (string, error) {
	// Create a Runfiles handle.
	rf, err := runfiles.New()
	if err != nil {
		return "", fmt.Errorf("could not create runfiles: %v", err)
	}
	scriptPath, err := rf.Rlocation(filepath.Join(ws, FlamegraphPlRlocation))
	if err != nil {
		return "", fmt.Errorf("could not find the flamegraph.pl script: %v", err)
	}
	return scriptPath, nil
}

// Runner runs a command. It matches execrunner.Runner's signature so callers can pass an
// execrunner.Runner (or any other type with this method) without an adapter.
type Runner interface {
	Run(*exec.Cmd) error
}

// FlamegraphSVG returns the flamegraph of the report in SVG format.
// It first converts the flamegraph to the format that Brendan Gregg's flamegraph tool accepts.
// Then, it calls the flamegraph tool to generate the SVG.
func (r *Report) FlamegraphSVG(runner Runner, ws string) (template.HTML, error) {
	// Convert the flamegraph to the format that Brendan Gregg's flamegraph tool accepts.
	flamegraph := r.brandongreggFlamegraph()
	perlScript, err := getFlamegraphPlPath(ws)
	if err != nil {
		return template.HTML(""), fmt.Errorf("failed to get the path to the flamegraph.pl script: %v", err)
	}
	cmd := exec.Command(perlScript)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return template.HTML(""), fmt.Errorf("failed to run the flamegraph command: %v", err)
	}

	go func() {
		defer stdin.Close()
		io.WriteString(stdin, flamegraph)
	}()

	if err := runner.Run(cmd); err != nil {
		return template.HTML(""), fmt.Errorf("failed to run the flamegraph command: %v", err)
	}

	// Convert output to a string for further usage.
	return template.HTML(stdout.String()), nil
}

// brandongreggFlamegraph returns the flamegraph of the report in Brendan Gregg's flamegraph format.
// Flamegraph format:
// <stack root to leaf> <count>
// where <stack> is a semi-colon-separated list of function names, and <count> is the number of times the stack occurred.
// TODO: create separate graphs for fail-open and fail-close paths.
func (r *Report) brandongreggFlamegraph() string {
	// Collect all paths from Caller (root) to Callee (leaf) in the report.
	var paths [][]string = make([][]string, 0, len(r.PathResults))
	for _, pathResult := range r.PathResults {
		if len(pathResult.Edges) == 0 {
			continue
		}
		path := make([]string, 0, len(pathResult.Edges)+1) // +1 for the leaf node (callee).
		for i := len(pathResult.Edges) - 1; i >= 0; i-- {
			// Add the caller to the path.
			path = append(path, pathResult.Edges[i].Caller)
		}
		// Add the leaf node (callee) to the path first.
		path = append(path, pathResult.Edges[0].Callee)
		// Add the path to the paths.
		paths = append(paths, path)
	}
	// Write to string in flamegraph format.
	sb := strings.Builder{}
	for _, path := range paths {
		sb.WriteString(strings.Join(path, ";") + " 1\n")
	}
	return sb.String()
}

// AggregatedStatus returns the aggregated status of the path, which is the final status of the path.
// edgeResults is the slice of analysis results for each edge (outbound to inbound order) in the path.
func AggregatedStatus(edgeResults []*EdgeWrapper) constant.Failness {
	// Status is the result of the last edge (i.e., inbound point) in the path.
	// The status is set to FailUnknownWithError, if there are no edges in the path, which is an unexpected case.
	status := constant.FailUnknownWithError
	if len(edgeResults) > 0 {
		// We now find the final status of the path by merging the statuses of the edges in the path.
		// We merge the statuses following the precedence: FailOpen > FailUnknownWithError > FailUnknown > FailClose,
		// i.e., if any edge in the path is FailOpen, the path is FailOpen.
		status = edgeResults[len(edgeResults)-1].AnalyzerOutput.Status
		for i := len(edgeResults) - 2; i >= 0; i-- {
			currStatus := edgeResults[i].AnalyzerOutput.Status
			status = utils.MergeStatus(status, currStatus, constant.OrderMapFailOpenPriority)
		}
	}
	return status
}
