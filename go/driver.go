package rpcshield

import (
	"context"
	_ "embed" // Using `embed` to embed the SVG template file
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/types"
	"html/template"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/uber-research/rpcshield/go/bazel"
	"github.com/uber-research/rpcshield/go/common/edgeinfo"
	"github.com/uber-research/rpcshield/go/common/mapper"
	"github.com/uber-research/rpcshield/go/common/pkgdeps"
	"github.com/uber-research/rpcshield/go/common/utils"
	"github.com/uber-research/rpcshield/go/config"
	"github.com/uber-research/rpcshield/go/constant"
	"github.com/uber-research/rpcshield/go/finder"
	"github.com/uber-research/rpcshield/go/finder/servicemapping"
	fty "github.com/uber-research/rpcshield/go/finder/types"
	"github.com/uber-research/rpcshield/go/genai"
	"github.com/uber-research/rpcshield/go/grail"
	"github.com/uber-research/rpcshield/go/graph"
	"github.com/uber-research/rpcshield/go/input"
	"github.com/uber-research/rpcshield/go/loader"
	"github.com/uber-research/rpcshield/go/output"
	"github.com/uber-research/rpcshield/go/query"
	"github.com/uber-research/rpcshield/go/reporting"
	"github.com/uber-research/rpcshield/go/staticanalyzer/asthelper"
	"github.com/uber-research/rpcshield/go/staticanalyzer/cacheanalyzer"
	"github.com/uber-research/rpcshield/go/staticanalyzer/function"
	"github.com/uber-research/rpcshield/go/staticanalyzer/predefined"
	"github.com/uber-research/rpcshield/go/staticanalyzer/ssaanal"
	"go.uber.org/zap"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

var gatewayPathRegex = regexp.MustCompile(`gateways?/(.+)$`)

// Driver is the top-level driver for rpcshield.
type Driver struct {
	// WorkspaceRoot is the root of the workspace.
	WorkspaceRoot string
	// Runner is the runner interface for running commands.
	Runner utils.Runner
	// AIClient is the AI client for LLM service.
	AIClient genai.Client
	// ServiceMapper is the service mapper for mapping IDL client package paths to services.
	ServiceMapper servicemapping.ServiceMapper
	// AllServices is the list of all services fetched from Grail.
	AllServices []grail.Service
	// ProdServiceTrafficRecords is the list of production service traffic records.
	ProdServiceTrafficRecords []query.ProdServiceTrafficRecord
	// Logger is an optional logger for logging purposes.
	Logger *zap.SugaredLogger
	// GoPathWrapper is the GoPathWrapper interface for running Bazel commands.
	GoPathWrapper  bazel.GoPathWrapper
	SSAASTBidirMap mapper.SSAASTMap
	SigASTBidirMap mapper.SignatureASTMap

	// The mapping from simplified to detailed inbound and outbound points is used for Jira ticketing via Bugspy.
	// TODO: this is a temporary solution. We should revisit this to make it synchronous with UIS.
	simplifiedToDetailedInbound  map[output.EndPoint]fty.InboundPoint
	simplifiedToDetailedOutbound map[output.EndPoint]fty.OutboundPoint
	cacheAnalyzer                cacheanalyzer.CacheAnalyzer
	opts                         DriverOptions
	timestampCache               map[string]string
	callerCalleeSites            map[*ssa.Function][]*ssa.Call
	sccpMetrics                  *ssaanal.SCCPAggregateMetrics
	analyzerDurations            map[string]float64
}

// DriverOptions is the optional configurations for the driver.
type DriverOptions struct {
	// SkipOBTierFilter is the flag to disable OB clipping by the callee tiers.
	SkipOBTierFilter bool
	// SkipProdTrafficFilter disables skipping services without observed inbound or outbound production traffic.
	SkipProdTrafficFilter bool
	// Report indicates whether to report rpcshield's findings.
	Report bool
	// Analyzers is the list of analyzers (SSA, AST, LLM) to run for fail-ness detection.
	Analyzers map[constant.AnalyzerKind]bool
	// GitSHA is the Git SHA of the commit analyzed.
	GitSHA string
	// CSV is the flag to write the report to a CSV file.
	CSV bool
	// HTML is the flag to write the report to an HTML file.
	HTML bool
	// OutputDir is the directory to write the report CSV file to.
	OutputDir string
	// Timestamp is the timestamp to store the date/time when rpcshield is run.
	Timestamp string
	// ShortCallerName is the flag to use the short caller name.
	ShortCallerName bool
	// SGLinkRemoteHash is the flag to use the SG link hash.
	SGLinkRemoteHash bool
	// BaseSHA is the base SHA to compare against.
	BaseSHA string
	// DisableSCCPAnalysis disables SCCP (Sparse Conditional Constant Propagation) analysis.
	DisableSCCPAnalysis bool
	// NilOtherSourcesAfterSrc, when true, sets OtherSources to Nil
	// (instead of Top) when they appear after Src in the CFG.
	NilOtherSourcesAfterSrc bool
	// RTAFlavor is the RTA implementation flavor for the normal Build path.
	RTAFlavor string
	// RTANumWorkers is the number of workers for the normal Build path.
	RTANumWorkers string
	// RTABenchFlavors is the comma-separated list of RTA flavors for CG construction-only benchmarking, or "all".
	RTABenchFlavors string
	// RTABenchNumWorkers is the comma-separated list of worker counts for CG construction-only benchmarking.
	RTABenchNumWorkers string
	// DisableParallelCallTree is the flag to disable parallel call tree computation.
	DisableParallelCallTree bool
	// KeepIBPkgs is an allowlist of packages that should always be analyzed during inbound detection, even if they fall outside heuristics.
	KeepIBPkgs map[string]bool
	// CGConstructionOnly is the flag to only run CG construction for eval bench (skip outbound detection and path analysis).
	CGConstructionOnly bool
	// CheckIsomorphism enables isomorphism checking between srta and prta_kumo_nonblocking.
	CheckIsomorphism bool
	// PermutationThreshold is the number of times the same function-set hash must
	// be observed reaching a sink before permutation detection triggers. Default is 100. Set to 0 to disable.
	PermutationThreshold int64
	// CanonicalEdgeOrder sorts every call-graph node's outgoing edges into a deterministic
	// order before path exploration, so convergence pruning does not depend on package load
	// order. Opt-in; see graph.Config.CanonicalEdgeOrder.
	CanonicalEdgeOrder bool
	// Config carries Uber-specific settings (Sourcegraph/Terrablob URL templates, code path
	// prefix, CSV repo name, service allowlists) that packages in this repo depend on. Zero
	// value disables the corresponding link/heuristic.
	Config config.Config
	// BazelLoader, when set, is called instead of GoPathWrapper.LiftGoPath + loader.LoadAll for
	// services listed in Config.BazelLoaderServices -- a faster, Bazel-query-based package loader
	// used for services that otherwise time out lifting a GOPATH. Nil (the OSS default) disables
	// this fast path entirely, always using GoPathWrapper instead.
	// json:"-" since encoding/json can't marshal a func -- and would otherwise abort marshaling
	// this whole struct (used for the "Running rpcshield driver" options log line) at the first
	// func/interface field it hits, silently dropping every field after it too.
	BazelLoader func(targetPkgPath string) ([]*packages.Package, error) `json:"-"`
	// KeepGoPathAfterRun disables the best-effort background cleanup of a lifted GOPATH directory
	// after a run. Uber's devpod environment sets this since its cache disk is large enough that
	// skipping cleanup is faster for subsequent runs; the OSS default (false) always cleans up.
	KeepGoPathAfterRun bool
	// TargetResolver resolves a service name to its Bazel targets. Nil defaults to
	// NewPinocchioTargetResolver (Uber's udeploy/pinocchio/<service>/production.yaml convention),
	// used by both the OSS CLI and Uber's monorepo wiring unless overridden. Ignored if Targets is
	// set directly. See Driver.RunOnGoPath/Driver.RunOnPackages for callers who want to skip target
	// resolution entirely.
	TargetResolver InboundTargetResolver `json:"-"`
	// Targets, when non-empty, is used directly as the Bazel targets for Driver.Run instead of
	// consulting TargetResolver -- lets a caller bypass service-name-to-target resolution
	// entirely while still going through the normal GoPathWrapper/BazelLoader package-loading path.
	Targets []string
	// ForceLoaderMode, when non-empty, overrides Config.BazelLoaderServices' per-service allowlist
	// for this run: "bazel" forces every target through the BazelLoader path, "gopath" forces every
	// target through GoPathWrapper.LiftGoPath. Empty (the default) preserves the allowlist behavior.
	ForceLoaderMode string
	// PackageSource, when set, is called once per target instead of the default
	// BazelLoader-or-GoPathWrapper+loader.LoadAll pipeline, to obtain packages/SSA for that target.
	// This is the seam for callers who already have prepared source (a pre-lifted GOPATH directory,
	// or already-loaded packages) and want to skip Bazel/GoPathWrapper entirely. See
	// Driver.RunOnGoPath/Driver.RunOnPackages for the corresponding convenience entrypoints.
	PackageSource func(target string) (pkgs []*packages.Package, ssaPkgs []*ssa.Package, ssaProg *ssa.Program, err error) `json:"-"`
}

// NewDriver returns a new Driver instance.
func NewDriver(workspaceRoot string, runner utils.Runner, gp bazel.GoPathWrapper, mapper servicemapping.ServiceMapper, aiClient genai.Client, allServices []grail.Service, prodServiceTrafficRecords []query.ProdServiceTrafficRecord, logger *zap.SugaredLogger, opts DriverOptions) *Driver {
	// Create a no-op logger if not provided to avoid nil panics.
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}
	return &Driver{
		WorkspaceRoot:             workspaceRoot,
		Runner:                    runner,
		AIClient:                  aiClient,
		AllServices:               allServices,
		ProdServiceTrafficRecords: prodServiceTrafficRecords,
		ServiceMapper:             mapper,
		GoPathWrapper:             gp,
		Logger:                    logger,
		opts:                      opts,
		cacheAnalyzer:             cacheanalyzer.NewCacheAnalyzer(),
	}
}

const (
	_graphBuildingDurationSecs         = "graph_building_duration_secs"
	_ssaAstMappingDurationSecs         = "ssa_ast_mapping_duration_secs"
	_analysisDurationSecs              = "analysis_duration_secs"
	_pkgCount                          = "pkg_count"
	_ssaPkgCount                       = "ssa_pkg_count"
	_targetCount                       = "target_count"
	_inboundCount                      = "inbound_count"
	_outboundCount                     = "outbound_count"
	_filteredOutboundCount             = "filtered_outbound_count"
	_outboundMissingServiceCountPrefix = "outbound_missing_service_count_"
	_findTargetDurationSecs            = "find_target_duration_secs"
	_liftGoPathDurationSecs            = "lift_go_path_duration_secs"
	_pkgLoadingDurationSecs            = "pkg_loading_duration_secs"
	_ibObDetectionDurationSecs         = "ib_ob_detection_duration_secs"
	_totalDurationSecs                 = "total_duration_secs"
	_maxUsedDramKB                     = "max_used_dram_kb"
	_outboundCountBeforeFilterPrefix   = "outbound_count_before_filter_"
	_outboundCountAfterFilterPrefix    = "outbound_count_after_filter_"
	_resolvedHTTPOutboundCountPrefix   = "resolved_http_outbound_count"
	_sccpAnalysisDurationSecs          = "sccp_analysis_duration_secs"
	_ssaAnalyzerDurationSecs           = "ssa_analyzer_duration_secs"
	_astAnalyzerDurationSecs           = "ast_analyzer_duration_secs"
)

// Status represents the overall status of the rpcshield run.
type Status string

const (
	// Success indicates that the rpcshield run was successful to the end.
	Success Status = "success"
	// SuccessNoProdIBOBTraffic indicates that rpcshield run was successful due to no production inbound or outbounds.
	SuccessNoProdIBOBTraffic Status = "success_no_ibob_traffic"
	// SuccessNoCrossTierOutbounds indicates that rpcshield run was successful due to no cross-tier outbounds found.
	SuccessNoCrossTierOutbounds Status = "success_cross_tier_no_outbounds"
	// SuccessNoCallPaths indicates that the rpcshield run was successful but no call paths were found from the call graph.
	SuccessNoCallPaths Status = "success_no_call_paths"
	// Error indicates that the rpcshield run encountered an error.
	Error Status = "error"
)

// Result contains the result of the rpcshield run.
type Result struct {
	// Status indicates the overall status of the rpcshield run.
	Status Status

	// ErrorMsg is the error message if the rpcshield run encountered an error.
	ErrorMsg string

	// RunMetrics is the key-value map of additional metrics.
	RunMetrics map[string]float64

	// GraphMetrics is the key-value map of graph-specific metrics.
	GraphMetrics map[string]float64

	// FailnessMetrics is the key-value map of fail-ness count metrics.
	FailnessMetrics map[string]float64

	// AnalyzerMetrics is the list of key-value map of analyzer metrics of caller-callee pairs.
	AnalyzerMetrics []map[string]string `json:"-"`

	// CSVFilePath is the path to the CSV file generated by the rpcshield run.
	CSVFilePath string `json:"-"`
	// HTMLFilePath is the path to the HTML file generated by the rpcshield run.
	HTMLFilePath string `json:"-"`

	// Inbounds is the list of inbound points detected by rpcshield.
	Inbounds []fty.InboundPoint

	// Outbounds is the list of outbound points detected by rpcshield.
	Outbounds []fty.OutboundPoint

	// FilteredOutbounds is the list of outbound points after filtering by cross-tier and production traffic.
	FilteredOutbounds []fty.OutboundPoint

	// ResolvedHTTPOutbounds is the list of resolved outbound points after HTTP outbound service name resolution.
	ResolvedHTTPOutbounds []fty.OutboundPoint

	// PathCount indicates the number of paths found by rpcshield.
	PathCount int

	// Reports is the list of reports generated by the rpcshield run.
	Reports []output.Report `json:"-"`

	// ReportSummaries is a per-IB-OB summary for JSON output (path counts, permutation hit).
	ReportSummaries []output.ReportSummary `json:"report_summaries,omitempty"`

	// ExplorationPerSource holds per-source (IB) exploration diagnostics for JSON output.
	ExplorationPerSource map[string]graph.SourceExplorationMetrics `json:"exploration_per_source,omitempty"`

	// CallPathLengths contains raw call path length data broken down by fail-ness and sync/async.
	CallPathLengths *CallPathLengths `json:"call_path_lengths"`
}

// CallPathLength holds the length of a call path and, for fail-open paths, the depth at which fail-open was introduced.
type CallPathLength struct {
	Length                       int `json:"length"`
	FailOpenDistanceFromOutbound int `json:"fail_open_distance_from_outbound,omitempty"`
}

// CallPathLengths groups raw call path lengths by fail-ness status and sync/async.
type CallPathLengths struct {
	FailCloseSync  []CallPathLength `json:"fail_close_sync"`
	FailCloseAsync []CallPathLength `json:"fail_close_async"`
	FailOpenSync   []CallPathLength `json:"fail_open_sync"`
	FailOpenAsync  []CallPathLength `json:"fail_open_async"`
}

//go:embed missingsvg.txt
var _missingSVG string

// Run is the entrypoint of the driver. It never panics (if it does, it will be caught and returned
// as an error).
func (d *Driver) Run(ctx context.Context, serviceName string) (result Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.Join(err, fmt.Errorf("panic: %v, stacktrace:\n%v", r, string(debug.Stack())))
		}
		// Overwrite the result status if there was an error.
		if err != nil {
			result.Status = Error
			// Populate the error message on the result *before* it is encoded below, so it
			// actually makes it into the persisted result.json instead of only being set on
			// the in-memory copy after the file has already been written.
			result.ErrorMsg = err.Error()
		}
		// Write result to the output directory for debugging purposes.
		f, fOpenError := os.Create(filepath.Join(d.opts.OutputDir, fmt.Sprintf("%s_result.json", serviceName)))
		if fOpenError != nil {
			err = errors.Join(err, fmt.Errorf("create result file: %w", fOpenError))
		}
		err = errors.Join(err, json.NewEncoder(f).Encode(result))
		err = errors.Join(err, f.Close())
		if err != nil {
			result.ErrorMsg = err.Error()
		}
	}()
	runStart := time.Now()
	d.analyzerDurations = make(map[string]float64)
	d.sccpMetrics = &ssaanal.SCCPAggregateMetrics{}
	defer func() {
		result.RunMetrics[_totalDurationSecs] = time.Now().Sub(runStart).Seconds()
		// Log and capture max DRAM usage
		maxUsedDram, err := getMaxUsedDram()
		if err != nil {
			d.Logger.Infow("max used DRAM", "maxrss", "failed to get resource usage")
			result.RunMetrics[_maxUsedDramKB] = 0
		} else {
			d.Logger.Infow("max used DRAM", "maxrss", maxUsedDram)
			result.RunMetrics[_maxUsedDramKB] = float64(maxUsedDram)
		}
	}()

	d.Logger.Infow("Running rpcshield driver", "service", serviceName, "options", d.opts)
	result.RunMetrics = make(map[string]float64)
	result.GraphMetrics = make(map[string]float64)
	result.FailnessMetrics = make(map[string]float64)
	result.CallPathLengths = &CallPathLengths{
		FailCloseSync:  []CallPathLength{},
		FailCloseAsync: []CallPathLength{},
		FailOpenSync:   []CallPathLength{},
		FailOpenAsync:  []CallPathLength{},
	}

	start := time.Now()
	targets, err := d.findTargets(serviceName)
	if err != nil {
		return result, fmt.Errorf("find targets: %w", err)
	}
	result.RunMetrics[_targetCount] = float64(len(targets))
	result.RunMetrics[_findTargetDurationSecs] = time.Now().Sub(start).Seconds()

	d.Logger.Infow("Found bazel targets", "service", serviceName, "targets", targets)

	index := slices.IndexFunc(d.AllServices, func(s grail.Service) bool { return s.Name == serviceName })
	if index == -1 {
		return result, fmt.Errorf("service %q not found in all services fetched from Grail", serviceName)
	}
	curService := d.AllServices[index]

	if d.timestampCache == nil {
		d.timestampCache = make(map[string]string)
	}

	var reports []output.Report
	// Submit the reports at the end of the analysis.
	defer func() {
		// Skip writing reports if there was an error during the analysis.
		if err != nil {
			return
		}
		// Log grouped reports for debugging purposes.
		d.logResults(reports)

		// Construct output reports by making the reports more user-friendly.
		// For example, there could be many path reports between the same inbound-outbound pair
		// making the column too large for CSV (Kirby upload) and HTML.
		outputReports := d.processReportsForOutput(reports)

		// Write the reports to CSV file, if enabled.
		if d.opts.CSV {
			csvFilePath, rowCnt, err := reporting.WriteReportsToCSV(d.opts.OutputDir, curService, outputReports, d.opts.GitSHA, d.opts.Timestamp, constant.SourceForCSV, d.opts.Config.RepoNameForCSV, d.opts.Config.TerrablobFileURLTemplate)
			if err != nil {
				d.Logger.Errorf("Error writing report to CSV: %v", err)
			} else {
				d.Logger.Infof("Successfully wrote %d of %d rows to CSV file '%s'", rowCnt, len(outputReports)+1, csvFilePath)
				result.RunMetrics["csv_rows_written"] = float64(rowCnt)
				result.CSVFilePath = csvFilePath
			}
		}

		// Write the reports to HTML file, if enabled.
		if d.opts.HTML {
			htmlFilePath, err := reporting.WriteReportsToHTML(d.opts.OutputDir, curService.Name, outputReports, d.opts.GitSHA, d.opts.Timestamp)
			if err != nil {
				d.Logger.Errorf("Error writing report to HTML: %v", err)
			} else {
				d.Logger.Infof("Successfully wrote report to HTML file '%s'", htmlFilePath)
				result.HTMLFilePath = htmlFilePath
			}
		}
	}()

	// If we have not observed any inbound or outbound points in production for the past 30 days, we can skip the
	// analysis without errors. However, if CGConstructionOnly is set, we still run for benchmarking purposes.
	if d.shouldSkipForMissingProdTraffic(curService) {
		d.Logger.Infow("No inbound or outbound points found in production for the past 30 days, skipping the analysis")
		result.Status = SuccessNoProdIBOBTraffic
		return result, nil
	}

	start = time.Now()
	pathCache := make(map[string]bool)
	for tidx, target := range targets {
		// Service configs occasionally list bare-workspace target labels (pkg/path:name)
		// without the //-prefix. Bazel interprets bare labels relative to the process cwd,
		// which for rpcshield is generally not the workspace root -- so any downstream
		// `bazel query deps(pkg/foo:bar)` resolves against the wrong parent directory and
		// fails with "no such package". Canonicalize once here so every downstream helper
		// sees the same //-prefixed form and cwd doesn't matter.
		target = canonicalizeLabel(target)
		// Resolve the import path of the code actually compiled into target once, up front:
		// for go_binary(embed=[":lib"]) targets whose embedded library lives in another
		// directory, the directory-derived guess is wrong (see resolveTargetImportPath).
		targetPkgPath := dirBasedImportPath(target)
		if d.opts.PackageSource == nil {
			targetPkgPath = resolveTargetImportPath(d.Runner, d.Logger, filepath.Join(d.WorkspaceRoot, "bin", "bazel"), target)
		}
		d.Logger.Info("target", tidx, " : ", target)

		var pkgs []*packages.Package
		var ssaPkgs []*ssa.Package
		var ssaProg *ssa.Program
		start = time.Now()

		usedBazelLoader := false
		if d.opts.PackageSource != nil {
			var err error
			pkgs, ssaPkgs, ssaProg, err = d.opts.PackageSource(target)
			if err != nil {
				return result, fmt.Errorf("load packages from PackageSource: %w", err)
			}
			d.Logger.Infow("Loaded packages via PackageSource", "num_packages", len(pkgs))
			result.RunMetrics[_pkgCount] += float64(len(pkgs))
		} else if d.opts.BazelLoader != nil && useBazelLoader(serviceName, d.opts.Config.BazelLoaderServices, d.opts.ForceLoaderMode) {
			d.Logger.Infow("Using bazel loader")
			d.Logger.Infow("Loading packages", "target_pkg_path", targetPkgPath)
			bkpkgs, err := d.opts.BazelLoader(targetPkgPath)

			pkgs = make([]*packages.Package, 0, len(bkpkgs))
			packages.Visit(bkpkgs, nil, func(pkg *packages.Package) {
				pkgs = append(pkgs, pkg)
			})
			if err != nil {
				return result, fmt.Errorf("load all packages under %q: %w", targetPkgPath, err)
			}
			d.Logger.Infow("Loaded packages", "num_packages", len(pkgs))
			d.Logger.Debugw("Packages", "packages", pkgs)
			result.RunMetrics[_pkgCount] += float64(len(pkgs))

			usedBazelLoader = true
		} else {
			goPath, cdeps, err := d.GoPathWrapper.LiftGoPath(d.Runner, target)
			if err != nil {
				return result, fmt.Errorf("lift GOPATH: %w", err)
			}
			d.Logger.Infow("Lifted GOPATH", "path", goPath, "cdeps", cdeps)
			result.RunMetrics[_liftGoPathDurationSecs] += time.Now().Sub(start).Seconds()
			defer func() {
				if testing.Testing() {
					d.Logger.Infow("Testing mode, not cleaning up GOPATH", "path", goPath)
					return
				}
				if d.opts.KeepGoPathAfterRun {
					d.Logger.Infow("KeepGoPathAfterRun set, not cleaning up GOPATH", "path", goPath)
					return
				}
				d.Logger.Infow("Starting a detached process to remove GOPATH to save space", "path", goPath)
				cmd := exec.Command("rm", "-rf", goPath)
				cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // Start a new session to detach the process.
				if err := cmd.Start(); err != nil {
					d.Logger.Errorw("Failed to start the process", "error", err)
				}
				d.Logger.Infow("Started detached process", "pid", cmd.Process.Pid)
			}()

			// Load everything under the GOPATH.
			pkgs, err = loader.LoadAll(goPath, cdeps)
			if err != nil {
				return result, fmt.Errorf("load all packages under %q: %w", goPath, err)
			}
			d.Logger.Infow("Loaded packages", "num_packages", len(pkgs))
			d.Logger.Debugw("Packages", "packages", pkgs)
			result.RunMetrics[_pkgCount] += float64(len(pkgs))

			// Force GC to free up memory.
			runtime.GC()

		}
		result.RunMetrics[_pkgLoadingDurationSecs] += time.Now().Sub(start).Seconds()

		if d.opts.PackageSource == nil {
			repairIllTypedPropagationFromSourcelessPkgs(pkgs)
		}

		// Stop processing if any package failed to load. This runs before SSA construction: the run
		// is going to abort either way, and building SSA for a large service first costs minutes of
		// CPU and tens of gigabytes of RAM -- enough that on the biggest services the process was
		// killed before it ever produced the diagnostic explaining why it could not proceed.
		if _, packagesWithErrors := d.dumpPackageDiagnostics(pkgs); packagesWithErrors != 0 {
			return result, fmt.Errorf("%d packages have errors", packagesWithErrors)
		}

		if d.opts.PackageSource == nil {
			// Generating SSA packages. Build the SSA program; needed for getting generics instantiated
			// and funclits resolved. Also needed for call graph construction.
			start = time.Now()
			if usedBazelLoader {
				ssaProg, _ = ssautil.AllPackages(pkgs, ssa.InstantiateGenerics|ssa.GlobalDebug)
				ssaPkgs = ssaProg.AllPackages()
			} else {
				ssaProg, ssaPkgs = ssautil.AllPackages(pkgs, ssa.InstantiateGenerics|ssa.GlobalDebug)
			}
			ssaProg.Build()
			result.RunMetrics[_pkgLoadingDurationSecs] += time.Now().Sub(start).Seconds()
		}

		d.Logger.Infow("dumpPackageDiagnostic", "mains", len(d.getMain(ssaProg)))

		d.Logger.Infow("Loaded SSA packages", "num_packages", len(ssaPkgs))
		d.Logger.Debugw("SSA Packages", "packages", ssaPkgs)
		validSSAPkgs := make([]*ssa.Package, 0, len(ssaPkgs))
		for _, pkg := range ssaPkgs {
			// An SSA package could be nil if the original package contains type errors (happens for
			// packages using CGO or compiler directives where the body of the functions are defined
			// externally). In those cases, we can simply skip such a package.
			if pkg == nil {
				continue
			}
			validSSAPkgs = append(validSSAPkgs, pkg)
		}
		if len(validSSAPkgs) != len(ssaPkgs) {
			d.Logger.Warnw("filtered invalid (nil) SSA packages", "num_packages", len(ssaPkgs)-len(validSSAPkgs))
		}
		ssaPkgs = validSSAPkgs
		result.RunMetrics[_ssaPkgCount] += float64(len(ssaPkgs))

		// Produce SSA to AST mapping.
		start = time.Now()
		d.Logger.Infow("Producing SSA to AST mapping")
		d.SSAASTBidirMap = mapper.SSAToASTMap(pkgs, ssaPkgs, ssaProg)
		d.SigASTBidirMap = mapper.SignatureToASTMap(pkgs)
		result.RunMetrics[_ssaAstMappingDurationSecs] += time.Now().Sub(start).Seconds()

		// Check if it is a Glue service.
		isGlue := utils.IsGlueService(d.WorkspaceRoot, target)
		d.Logger.Infow("IsGlueService", "is_glue", isGlue)

		// Find the binary package as the entry point.
		entryPkg, err := d.findPackageFromTarget(targetPkgPath, pkgs)
		if err != nil {
			return result, fmt.Errorf("find entry package: %w", err)
		}

		start = time.Now()
		d.ServiceMapper.RankCachedServices(pkgs)
		f := finder.New(curService, d.ServiceMapper, d.Logger, d.opts.KeepIBPkgs, d.opts.Config.CodebasePkgPrefix, d.opts.Config.KafkaConsumerProxyPkgPath, d.opts.Config.InfraPkgPrefixes, d.opts.Config.EnableGenericGRPCThriftDetection, d.opts.Config.AdditionalHTTPClientTypes...)
		inbounds, err := f.Inbound(entryPkg, pkgs, ssaProg)
		if err != nil {
			return result, fmt.Errorf("find inbound: %w", err)
		}
		d.Logger.Infow("Found inbound functions", "num_functions", len(inbounds))
		result.Inbounds = fty.MergeInboundPoints(result.Inbounds, inbounds)
		result.RunMetrics[_inboundCount] += float64(len(inbounds))

		// Early exit for CG construction-only eval bench
		if d.opts.CGConstructionOnly {
			if err := d.runCGConstructionOnly(pkgs, ssaProg, ssaPkgs, isGlue, entryPkg, inbounds, serviceName, &result); err != nil {
				return result, err
			}

			// On the last target, return the result; otherwise continue to the next target.
			if tidx == len(targets)-1 {
				return result, nil
			}
			continue
		}

		outbounds, outboundMissingServiceCount, err := f.Outbound(entryPkg, pkgs)
		if err != nil {
			return result, fmt.Errorf("find outbound: %w", err)
		}

		for k, v := range outboundMissingServiceCount {
			result.RunMetrics[_outboundMissingServiceCountPrefix+string(k)] += float64(v)
		}

		d.Logger.Infow("Found outbound functions", "num_functions", len(outbounds))
		if len(outboundMissingServiceCount) > 0 {
			d.Logger.Warnw("Found outbound functions missing service mapping", "num_ob_missing_service", outboundMissingServiceCount)
		}
		outboundsTypeCountBeforeFiltering := d.countOutboundsType(outbounds)

		for k, v := range outboundsTypeCountBeforeFiltering {
			result.RunMetrics[_outboundCountBeforeFilterPrefix+string(k)] += v
		}

		result.Outbounds = fty.MergeOutboundPoints(result.Outbounds, outbounds)
		result.RunMetrics[_outboundCount] += float64(len(outbounds))
		result.RunMetrics[_ibObDetectionDurationSecs] += time.Now().Sub(start).Seconds()

		// Continue to the next target if there are no inbound or outbound points. Note that we do not actually
		// fail the entire run since it is possible that some targets do not have any RPC traffic (e.g., utility binaries).
		// We will have a final check to see if we have not found any inbound or outbound points across all targets.
		if len(inbounds) == 0 || len(outbounds) == 0 {
			continue
		}

		if d.opts.SkipOBTierFilter {
			d.Logger.Warnw("OB clipping by tier is disabled by the driver options")
		} else {
			filteredOBs := d.filterIrrelevantOutbounds(outbounds, curService.Tier)
			if len(filteredOBs) != len(outbounds) {
				d.Logger.Infow("Filtered OB points since they are not cross-tier", "before", len(outbounds), "after", len(filteredOBs))
			}
			outbounds = filteredOBs
		}
		outboundsTypeCountAfterFiltering := d.countOutboundsType(outbounds)

		for k, v := range outboundsTypeCountAfterFiltering {
			result.RunMetrics[_outboundCountAfterFilterPrefix+string(k)] += v

		}

		result.FilteredOutbounds = fty.MergeOutboundPoints(result.FilteredOutbounds, outbounds)
		result.RunMetrics[_filteredOutboundCount] += float64(len(outbounds))

		// Continue to the next target if there are no outbound points after filtering.
		// Note that we do not actually fail the entire run since it is possible that some targets
		// do not have any cross-tier outbound points.
		if len(outbounds) == 0 {
			d.Logger.Infow("No outbound points found, skipping the analysis")
			continue
		}

		start = time.Now()
		// Parse single RTA flavor and worker count for the normal Build path
		rtaFlavor, err := graph.ParseRTAFlavor(d.opts.RTAFlavor)
		if err != nil {
			d.Logger.Errorf("Invalid RTA flavor: %v", err)
			return result, err
		}
		rtaNumWorkers := 1
		if d.opts.RTANumWorkers != "" {
			workers, err := graph.ParseRTANumWorkers(d.opts.RTANumWorkers)
			if err != nil {
				d.Logger.Errorf("Invalid RTA num workers: %v", err)
				return result, err
			}
			rtaNumWorkers = workers[0]
		}
		d.Logger.Infow("RTA configuration", "flavor", rtaFlavor, "num_workers", rtaNumWorkers)

		graphConfig := graph.Config{
			DisableSCCPAnalysis:     d.opts.DisableSCCPAnalysis,
			DisableRelaxedContext:   slices.Contains(d.opts.Config.GraphDisableContextRelaxServices, serviceName),
			DisableParallelCallTree: d.opts.DisableParallelCallTree,
			RTAFlavor:               rtaFlavor,
			RTANumWorkers:           rtaNumWorkers,
			PermutationThreshold:    d.opts.PermutationThreshold,
			CanonicalEdgeOrder:      d.opts.CanonicalEdgeOrder,
			CodebasePkgPrefix:       d.opts.Config.CodebasePkgPrefix,
			SafeGoPkgPath:           d.opts.Config.SafeGoPkgPath,
		}
		if d.opts.Config.ExcludePackagePatterns != nil || len(d.opts.Config.ExtraExcludePackagePatterns) > 0 {
			base := graph.DefaultExcludePackagePatterns
			if d.opts.Config.ExcludePackagePatterns != nil {
				base = d.opts.Config.ExcludePackagePatterns
			}
			graphConfig.ExcludePackagePatterns = append(append([]string{}, base...), d.opts.Config.ExtraExcludePackagePatterns...)
		}
		d.Logger.Infow("Graph config", "config", graphConfig)

		b := graph.NewBuilder(d.Logger, pkgs, ssaProg, ssaPkgs, d.SSAASTBidirMap, d.SigASTBidirMap, isGlue, entryPkg, inbounds, outbounds, true, graphConfig)
		d.Logger.Infof("Starting builder")
		paths, buildResult, err := b.Build()
		d.Logger.Infof("Finished builder")

		// Capture per-source exploration metrics for JSON output.
		// Merge (not replace) to accumulate across multiple analysis targets.
		if buildResult != nil && buildResult.PerSource != nil {
			if result.ExplorationPerSource == nil {
				result.ExplorationPerSource = make(map[string]graph.SourceExplorationMetrics)
			}
			for k, v := range buildResult.PerSource {
				result.ExplorationPerSource[k] = v
			}
		}
		if err != nil {
			d.Logger.Errorf("Error in builder: %v", err)
			return result, err
		}

		// resolved http outbound service name in per call path manner
		paths, httpTotalPathsCount, httpResolvedPathsCount, resolvedOutbounds := d.resolveHTTPOutboundService(paths, curService)
		result.ResolvedHTTPOutbounds = append(result.ResolvedHTTPOutbounds, resolvedOutbounds...)
		result.RunMetrics["httpTotalPathsCount"] += float64(httpTotalPathsCount)
		result.RunMetrics["httpUnresolvedPathsCount"] += float64(httpTotalPathsCount - httpResolvedPathsCount)
		result.RunMetrics["httpResolvedPathsCount"] += float64(httpResolvedPathsCount)
		result.RunMetrics[_resolvedHTTPOutboundCountPrefix] += float64(len(resolvedOutbounds))

		for name, v := range buildResult.Metrics {
			result.GraphMetrics[name] += v
		}

		// Assume the deduplication on paths only happens when there are multiple targets.
		// Single target case should be unique paths.
		if len(targets) > 1 {
			tempPaths := make([]*graph.CallPath, 0)
			for _, cp := range paths {
				if _, ok := pathCache[cp.Hash()]; !ok {
					pathCache[cp.Hash()] = true
					tempPaths = append(tempPaths, cp)
				}
			}
			paths = tempPaths
		}
		result.PathCount = len(paths)
		d.Logger.Infof("Found %d paths", len(paths))
		for _, cp := range paths {
			for _, edge := range cp.Edges {
				d.Logger.Debugf("\n edge: %s\n", edge.Edge.Caller.Func.String())
			}
		}
		result.RunMetrics[_graphBuildingDurationSecs] += time.Now().Sub(start).Seconds()

		for i, cp := range paths {
			fmt.Printf("path %d \n", i)
			for j, edge := range cp.Edges {
				fmt.Printf("\n")
				for k := 0; k < j; k++ {
					fmt.Printf(" ")
				}
				fmt.Printf("%s\n", edge.Edge.Caller.Func.String())
			}
		}

		// We continue to next target if there are no call paths found. Note that we do not actually fail the entire run
		// since the next target could have call paths. We will fail the run at the end if no call paths are found
		// across all targets.
		// No paths found is possible, for example, in cases where the outbound points are not reachable from the inbound points.
		if len(paths) == 0 {
			d.Logger.Infow("No call paths found, skipping further analysis for this target", "target", target)
			continue
		}

		// Traverse over each call path and run static and LLM analyzers to determine fail-ness status of the path.
		start = time.Now()
		d.Logger.Infow("Analyzing call paths", "analyzers", d.opts.Analyzers, "num_paths", len(paths))
		reports = append(reports, d.analyzeCallPaths(pkgs, paths)...)
		// Collect the total counts of each analyzer kind for observability purposes.
		kindStats := make(map[constant.AnalyzerKind]int)
		// Collect the total counts of each fail-ness status across call paths for observability purposes.
		failnessPathStats := make(map[constant.Failness]int)
		// Collect call path lengths for LDA observability.
		var failCloseSyncPathLengths []CallPathLength
		var failOpenSyncPathLengths []CallPathLength
		var failCloseAsyncPathLengths []CallPathLength
		var failOpenAsyncPathLengths []CallPathLength
		for _, r := range reports {
			for _, pr := range r.PathResults {
				failOpenIntroducedAtLength := 0
				for k, er := range pr.Edges {
					// Find the first fail open edge in the path.
					if failOpenIntroducedAtLength == 0 && er.AnalyzerOutput.Status == constant.FailOpen {
						failOpenIntroducedAtLength = k + 1
					}

					src := er.AnalyzerOutput.Source
					if src != er.AnalyzerOutput.OriginalSource {
						src = src + "_" + er.AnalyzerOutput.OriginalSource
					}
					kindStats[src]++

					// Add the analyzer result to the result for observability purposes.
					result.AnalyzerMetrics = append(result.AnalyzerMetrics, map[string]string{
						"run_timestamp":      d.opts.Timestamp,
						"service":            r.Inbound.Service.Name,
						"caller":             er.Caller,
						"callee":             er.Callee,
						"source_code_link":   er.SourceGraphLink,
						"edge_result_source": string(src),
						"edge_result":        string(er.AnalyzerOutput.Status),
						"error_count":        strconv.Itoa(len(er.Errors)),
						"error":              strings.Join(er.Errors, "<error_sep>"),
					})
				}
				failnessPathStats[pr.Status]++

				// Track the path length statistics for fail open and fail close paths.
				if pr.Status == constant.FailOpen {
					if pr.IsAsync {
						failOpenAsyncPathLengths = append(failOpenAsyncPathLengths, CallPathLength{Length: len(pr.Edges), FailOpenDistanceFromOutbound: failOpenIntroducedAtLength})
					} else {
						failOpenSyncPathLengths = append(failOpenSyncPathLengths, CallPathLength{Length: len(pr.Edges), FailOpenDistanceFromOutbound: failOpenIntroducedAtLength})
					}
				} else if pr.Status == constant.FailClose {
					if pr.IsAsync {
						failCloseAsyncPathLengths = append(failCloseAsyncPathLengths, CallPathLength{Length: len(pr.Edges)})
					} else {
						failCloseSyncPathLengths = append(failCloseSyncPathLengths, CallPathLength{Length: len(pr.Edges)})
					}
				}
			}
		}
		d.Logger.Infow("Analyzer result", "kind_stats", kindStats)
		for k, v := range kindStats {
			result.RunMetrics[fmt.Sprintf("analyzer_%s_count", strings.ToLower(string(k)))] += float64(v)
		}
		d.Logger.Infow("Fail-ness path result", "failness_path_stats", failnessPathStats)
		for k, v := range failnessPathStats {
			result.FailnessMetrics[fmt.Sprintf("%s_path_count", strings.ToLower(string(k)))] += float64(v)
		}

		// Compute call path length percentile statistics for LDA observability.
		// percentile returns the value at the given percentile (0-100) from a sorted slice using nearest-rank.
		percentile := func(sorted []int, p int) float64 {
			n := len(sorted)
			if n == 0 {
				return 0
			}
			rank := (p*n + 99) / 100 // ceiling of p*n/100
			if rank < 1 {
				rank = 1
			}
			if rank > n {
				rank = n
			}
			return float64(sorted[rank-1])
		}
		type pathLengthCategory struct {
			name    string
			lengths []CallPathLength
		}
		for _, cat := range []pathLengthCategory{
			{"fail_close_sync", failCloseSyncPathLengths},
			{"fail_close_async", failCloseAsyncPathLengths},
			{"fail_open_sync", failOpenSyncPathLengths},
			{"fail_open_async", failOpenAsyncPathLengths},
		} {
			var p50, p90, p99, p100 float64
			if len(cat.lengths) > 0 {
				sorted := make([]int, len(cat.lengths))
				for i, pl := range cat.lengths {
					sorted[i] = pl.Length
				}
				slices.Sort(sorted)
				p50 = percentile(sorted, 50)
				p90 = percentile(sorted, 90)
				p99 = percentile(sorted, 99)
				p100 = float64(sorted[len(sorted)-1])
			}
			d.Logger.Infow("Call path length stats", "category", cat.name, "count", len(cat.lengths), "p50", p50, "p90", p90, "p99", p99, "p100", p100)
			prefix := "call_path_length_" + cat.name + "_"
			result.RunMetrics[prefix+"p50"] = p50
			result.RunMetrics[prefix+"p90"] = p90
			result.RunMetrics[prefix+"p99"] = p99
			result.RunMetrics[prefix+"p100"] = p100
			result.RunMetrics["call_path_"+cat.name+"_count"] = float64(len(cat.lengths))
		}

		// Compute overall call path length percentiles across all categories.
		var allLengths []int
		for _, ls := range [][]CallPathLength{failCloseSyncPathLengths, failCloseAsyncPathLengths, failOpenSyncPathLengths, failOpenAsyncPathLengths} {
			for _, pl := range ls {
				allLengths = append(allLengths, pl.Length)
			}
		}
		var overallP50, overallP90, overallP99, overallP100 float64
		if len(allLengths) > 0 {
			slices.Sort(allLengths)
			overallP50 = percentile(allLengths, 50)
			overallP90 = percentile(allLengths, 90)
			overallP99 = percentile(allLengths, 99)
			overallP100 = float64(allLengths[len(allLengths)-1])
		}
		d.Logger.Infow("Call path length stats", "category", "overall", "count", len(allLengths), "p50", overallP50, "p90", overallP90, "p99", overallP99, "p100", overallP100)
		result.RunMetrics["call_path_length_overall_p50"] = overallP50
		result.RunMetrics["call_path_length_overall_p90"] = overallP90
		result.RunMetrics["call_path_length_overall_p99"] = overallP99
		result.RunMetrics["call_path_length_overall_p100"] = overallP100
		result.RunMetrics["call_path_overall_count"] = float64(len(allLengths))

		// Store raw call path lengths in the result for the result.json output.
		result.CallPathLengths.FailCloseSync = append(result.CallPathLengths.FailCloseSync, failCloseSyncPathLengths...)
		result.CallPathLengths.FailCloseAsync = append(result.CallPathLengths.FailCloseAsync, failCloseAsyncPathLengths...)
		result.CallPathLengths.FailOpenSync = append(result.CallPathLengths.FailOpenSync, failOpenSyncPathLengths...)
		result.CallPathLengths.FailOpenAsync = append(result.CallPathLengths.FailOpenAsync, failOpenAsyncPathLengths...)

		result.RunMetrics[_analysisDurationSecs] += time.Now().Sub(start).Seconds()
	} // end of per target analysis

	for k, v := range d.analyzerDurations {
		result.RunMetrics[k] += v
	}
	for k, v := range d.sccpMetrics.AsMap() {
		result.RunMetrics[k] = v
	}

	if len(result.Inbounds) == 0 || len(result.Outbounds) == 0 {
		return result, fmt.Errorf("no inbound or outbound points found, inbound %d, outbound %d", len(result.Inbounds), len(result.Outbounds))
	}

	if len(result.FilteredOutbounds) == 0 {
		result.Status = SuccessNoCrossTierOutbounds
		return result, nil
	}

	if result.PathCount == 0 {
		result.Status = SuccessNoCallPaths
		return result, nil
	}

	// Group the reports by inbound-outbound quadruple (inbound service, outbound service, inbound API, outbound API).
	reports = d.groupReportsByInboundOutbound(reports)

	d.enrichReportMetrics(reports, result.ExplorationPerSource)

	// Build report summaries for JSON output.
	summaries := make([]output.ReportSummary, len(reports))
	for i := range reports {
		summaries[i] = output.ReportSummary{
			Inbound:                 reports[i].Inbound,
			Outbound:                reports[i].Outbound,
			Status:                  reports[i].Status,
			TotalPaths:              reports[i].TotalPaths,
			PathCounts:              reports[i].PathCounts,
			PermutationThresholdHit: reports[i].PermutationThresholdHit,
		}
	}
	result.ReportSummaries = summaries

	result.Reports = reports
	result.Status = Success
	return result, nil
}

// RunOnGoPath runs the analysis pipeline against an already-prepared GOPATH-shaped source
// directory (e.g. produced by a prior GoPathWrapper.LiftGoPath call, or assembled by other means),
// bypassing Bazel-target resolution (Driver.opts.TargetResolver / findTargets), the AllServices
// registry lookup, and GoPathWrapper.LiftGoPath entirely. This is the entrypoint for callers who
// have prepared source out of band and don't have (or don't want to use) Uber's Bazel/pinocchio/
// service-registry conventions.
//
// curService is used directly for tier resolution and CSV/HTML/result-file naming (in place of an
// AllServices lookup). targets are "//<pkgPath>:<name>"-shaped labels used only to locate each
// target's entry package within the loaded packages (via findPackageFromTarget/IsGlueService's
// pkgPath extraction) -- no real Bazel invocation happens. goPath/cdeps are passed straight to
// loader.LoadAll for every target.
func (d *Driver) RunOnGoPath(ctx context.Context, curService grail.Service, targets []string, goPath string, cdeps []string) (Result, error) {
	clone := *d
	clone.AllServices = []grail.Service{curService}
	clone.opts.Targets = targets
	clone.opts.PackageSource = func(string) ([]*packages.Package, []*ssa.Package, *ssa.Program, error) {
		pkgs, err := loader.LoadAll(goPath, cdeps)
		if err != nil {
			return nil, nil, nil, err
		}
		repairIllTypedPropagationFromSourcelessPkgs(pkgs)
		ssaProg, ssaPkgs := ssautil.AllPackages(pkgs, ssa.InstantiateGenerics|ssa.GlobalDebug)
		ssaProg.Build()
		return pkgs, ssaPkgs, ssaProg, nil
	}
	return clone.Run(ctx, curService.Name)
}

// RunOnPackages is like RunOnGoPath, but for a caller who already has loaded packages in hand
// (e.g. reusing a prior loader.LoadAll call, or an in-memory test fixture) and wants to skip even
// loader.LoadAll.
func (d *Driver) RunOnPackages(ctx context.Context, curService grail.Service, targets []string, pkgs []*packages.Package) (Result, error) {
	clone := *d
	clone.AllServices = []grail.Service{curService}
	clone.opts.Targets = targets
	clone.opts.PackageSource = func(string) ([]*packages.Package, []*ssa.Package, *ssa.Program, error) {
		repairIllTypedPropagationFromSourcelessPkgs(pkgs)
		ssaProg, ssaPkgs := ssautil.AllPackages(pkgs, ssa.InstantiateGenerics|ssa.GlobalDebug)
		ssaProg.Build()
		return pkgs, ssaPkgs, ssaProg, nil
	}
	return clone.Run(ctx, curService.Name)
}

func (d *Driver) logResults(reports []output.Report) {
	d.Logger.Infof("Final Results (%d reports):", len(reports))
	for r, report := range reports {
		d.Logger.Infof("---------- Report %d of %d ----------", r+1, len(reports))
		d.Logger.Infof("UUID: %s", report.ID)
		d.Logger.Infof("Inbound: service name: %s, service endpoint: %s", report.Inbound.Service.Name, report.Inbound.APIName)
		d.Logger.Infof("Outbound: service name: %s, service endpoint: %s", report.Outbound.Service.Name, report.Outbound.APIName)
		d.Logger.Infof("Final Status: %s", report.Status)
		d.Logger.Infof("Number of paths: %d", len(report.PathResults))
		for i, pathResult := range report.PathResults {
			d.Logger.Infof("")
			d.Logger.Infof("Analyzing Path %d of %d (outbound to inbound)", i+1, len(report.PathResults))
			for _, edge := range pathResult.Edges {
				d.Logger.Infof("\tCaller: %s", edge.Caller)
				d.Logger.Infof("\tCallee: %s", edge.Callee)
				d.Logger.Infof("\tSourceGraph link: %s", edge.SourceGraphLink)
				for errIndex, errStr := range edge.Errors {
					d.Logger.Infof("\tError %d: %v", errIndex, errStr)
				}
				src := edge.AnalyzerOutput.Source
				if src != edge.AnalyzerOutput.OriginalSource {
					src = src + "_" + edge.AnalyzerOutput.OriginalSource
				}
				d.Logger.Infof("\tEdge Status: %s, Source: %s", edge.AnalyzerOutput.Status, src)
				d.Logger.Infof("")
			}
			d.Logger.Infof("Path status: %s", pathResult.Status)
		}
		d.Logger.Infof("\n")
	}
}

func (d *Driver) groupReportsByInboundOutbound(reports []output.Report) []output.Report {
	type reportKey struct {
		inbound  output.EndPoint
		outbound output.EndPoint
	}

	// Group the reports by inbound-outbound quadruple (inbound service, outbound service, inbound API, outbound API).
	groupedReportsMap := make(map[reportKey]output.Report)
	for _, report := range reports {
		r := reportKey{
			inbound:  report.Inbound,
			outbound: report.Outbound,
		}

		existingReport, ok := groupedReportsMap[r]
		if !ok {
			existingReport = report
		} else {
			existingReport.Merge(report)
		}
		groupedReportsMap[r] = existingReport
	}

	// Convert the map to a slice.
	var groupedReports []output.Report
	for _, v := range groupedReportsMap {
		v.TotalPaths = len(v.PathResults)
		// Sort paths deterministically at assembly time so downstream truncation
		// and reporting produce stable output across otherwise-identical runs.
		v.SortPathResults()
		groupedReports = append(groupedReports, v)
	}

	// Inject the flamegraph SVG into the reports.
	for i, report := range groupedReports {
		ib := report.Inbound.APIName
		ob := report.Outbound.APIName
		d.Logger.Debugf("producing FlamegraphSVG for inbound %s, outbound %s", ib, ob)
		fg, err := report.FlamegraphSVG(d.Runner, d.WorkspaceRoot)
		if err != nil {
			fg = template.HTML(_missingSVG)
			d.Logger.Errorf("failed to produce FlamegraphSVG for inbound %s, outbound %s: %v", err, ib, ob)
		}
		groupedReports[i].Flamegraph = fg
	}

	return groupedReports
}

// enrichReportMetrics sets PermutationThresholdHit from exploration metrics
// and computes per-IB-OB path counts by fail-ness and sync/async.
func (d *Driver) enrichReportMetrics(reports []output.Report, explorationPerSource map[string]graph.SourceExplorationMetrics) {
	if explorationPerSource != nil {
		for i := range reports {
			ibName := reports[i].Inbound.APIName
			obName := reports[i].Outbound.APIName
			if srcMetrics, ok := explorationPerSource[ibName]; ok {
				if hit, ok := srcMetrics.PermutationHitPerSink[obName]; ok {
					reports[i].PermutationThresholdHit = hit
				}
			}
		}
	}

	for i := range reports {
		var counts output.PathCounts
		for _, pr := range reports[i].PathResults {
			switch pr.Status {
			case constant.FailClose:
				counts.Total.FailClose++
				if pr.IsAsync {
					counts.Async.FailClose++
				} else {
					counts.Sync.FailClose++
				}
			case constant.FailOpen:
				counts.Total.FailOpen++
				if pr.IsAsync {
					counts.Async.FailOpen++
				} else {
					counts.Sync.FailOpen++
				}
			default: // FailUnknown or unexpected status
				counts.Total.FailUnknown++
				if pr.IsAsync {
					counts.Async.FailUnknown++
				} else {
					counts.Sync.FailUnknown++
				}
			}
		}
		reports[i].PathCounts = counts
	}
}

// analyzeCallPaths analyzes the call paths and returns the results of the analysis wrapped in output.Report.
// Note that we output reports for each path in the callPaths, aggregating the results by inbound-outbound quadruple
// happens in another function.
func (d *Driver) analyzeCallPaths(pkgs []*packages.Package, callPaths []*graph.CallPath) []output.Report {
	allPkgsMap := make(map[string]*packages.Package, len(pkgs))
	for _, p := range pkgs {
		allPkgsMap[p.PkgPath] = p
	}

	// Build a map from caller function to all callee call sites across all paths.
	// This is used to populate OtherSources for SCCP analysis.
	d.callerCalleeSites = make(map[*ssa.Function][]*ssa.Call)
	seen := make(map[*ssa.Call]bool)
	for _, path := range callPaths {
		for _, edge := range path.Edges {
			if call, ok := edge.Edge.Site.(*ssa.Call); ok && !seen[call] {
				seen[call] = true
				d.callerCalleeSites[edge.Edge.Caller.Func] = append(
					d.callerCalleeSites[edge.Edge.Caller.Func], call)
			}
		}
	}

	// TODO: add caching logic for skipping caller-callee pairs that have already been analyzed.
	// Analyze each path in `callPaths`.
	allResults := make([]output.Report, 0, len(callPaths))
	for _, path := range callPaths {
		edgeResults := make([]*output.EdgeWrapper, 0, len(path.Edges))
		// Analyze each edge (caller-callee pair) in call path in reverse order, i.e., from outbound to inbound.
		for j := len(path.Edges) - 1; j >= 0; j-- {
			var prevEdgeResult *output.EdgeWrapper
			if len(edgeResults) > 0 {
				prevEdgeResult = edgeResults[len(edgeResults)-1]
			}
			edgeResults = append(edgeResults, d.analyzeEdge(path.Edges[j], allPkgsMap, prevEdgeResult))
		}

		status := output.AggregatedStatus(edgeResults)

		// Create the report for the path with aggregated status and append it to the list of all results.
		report := output.Report{
			ID: uuid.New().String(),
			Inbound: output.EndPoint{
				Service: path.Inbound.Service,
				APIName: path.Inbound.CanonicalName,
			},
			Outbound: output.EndPoint{
				Service: path.Outbound.Service,
				APIName: path.Outbound.CanonicalName,
			},
			PathResults: []output.PathResult{
				{
					Edges:   edgeResults,
					Status:  status,
					IsAsync: path.IsAsync,
				},
			},
			Status: status,
		}

		allResults = append(allResults, report)

		// TODO: this is a temporary solution. We should revisit this to make it synchronous with UIS.
		// Store the simplified to detailed mapping for the inbound and outbound points to be used for Jira ticketing later
		// using BugSpy.
		if d.simplifiedToDetailedInbound == nil {
			d.simplifiedToDetailedInbound = make(map[output.EndPoint]fty.InboundPoint)
		}
		if d.simplifiedToDetailedOutbound == nil {
			d.simplifiedToDetailedOutbound = make(map[output.EndPoint]fty.OutboundPoint)
		}
		d.simplifiedToDetailedInbound[report.Inbound] = path.Inbound
		d.simplifiedToDetailedOutbound[report.Outbound] = path.Outbound
	}
	return allResults
}

func (d *Driver) analyzeEdge(edge *edgeinfo.EdgeInfo, allPkgsMap map[string]*packages.Package, prevEdgeResult *output.EdgeWrapper) (edgeResult *output.EdgeWrapper) {
	cgEdge := edge.Edge
	caller := cgEdge.Caller.Func

	callerString := caller.String()
	if d.opts.ShortCallerName {
		pkg := caller.Package()
		if pkg == nil || pkg.Pkg == nil {
			callerString = caller.Name()
		} else {
			callerString = pkg.Pkg.Path() + "/" + caller.Name()
		}
	}

	// Have an unknown default value, and we will override fields as we analyze the edge.
	edgeResult = &output.EdgeWrapper{
		Caller: callerString,
		Callee: "<nil>",
		AnalyzerOutput: output.AnalyzerOutput{
			Status:         constant.FailUnknown,
			Source:         constant.Unknown,
			OriginalSource: constant.Unknown,
		},
	}

	if cgEdge.Site == nil {
		edgeResult.Errors = append(edgeResult.Errors, "no site found for edge")
		edgeResult.AnalyzerOutput.Status = constant.FailUnknownWithError
		return
	}

	// Create the package info and AST context for the caller package.
	var astContext *asthelper.ASTContext
	if caller.Package() != nil && caller.Package().Pkg != nil {
		callerPkg, ok := allPkgsMap[caller.Package().Pkg.Path()]
		if !ok {
			edgeResult.Errors = append(edgeResult.Errors, fmt.Sprintf("caller `%s`'s package not found", caller.Name()))
			return
		}
		pkgInfo := pkgdeps.New(callerPkg, allPkgsMap)
		astContext = asthelper.New(pkgInfo, d.SSAASTBidirMap.StoA[caller])
	}

	// Set the callee name in the edge result.
	callee := edge.CallExpr
	var calleeObj types.Object
	if astContext != nil {
		calleeObj = astContext.ObjectOf(callee)
	}
	if calleeObj != nil {
		edgeResult.Callee = calleeObj.Name()

	}

	// Build the sourcegraph link for the edge pointing to the callee site in the caller.
	sgURL, rawFilepath, callerLastModifiedTimestamp, err := d.buildSourcegraphLink(cgEdge, allPkgsMap)
	if err != nil {
		edgeResult.Errors = append(edgeResult.Errors, fmt.Sprintf("build sourcegraph link: %s", err))
	} else {
		edgeResult.SourceGraphLink = sgURL
		edgeResult.Filepath = rawFilepath
		edgeResult.CallerLastModifiedTimestamp = callerLastModifiedTimestamp
		// Get the line numbers
		callerPkg, ok := allPkgsMap[cgEdge.Caller.Func.Pkg.Pkg.Path()]
		if !ok {
			edgeResult.Errors = append(edgeResult.Errors, fmt.Sprintf("caller package not found: %s", cgEdge.Caller.Func.Pkg.Pkg.Path()))
		} else {
			fset := callerPkg.Fset
			edgeResult.CalleeLineNo = fset.Position(cgEdge.Site.Pos()).Line
			// Get the begin and end line number of the caller function.
			if callerAST, ok := d.SSAASTBidirMap.StoA[caller]; ok {
				if callerFuncDecl, ok := callerAST.(*ast.FuncDecl); ok {
					edgeResult.CallerBeginLineNo = fset.Position(callerFuncDecl.Pos()).Line
					edgeResult.CallerEndLineNo = fset.Position(callerFuncDecl.End()).Line
				}
			}
		}
	}

	// Check if the caller contains annotations (as comments) to skip the analysis.
	if callerAST, ok := d.SSAASTBidirMap.StoA[caller]; ok {
		if callerFuncDecl, ok := callerAST.(*ast.FuncDecl); ok && callerFuncDecl.Doc != nil {
			for _, comment := range callerFuncDecl.Doc.List {
				switch {
				case strings.Contains(comment.Text, constant.FailOpenAnnotation):
					edgeResult.AnalyzerOutput.Status = constant.FailOpen
					edgeResult.AnalyzerOutput.Source = constant.Annotation
					edgeResult.AnalyzerOutput.OriginalSource = constant.Annotation
					return
				case strings.Contains(comment.Text, constant.FailCloseAnnotation):
					edgeResult.AnalyzerOutput.Status = constant.FailClose
					edgeResult.AnalyzerOutput.Source = constant.Annotation
					edgeResult.AnalyzerOutput.OriginalSource = constant.Annotation
					return
				case strings.Contains(comment.Text, constant.FailCloseSuppressAnnotation):
					edgeResult.AnalyzerOutput.Status = constant.FailCloseSuppressed
					edgeResult.AnalyzerOutput.Source = constant.Annotation
					edgeResult.AnalyzerOutput.OriginalSource = constant.Annotation
					return
				}
			}
		}
	}

	// TODO: we can add an early return here if the a FailOpen is detected in the previous edge.
	//  This is because once a FailOpen is detected, it is always a FailOpen.
	//  However, we don't do this now, allowing the analyzers to run on all edges to collect any issues in determining
	//  the fail-ness status of the edges.

	// Run the Cached analyzer, static analyzers (Predefined, SSA, and AST), and LLM analyzer.
	analyzerOutput, err := d.runAnalyzers(caller, callee, calleeObj, cgEdge.Site, astContext, edgeResult.SourceGraphLink)
	if err != nil {
		edgeResult.Errors = append(edgeResult.Errors, fmt.Sprintf("run analyzers: %s", err))
	}
	if analyzerOutput != nil {
		edgeResult.AnalyzerOutput = *analyzerOutput
	}
	return
}

func (d *Driver) getLastModifiedTimestamp(runner utils.Runner, caller string, filePath string, repoPath string) (string, error) {
	// Check if the file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return "", fmt.Errorf("file does not exist: %s", filePath)
	}

	out, _, err := utils.ExecCommand(runner, "git", "-C", repoPath, "log", "-s", "-L", fmt.Sprintf(":%s:%s", caller, filePath), "--date=format:'%b %d %Y'", "--pretty=format:%H|%an|%ad", "-n", "1")
	if err != nil {
		return "", fmt.Errorf("failed to get git log: %v", err)
	}

	fields := strings.Split(out, "|")
	commitHash := fields[0]
	authorName := fields[1]
	timestamp := fields[2]

	d.Logger.Infof("gcommitHash: %s, authorName: %s, timestamp: %s \n", commitHash, authorName, timestamp)

	if timestamp == "" {
		return "", fmt.Errorf("no commit timestamp found for function")
	}

	return timestamp, nil
}

func (d *Driver) buildSourcegraphLink(edge *callgraph.Edge, allPkgsMap map[string]*packages.Package) (string, string, string, error) {
	sgURL := d.opts.Config.SourcegraphURLTemplate
	if d.opts.SGLinkRemoteHash {
		// TODO: convert to git remote branch later
		sgURL = strings.Replace(sgURL, constant.GitSHAPlaceholderString, d.opts.BaseSHA, 1)
	} else {
		sgURL = strings.Replace(sgURL, constant.GitSHAPlaceholderString, d.opts.GitSHA, 1)
	}

	// Find the package defining the caller function
	if edge.Caller.Func.Pkg == nil {
		return "", "", "", fmt.Errorf("caller package is nil: %s", edge.Caller.Func.String())
	}
	callerPkg, ok := allPkgsMap[edge.Caller.Func.Pkg.Pkg.Path()]
	if !ok {
		return "", "", "", fmt.Errorf("caller package not found: %s", edge.Caller.Func.Pkg.Pkg.Path())
	}

	// Get filepath defining the caller
	callerPos := callerPkg.Fset.PositionFor(edge.Caller.Func.Pos(), false)
	filePath := callerPos.Filename
	// The raw filepath can have a different prefixes, such as bazel sandbox, leading to invalid URL.
	// To remove that we apply the heuristic: trim the filepath until the last occurrence of the
	// configured code prefix (e.g. `src/example.internal`). Skipped if no prefix is configured.
	if codePrefix := d.opts.Config.CodePrefix; codePrefix != "" {
		if index := strings.LastIndex(filePath, codePrefix); index != -1 {
			filePath = filePath[index:]
		}
	}

	// Heuristic to post-process filepath to create a valid sourcegraph URL. This includes:
	// - Remove `_cffgen` from the filepath `/path/to/file_cffgen.go` to `/path/to/file.go`
	filePath = strings.Replace(filePath, constant.CFFGenSuffix, "", 1)

	// Replace filepath placeholder in the sourcegraph URL
	sgURL = strings.Replace(sgURL, constant.FilePathPlaceholderString, filePath, 1)

	// Get the line number of the callee in the caller
	calleeSitePos := edge.Site.Pos()
	if !calleeSitePos.IsValid() {
		sgURL = strings.Replace(sgURL, constant.LinePlaceholderString, strconv.Itoa(callerPos.Line), 1)
	} else {
		calleeSitePosition := callerPkg.Fset.Position(calleeSitePos)
		sgURL = strings.Replace(sgURL, constant.LinePlaceholderString, strconv.Itoa(calleeSitePosition.Line), 1)
	}
	// Get the last modified timestamp of the caller function.
	// fullyCallerFuncName := edge.Caller.Func.String()
	// var callerFuncName string
	// if obj := edge.Caller.Func.Object(); obj != nil {
	// 	callerFuncName = obj.Name()
	// }
	// callerLastModifiedTimestamp, _ := d.queryTimestamp(d.Runner, callerFuncName, fullyCallerFuncName, filePath, d.WorkspaceRoot)
	callerLastModifiedTimestamp := ""
	return sgURL, filePath, callerLastModifiedTimestamp, nil
}

func (d *Driver) queryTimestamp(runner utils.Runner, caller string, fullyCallerFuncName string, filePath string, repoPath string) (string, error) {
	// Check if timestamp is already cached
	if cached, ok := d.timestampCache[fullyCallerFuncName]; ok {
		d.Logger.Infof("cached timestamp for caller %s: %s", fullyCallerFuncName, cached)
		return cached, nil
	}

	callerLastModifiedTimestamp, err := d.getLastModifiedTimestamp(d.Runner, caller, filePath, d.WorkspaceRoot)
	if err != nil {
		d.Logger.Errorf("failed to get last modified timestamp for caller %s: %v", fullyCallerFuncName, err)
		callerLastModifiedTimestamp = "No timestamp for " + caller
	}

	d.timestampCache[fullyCallerFuncName] = callerLastModifiedTimestamp
	return callerLastModifiedTimestamp, nil
}

// runAnalyzers runs the static (SCCP, SSA, AST) and LLM analyzers for the caller-callee pair. The strategy is:
// 1. Check the cache analyzer first. If it has a result, return it.
// 2. Run the Predefined analyzer. If it returns a non-unknown status, return it.
// 3. Run the SCCP analyzer. If it returns a non-unknown status, return it.
// 4. Fall back to SSA, then AST, then LLM analyzers if SCCP fails or returns unknown.
func (d *Driver) runAnalyzers(caller *ssa.Function, callee *ast.CallExpr, calleeObj types.Object, calleeSite ssa.CallInstruction, astContext *asthelper.ASTContext, sgLink string) (analyzerOutput *output.AnalyzerOutput, err error) {
	source := constant.Unknown

	// As a last resort, we recover from a panic when running the analyzer, convert the panic to
	// a diagnostic and return.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic occurred in `%s` analyzer: %v\n%s", source, r, debug.Stack())
		}
	}()

	// First check if the cache analyzer has the result.
	if d.opts.Analyzers[constant.CacheAnalyzerKind] {
		source = constant.CacheAnalyzerKind
		var originalInfo cacheanalyzer.OriginalFailnessInfo
		originalInfo, err = d.cacheAnalyzer.AnalyzeCall(caller, calleeSite)
		if err == nil {
			analyzerOutput = &output.AnalyzerOutput{Status: originalInfo.Status, Source: source, OriginalSource: originalInfo.Source}
			return
		}
		// if the cache analyzer does not find, add the result to the cache in the end, if there is no error.
		defer func() {
			if err == nil {
				d.cacheAnalyzer.InsertToCache(caller, calleeSite, analyzerOutput.Status, analyzerOutput.OriginalSource)
			}
		}()
	}

	// Run Predefined analyzer.
	if d.opts.Analyzers[constant.Predefined] {
		source = constant.Predefined
		var statusCode constant.Failness
		statusCode, err = predefined.AnalyzeCall(caller, calleeSite)
		if err == nil && statusCode != constant.FailUnknown {
			analyzerOutput = &output.AnalyzerOutput{Status: statusCode, Source: source, OriginalSource: constant.Predefined}
			return
		}
	}

	// Run SCCP analyzer first; fall back to SSA/AST only if it fails or returns unknown.
	if d.opts.Analyzers[constant.SCCP] {
		source = constant.SCCP
		sccpOpts := ssaanal.DefaultSCCPOptions()
		sccpOpts.Logger = d.Logger
		sccpOpts.InverseCheck = true
		sccpOpts.Metrics = d.sccpMetrics
		sccpOpts.NilOtherSourcesAfterSrc = d.opts.NilOtherSourcesAfterSrc
		sccpOpts.KnownErrorConstructorFuncs = d.opts.Config.KnownErrorConstructorFuncs
		if allCalls := d.callerCalleeSites[caller]; len(allCalls) > 1 {
			others := make([]*ssa.Call, 0, len(allCalls)-1)
			for _, c := range allCalls {
				if ssa.CallInstruction(c) != calleeSite {
					others = append(others, c)
				}
			}
			sccpOpts.OtherSources = others
		}
		sccpStart := time.Now()
		statusCode, sccpErr := ssaanal.AnalyzeCallBySCCPWithOptions(caller, calleeSite, sccpOpts)
		d.analyzerDurations[_sccpAnalysisDurationSecs] += time.Since(sccpStart).Seconds()
		if sccpErr == nil && statusCode != constant.FailUnknown {
			analyzerOutput = &output.AnalyzerOutput{Status: statusCode, Source: source, OriginalSource: constant.SCCP}
			return
		}
	}

	// Run SSA analyzer (fallback)
	if d.opts.Analyzers[constant.SSA] {
		source = constant.SSA
		var statusCode constant.Failness
		ssaStart := time.Now()
		statusCode, err = ssaanal.AnalyzeCall(caller, calleeSite)
		d.analyzerDurations[_ssaAnalyzerDurationSecs] += time.Since(ssaStart).Seconds()
		if err == nil && statusCode != constant.FailUnknown {
			analyzerOutput = &output.AnalyzerOutput{Status: statusCode, Source: source, OriginalSource: constant.SSA}
			return
		}
	}

	// Prepare required inputs for calling the AST and LLM analyzers.
	prepareASTContext := func() (*ast.FuncDecl, error) {
		if astContext == nil {
			return nil, fmt.Errorf("AST context is nil")
		}
		callerAST, ok := d.SSAASTBidirMap.StoA[caller]
		if !ok {
			return nil, fmt.Errorf("caller `%s` not found in SSA to AST map", caller.Name())
		}
		var callerFuncDecl *ast.FuncDecl
		switch c := callerAST.(type) {
		case *ast.FuncDecl:
			callerFuncDecl = c
		case *ast.FuncLit:
			if f, ok := astContext.FuncLitFuncMap[c]; ok {
				callerFuncDecl = f.FakeFuncDecl
			}
		default:
			return nil, fmt.Errorf("caller `%s` is not a function declaration or literal", caller.Name())
		}
		return callerFuncDecl, nil
	}

	// Run AST analyzer
	if d.opts.Analyzers[constant.AST] {
		source = constant.AST
		callerFuncDecl, prepErr := prepareASTContext()
		if prepErr != nil {
			return nil, fmt.Errorf("prepare AST context for AST analyzer: %w", prepErr)
		}
		astStart := time.Now()
		analyzerOutput, err = function.Run(callerFuncDecl, callee, astContext, d.Logger)
		d.analyzerDurations[_astAnalyzerDurationSecs] += time.Since(astStart).Seconds()
		if err == nil && analyzerOutput.Status != constant.FailUnknown {
			return
		}
		if err != nil {
			err = errors.Join(err, fmt.Errorf("run AST analyzer: %w", err))
			if analyzerOutput == nil {
				analyzerOutput = &output.AnalyzerOutput{}
			}
			analyzerOutput.Status = constant.FailUnknownWithError
			analyzerOutput.Source = constant.AST
			analyzerOutput.OriginalSource = constant.AST
		}
	}

	// Run LLM analyzer
	if d.opts.Analyzers[constant.LLM] {
		source = constant.LLM
		callerFuncDecl, prepErr := prepareASTContext()
		if prepErr != nil {
			return nil, fmt.Errorf("prepare AST context for LLM analyzer: %w", prepErr)
		}
		analyzerOutput, err = d.runLLMAnalyzer(callerFuncDecl, callee, calleeObj, astContext)
		if err != nil {
			err = errors.Join(err, fmt.Errorf("run LLM analyzer: %w", err))
			if analyzerOutput == nil {
				analyzerOutput = &output.AnalyzerOutput{}
			}
			analyzerOutput.Status = constant.FailUnknownWithError
			analyzerOutput.Source = constant.LLM
			analyzerOutput.OriginalSource = constant.LLM
		}
	}

	return
}

func (d *Driver) runLLMAnalyzer(caller *ast.FuncDecl, callee *ast.CallExpr, calleeObj types.Object, astContext *asthelper.ASTContext) (*output.AnalyzerOutput, error) {
	if calleeObj == nil {
		return nil, fmt.Errorf("callee is nil")
	}
	calleeSitePosition := astContext.PkgInfo.Pkg.Fset.Position(callee.Pos())
	startPos := astContext.PkgInfo.Pkg.Fset.PositionFor(caller.Pos(), false)
	endPos := astContext.PkgInfo.Pkg.Fset.PositionFor(caller.End(), false)
	filePath := startPos.Filename
	llmCallerFuncInput := input.NewLLMFuncInput(caller.Name.Name, filePath, startPos.Line, endPos.Line)
	llmAnalyzerInput := input.NewLLMAnalyzerInput(llmCallerFuncInput, calleeObj.Name(), calleeSitePosition.Line)
	analyzerOutput, err := genai.LLMAnalyzer(context.Background(), d.AIClient, "", llmAnalyzerInput, d.Logger)
	if err != nil {
		return nil, fmt.Errorf("run LLM analyzer: %w", err)
	}
	return analyzerOutput, nil
}

func (d *Driver) getMain(ssaProg *ssa.Program) []*ssa.Package {
	mains := []*ssa.Package{}
	progPkgs := ssaProg.AllPackages()
	for _, pkg := range progPkgs {
		if pkg == nil {
			continue
		}
		if pkg.Pkg == nil {
			continue
		}
		if pkg.Pkg.Name() == "main" {
			d.Logger.Infow("Found main pkg", "pkg", pkg)
			if pkg.Func("main") != nil {
				mains = append(mains, pkg)
			}
		}
	}
	if len(mains) == 0 {
		d.Logger.Info("No main packages found")
	}
	return mains
}

func repairIllTypedPropagationFromSourcelessPkgs(pkgs []*packages.Package) {
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if isSourcelessBuildConstraintPackage(p) {
			p.IllTyped = false
			return
		}
		if p.Types == nil {
			return
		}
		illTyped := len(p.Errors) > 0
		if !illTyped {
			for _, imp := range p.Imports {
				if imp.IllTyped {
					illTyped = true
					break
				}
			}
		}
		p.IllTyped = illTyped
	})
}

// isSourcelessBuildConstraintPackage reports whether p failed to type-check solely because it has
// no Go files matching the current build constraints (e.g. a vendored package whose only source
// file is gated behind a dead/ancient Go version tag such as "!go1.7"). go/packages' loader emits
// a "sources missing for package" diagnostic for these and falls back to loading from export data;
// that fallback can fail in some Bazel build environments even though the package genuinely has no
// compiled sources to analyze.
func isSourcelessBuildConstraintPackage(p *packages.Package) bool {
	if len(p.CompiledGoFiles) != 0 || len(p.Errors) == 0 {
		return false
	}
	for _, e := range p.Errors {
		if !strings.HasPrefix(e.Msg, "sources missing for package ") {
			return false
		}
	}
	return true
}

// dumpPackageDiagnostics logs the packages that failed to load and returns how many loaded
// cleanly and how many did not.
//
// A package failed to load exactly when ssautil.AllPackages would not create an SSA package for
// it, which it decides from `p.Types != nil && !p.IllTyped`. Deciding it here from the same two
// fields rather than from a nil lookup in the built SSA program lets the caller bail out before
// paying for SSA construction.
func (d *Driver) dumpPackageDiagnostics(pkgs []*packages.Package) (int, int) {
	packagesWithErrors := 0
	packageWoErrors := 0
	for _, p := range pkgs {
		typeInf := 0
		if p.TypesInfo != nil {
			typeInf = len(p.TypesInfo.Types)
		}

		if p.Types == nil || p.IllTyped {
			d.Logger.Infow("dumpPackageDiagnostic", "PkgName", p.Name, "PkgPath", p.PkgPath, "TypeInfoLen", typeInf)

			if isSourcelessBuildConstraintPackage(p) {
				// This package has no Go files matching the current build constraints (e.g. a
				// vendored package whose only source file is gated behind an ancient/dead Go
				// version tag like "!go1.7"). go/packages' loader already self-heals this by
				// falling back to export-data loading; whether that fallback yields non-nil
				// types can vary across Bazel build environments, but since the package has no
				// compiled sources, there is no code that could depend on missing symbols here.
				// Treat it as empty rather than fatal.
				d.Logger.Infow("dumpPackageDiagnostic", "PkgName", p.Name, "PkgPath", p.PkgPath, "sourcelessBuildConstraintPackage", true)
				packageWoErrors++
				continue
			}

			packagesWithErrors++
			// nil implies some error in the package. How many errors?

			if len(p.Errors) > 0 {
				d.Logger.Infow("dumpPackageDiagnostic", "num_errors", len(p.Errors))
				for _, e := range p.Errors {
					d.Logger.Infow("dumpPackageDiagnostic", "p.Name", p.Name, "error", e)
				}
			}
			if len(p.TypeErrors) > 0 {
				d.Logger.Infow("dumpPackageDiagnostic", "num_type_errors", len(p.TypeErrors))
				for _, e := range p.TypeErrors {
					d.Logger.Infow("dumpPackageDiagnostic", "p.Name", p.Name, "error", e)
				}
			}
		} else {
			packageWoErrors++
		}
	}
	// Find the main packages.
	d.Logger.Infow("dumpPackageDiagnostic", "packageWoErrors", packageWoErrors, "packagesWithErrors", packagesWithErrors)
	return packageWoErrors, packagesWithErrors
}

// findTargets resolves serviceName to its Bazel targets, using DriverOptions.Targets directly if
// supplied, else DriverOptions.TargetResolver, else the default pinocchioTargetResolver.
func (d *Driver) findTargets(serviceName string) ([]string, error) {
	if len(d.opts.Targets) > 0 {
		return d.opts.Targets, nil
	}
	resolver := d.opts.TargetResolver
	if resolver == nil {
		resolver = NewPinocchioTargetResolver(d.WorkspaceRoot, d.Logger)
	}
	return resolver.FindTargets(serviceName)
}

// findPackageFromTarget finds the entry-point package given its resolved import path.
func (d *Driver) findPackageFromTarget(targetPkgPath string, pkgs []*packages.Package) (*packages.Package, error) {
	for _, pkg := range pkgs {
		if pkg.PkgPath == targetPkgPath {
			return pkg, nil
		}
	}
	return nil, fmt.Errorf("target package %s not found", targetPkgPath)
}

// filterIrrelevantOutbounds filters out the OB points for the service that are not lower than the
// service tier (given by callerTier). If the OB point is not associated with a service (happens
// when the service name inference for OBs fails), it will be kept by default.
func (d *Driver) filterIrrelevantOutbounds(outbounds []fty.OutboundPoint, callerTier int) []fty.OutboundPoint {
	filtered := make([]fty.OutboundPoint, 0, len(outbounds))
	for _, ob := range outbounds {
		// add HTTP OBs anyway, will filter out after CG construction
		if ob.Type == fty.TypeHTTP || callerTier < ob.Service.Tier {
			filtered = append(filtered, ob)
		}
	}
	return filtered
}

func (d *Driver) countOutboundsType(outbounds []fty.OutboundPoint) map[fty.OutboundType]float64 {
	countMap := make(map[fty.OutboundType]float64)
	for _, ob := range outbounds {
		switch ob.Type {
		case fty.TypeHTTP:
			countMap[fty.TypeHTTP] += 1.0
		case fty.TypeGRPC:
			countMap[fty.TypeGRPC] += 1.0
		case fty.TypeThrift:
			countMap[fty.TypeThrift] += 1.0
		case fty.TypeCadence:
			countMap[fty.TypeCadence] += 1.0
		default:
			countMap[ob.Type] += 1.0
		}
	}
	return countMap
}

func (d *Driver) shouldSkipForMissingProdTraffic(curService grail.Service) bool {
	noProdIBTraffic := slices.ContainsFunc(d.ProdServiceTrafficRecords, func(r query.ProdServiceTrafficRecord) bool {
		return r.ServiceName == curService.Name && !r.AppearedAsCallee
	})
	noProdOBTraffic := slices.ContainsFunc(d.ProdServiceTrafficRecords, func(r query.ProdServiceTrafficRecord) bool {
		return r.ServiceName == curService.Name && !r.AppearedAsCaller
	})
	d.Logger.Infow(
		"Production traffic gate",
		"no_prod_ib_traffic", noProdIBTraffic,
		"no_prod_ob_traffic", noProdOBTraffic,
		"skip_gate", d.opts.SkipProdTrafficFilter,
	)
	return (noProdIBTraffic || noProdOBTraffic) && !d.opts.CGConstructionOnly && !d.opts.SkipProdTrafficFilter
}

// processReportsForOutput processes the reports to create user-friendly output reports by limiting
// the number of paths per fail-ness type. This helps keep the output manageable for CSV and HTML reports.
func (d *Driver) processReportsForOutput(reports []output.Report) []output.Report {
	outputReports := make([]output.Report, 0, len(reports))

	// Priority order for fail-ness status
	priorityOrder := []constant.Failness{
		constant.FailClose,
		constant.FailCloseSuppressed,
		constant.FailOpen,
		constant.FailUnknown,
		constant.FailUnknownWithError,
	}

	// Percentage-based quotas (must sum to 100)
	quotaPercentages := map[constant.Failness]int{
		constant.FailClose:            40,
		constant.FailCloseSuppressed:  15,
		constant.FailOpen:             15,
		constant.FailUnknown:          15,
		constant.FailUnknownWithError: 15,
	}

	for _, report := range reports {
		var outputPathResults []output.PathResult

		if len(report.PathResults) > constant.MaxPathsToStoreForQuadruple {
			// Pre-allocate with a reasonable size based on max paths
			outputPathResults = make([]output.PathResult, 0, constant.MaxPathsToStoreForQuadruple)

			// Group paths by status
			pathsByStatus := make(map[constant.Failness][]output.PathResult)
			for _, r := range report.PathResults {
				pathsByStatus[r.Status] = append(pathsByStatus[r.Status], r)
			}

			// Calculate actual quotas based on percentages
			quotas := make(map[constant.Failness]int)
			remainingPaths := constant.MaxPathsToStoreForQuadruple

			// First pass: calculate quotas and handle rounding
			for _, status := range priorityOrder {
				if status == priorityOrder[len(priorityOrder)-1] {
					// Last status gets remaining paths to ensure we sum to MaxPathsToStoreForQuadruple
					quotas[status] = remainingPaths
				} else {
					// Calculate quota based on percentage
					quota := (constant.MaxPathsToStoreForQuadruple * quotaPercentages[status]) / 100
					quotas[status] = quota
					remainingPaths -= quota
				}
			}

			// Take paths in priority order up to their quota
			for _, status := range priorityOrder {
				paths := pathsByStatus[status]
				quota := quotas[status]
				// Take up to quota number of paths for this status
				for i := 0; i < len(paths) && i < quota; i++ {
					outputPathResults = append(outputPathResults, paths[i])
				}
			}
		} else {
			// If within limits, just use all paths
			outputPathResults = report.PathResults
		}

		// Copy the base report and modify only what's needed
		outputReport := report
		outputReport.PathResults = outputPathResults
		outputReports = append(outputReports, outputReport)
	}

	return outputReports
}

// resolveHTTPOutboundService resolves the HTTP outbound service name in per call path manner
// one HTTP outbound endpoint could be shared by multiple services, so per-call path resolution is needed.
// return the resolved paths and filter out the paths that cannot find the service name.
// Tier filtering is skipped when outbound clipping by tier is disabled.
func (d *Driver) resolveHTTPOutboundService(paths []*graph.CallPath, curService grail.Service) ([]*graph.CallPath, int, int, []fty.OutboundPoint) {
	resolvedPaths := make([]*graph.CallPath, 0, len(paths))
	totalHTTPPathCount := 0
	resolvedPathsCount := 0
	resolvedOutbounds := make([]fty.OutboundPoint, 0)
	for _, path := range paths {
		if path.Outbound.Type != fty.TypeHTTP {
			// non-HTTP outbound, skip the resolution
			resolvedPaths = append(resolvedPaths, path)
			continue
		}
		matchedService := false
		totalHTTPPathCount += 1
		for i := len(path.Edges) - 1; i >= 0 && !matchedService; i-- {
			// reverse the edges can check the callee node, which will cover the ob node
			edge := path.Edges[i].Edge
			callerPkgPath := ""
			if edge.Caller.Func != nil && edge.Caller.Func.Pkg != nil && edge.Caller.Func.Pkg.Pkg != nil {
				callerPkgPath = edge.Caller.Func.Pkg.Pkg.Path()
			}
			matches := gatewayPathRegex.FindStringSubmatch(callerPkgPath)
			// find something like gateways/service-name/...
			if len(matches) >= 2 {
				extracted := matches[1]
				outPath := strings.Split(extracted, "/")
				// reverse the parts
				for i := len(outPath) - 1; i >= 0 && !matchedService; i-- {
					if outPath[i] == "" {
						continue
					}
					// reference to the service name from GrailService
					for _, service := range d.AllServices {
						if service.Name == outPath[i] {
							path.Outbound.Service = service
							matchedService = true
							resolvedPathsCount += 1
							resolvedOutbounds = append(resolvedOutbounds, path.Outbound)
							break
						}
					}
				}
			}
		}
		if !matchedService {
			d.Logger.Warnw("Failed to match service name for HTTP outbound path", "path", path)
			continue
		}
		// Tier filtering HTTP outbounds are per-path-based, we need to do tier filtering after the service name resolution.
		if d.opts.SkipOBTierFilter || curService.Tier < path.Outbound.Service.Tier {
			resolvedPaths = append(resolvedPaths, path)
		} else {
			d.Logger.Warnw("HTTP outbound path is not lower than the service tier", "path", path)
		}
	}
	return resolvedPaths, totalHTTPPathCount, resolvedPathsCount, resolvedOutbounds
}

// getMaxUsedDram returns the maximum resident set size (RSS) used by the process in kilobytes.
func getMaxUsedDram() (int64, error) {
	var rusage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &rusage); err != nil {
		return 0, fmt.Errorf("failed to get resource usage: %w", err)
	}
	return rusage.Maxrss, nil
}

// dirBasedImportPath derives a target's import path from its label directory alone. It is the
// right answer for the common case where a go_binary and the go_library it compiles share a
// directory; see resolveTargetImportPath for the embed-in-another-directory case.
func dirBasedImportPath(target string) string {
	return strings.Split(strings.TrimPrefix(target, "//src/"), ":")[0]
}

// resolveTargetImportPath returns the Go import path of the source code compiled into target.
// For most go_binary targets this is simply target's own directory. For go_binary targets
// declared as `go_binary(name="foo", embed=[":lib"])` where the embedded go_library lives in
// a different directory, target itself declares no importpath -- the compiled code is the embed
// target's library, whose import path is that library's directory.
//
// Resolution walks the target's `embed` attribute via a narrow single-attribute bazel query:
//
//	bazel query 'labels("embed", //TARGET)' --output=label
//
// A non-empty result yields the embedded library's directory-derived import path; an empty
// result (self-contained target) or a query error falls back to target's own directory, so the
// common case is unaffected. The query is deliberately narrow -- one attribute on one target
// with no graph traversal -- so it cannot pull in data-only or tool dependencies.
func resolveTargetImportPath(runner utils.Runner, logger *zap.SugaredLogger, bazelPath, target string) string {
	dirBased := dirBasedImportPath(target)
	query := fmt.Sprintf(`labels("embed", %s)`, target)
	out, _, err := utils.ExecCommand(runner, bazelPath, "query", "--output=label", query)
	if err != nil {
		logger.Debugw("resolveTargetImportPath: embed query failed, falling back to target dir", "target", target, "dir", dirBased, "error", err)
		return dirBased
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "//src/") {
			continue
		}
		embedded := dirBasedImportPath(line)
		if embedded != dirBased {
			logger.Infow("resolveTargetImportPath: target embeds a library from a different directory; using embed's import path", "target", target, "target_dir", dirBased, "embed_label", line, "resolved_import_path", embedded)
		}
		return embedded
	}
	return dirBased
}

// canonicalizeLabel normalizes a Bazel target label to its fully-qualified form so downstream
// `bazel query`/`cquery` invocations resolve it against the workspace root regardless of the
// process cwd. `//pkg` becomes `//pkg:pkg`, `@repo//pkg` becomes `@repo//pkg:pkg`, and bare
// workspace-root labels (`pkg/path:name` or `pkg/path`) get the `//` prefix, so both writing
// styles round-trip to canonical form.
func canonicalizeLabel(label string) string {
	if !strings.HasPrefix(label, "//") && !strings.HasPrefix(label, "@") {
		label = "//" + label
	}
	if strings.Contains(label, ":") {
		return label
	}
	if idx := strings.LastIndex(label, "/"); idx >= 0 {
		return label + ":" + label[idx+1:]
	}
	return label
}

func useBazelLoader(serviceName string, bazelLoaderServices []string, forceMode string) bool {
	switch forceMode {
	case "bazel":
		return true
	case "gopath":
		return false
	}
	return slices.Contains(bazelLoaderServices, serviceName)
}
