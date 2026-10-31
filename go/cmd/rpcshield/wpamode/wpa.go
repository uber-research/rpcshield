package wpamode

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"

	rpcshield "github.com/uber-research/rpcshield/go"
	"github.com/uber-research/rpcshield/go/bazel"
	"github.com/uber-research/rpcshield/go/cmd/rpcshield/common"
	"github.com/uber-research/rpcshield/go/common/utils"
	"github.com/uber-research/rpcshield/go/config"
	"github.com/uber-research/rpcshield/go/constant"
	"github.com/uber-research/rpcshield/go/finder/servicemapping"
	"github.com/uber-research/rpcshield/go/genai"
	"github.com/uber-research/rpcshield/go/grail"
	"github.com/uber-research/rpcshield/go/query"
	"github.com/uber-research/rpcshield/go/serviceregistry"
	"github.com/uber-research/rpcshield/go/staticanalyzer/asthelper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/tools/go/packages"
)

// Options contains the options for the WPA sub-command.
type Options struct {
	// Service is the service name to run WPA on.
	Service string
	// Workspace is the workspace directory (i.e., the root of the monorepo).
	Workspace string
	// LogLevel is the log level for the logger.
	LogLevel zapcore.Level
	// Report indicates whether the rpcshield's findings are reported.
	Report bool
	// ReportMetrics indicates whether the metrics are reported via LDA.
	ReportMetrics bool
	// CachedGrailAllServicesJSON is the path to the cached grail response for all services JSON file.
	// It is mainly used in CI to avoid querying grail services over and over again since the
	// internal mTLS certificate used to authenticate isn't available in CI for long-running jobs
	// (the certificate expires in 1 hour).
	CachedGrailAllServicesJSON common.CacheOption
	// CachedFxMappingsJSON is the path to the cached Fx mapping from the Fx scanner.
	CachedFxMappingsJSON common.CacheOption
	// CachedProdTrafficRecordsJSON is the path to the cached production service traffic records JSON file.
	CachedProdTrafficRecordsJSON common.CacheOption
	// FetchProductionTrafficRecords fetches fresh production service traffic records when the
	// cache is empty or being refreshed (see CachedProdTrafficRecordsJSON). Nil disables the
	// feature, returning no records instead of fetching any (the OSS default, since this
	// typically requires a Uber-internal warehouse query).
	// json:"-" since encoding/json can't marshal a func -- and would otherwise abort marshaling
	// this whole struct (used for the "Running WPA" options log line) at the first func field it
	// hits, silently dropping every field after it too.
	FetchProductionTrafficRecords func() ([]query.ProdServiceTrafficRecord, error) `json:"-"`
	// FetchUSSOToken fetches a USSO token for the given host when GrailUSSOToken/GenAIAPIUSSOToken
	// aren't supplied directly. Nil (the OSS default) means tokens must be supplied directly;
	// Run returns an error if a token is needed but neither is set.
	FetchUSSOToken func(host string, logger *zap.SugaredLogger) (string, error) `json:"-"`
	// ReportResult reports a named set of metrics/values, called only when ReportMetrics is set.
	// Nil (the OSS default) makes ReportMetrics a no-op, since reporting typically targets a
	// Uber-internal LDA telemetry endpoint.
	ReportResult func(toolname string, values map[string]string, logger *zap.SugaredLogger) error `json:"-"`
	// CachedKeepIBPkgsJSON is the path to the cached keep packages JSON file.
	CachedKeepIBPkgsJSON common.CacheOption
	// CPUProfile is the path to write CPU profile to (only if non-empty).
	CPUProfile string
	// AllocsProfile is the path to write allocs profile to (only if non-empty).
	AllocsProfile string
	// MutexProfile is the path to write mutex profile to (only if non-empty).
	MutexProfile string
	// BlockProfile is the path to write block profile to (only if non-empty).
	BlockProfile string
	// SkipOBTierFilter is the flag to disable OB clipping by the callee tiers.
	SkipOBTierFilter bool
	// SkipProdTrafficFilter disables skipping services without observed inbound or outbound production traffic.
	SkipProdTrafficFilter bool
	// Analyzers is the list of analyzers (SSA, AST, LLM) to run for fail-ness detection.
	Analyzers map[constant.AnalyzerKind]bool
	// GitSHA is the git SHA of the commit to be analyzed.
	GitSHA string
	// CSV is the flag to write the report to a CSV file.
	CSV bool
	// HTML is the flag to write the report to an HTML file.
	HTML bool
	// OutputDir is the directory to write the report CSV file to.
	OutputDir string
	// Timestamp is the timestamp to store the date/time when rpcshield is run.
	Timestamp string
	// FractionOfDRAM is the fraction of DRAM to use for the analysis (0-1).
	FractionOfDRAM float64
	// GrailUSSOToken is the Grail USSO token.
	GrailUSSOToken string
	// GenAIAPIUSSOToken is the GenAI API USSO token.
	GenAIAPIUSSOToken string
	// Difftime is the flag to run the diff time analysis.
	Difftime bool
	// BaseSHA todo: will be removed when remote branch is supported.
	BaseSHA string
	// DisableSCCPAnalysis disables SCCP (Sparse Conditional Constant Propagation) analysis.
	DisableSCCPAnalysis bool
	// NilOtherSourcesAfterSrc sets OtherSources to Nil when they appear after Src in the CFG.
	NilOtherSourcesAfterSrc bool
	// RTAFlavor is the RTA implementation flavor for the normal Build path.
	RTAFlavor string
	// RTANumWorkers is the number of workers for the normal Build path.
	RTANumWorkers string
	// DisableParallelCallTree is the flag to disable parallel call tree computation.
	DisableParallelCallTree bool
	// CGConstructionOnly is the flag to only run CG construction for eval bench (skip outbound detection and path analysis).
	CGConstructionOnly bool
	// RTABenchFlavors is the comma-separated list of RTA flavors for CG construction-only benchmarking, or "all".
	RTABenchFlavors string
	// RTABenchNumWorkers is the comma-separated list of worker counts for CG construction-only benchmarking.
	RTABenchNumWorkers string
	// CheckIsomorphism enables isomorphism checking between srta and prta_kumo_nonblocking (only for CGConstructionOnly).
	CheckIsomorphism bool
	// PermutationThreshold is the number of times the same function-set hash must
	// be observed reaching a sink before permutation detection triggers. Default is 100. Set to 0 to disable.
	PermutationThreshold int64
	// ForceLoaderMode, when non-empty, overrides the BazelLoaderServices allowlist for this run:
	// "bazel" forces the BazelLoader path, "gopath" forces GoPathWrapper.LiftGoPath. Empty keeps
	// the per-service allowlist behavior.
	ForceLoaderMode string
	// TierOverrides is a map of service name to tier number for overriding Grail-sourced tiers.
	TierOverrides map[string]int
	// CanonicalEdgeOrder sorts call-graph outgoing edges deterministically before path exploration.
	CanonicalEdgeOrder bool
	// ExtraExcludePackagePatterns is passed straight through to
	// config.Config.ExtraExcludePackagePatterns -- additional graph call-graph package-exclusion
	// regex patterns on top of graph.DefaultExcludePackagePatterns. Empty (the OSS default) adds
	// nothing, so only the generic OSS defaults apply.
	ExtraExcludePackagePatterns []string
	// CodePrefix, RepoNameForCSV, SourcegraphURLTemplate, TerrablobFileURLTemplate,
	// MoneyIntegrationGogoprotoPath, CodebasePkgPrefix, and AdditionalHTTPClientTypes are passed
	// straight through to the matching config.Config fields -- see that struct's doc comments for
	// what each one does. All are empty (the OSS default) unless the caller supplies an
	// organization-specific value.
	CodePrefix                    string
	RepoNameForCSV                string
	SourcegraphURLTemplate        string
	TerrablobFileURLTemplate      string
	MoneyIntegrationGogoprotoPath string
	CodebasePkgPrefix             string
	AdditionalHTTPClientTypes     []string
	KafkaConsumerProxyPkgPath     string
	InfraPkgPrefixes              []string
	KnownErrorConstructorFuncs    []string
	SafeGoPkgPath                 string
	// GraphDisableContextRelaxServices and BazelLoaderServices are passed straight through to the
	// matching config.Config fields -- see that struct's doc comments for what each one does. Both
	// are empty (the OSS default) unless the caller supplies an organization-specific value.
	GraphDisableContextRelaxServices []string
	BazelLoaderServices              []string
	// GrailHost, GrailRPCServiceName, GenAIBaseURL, GenAIModel, and GenAIOrgID are passed straight
	// through to the matching config.Config fields, and additionally used directly to configure
	// the *grail.Grail and genai.Client this Run constructs (unless ServiceRegistryProvider is
	// set, in which case GrailHost/GrailRPCServiceName are unused). See config.Config's doc
	// comments for what each one does and its OSS default.
	GrailHost           string
	GrailRPCServiceName string
	GenAIBaseURL        string
	GenAIModel          string
	GenAIOrgID          string
	// BazelLoader, when set, is passed straight through to rpcshield.DriverOptions.BazelLoader --
	// see that field's doc for details. Nil (the OSS default) disables the fast path.
	BazelLoader func(targetPkgPath string, additionalLabels []string) ([]*packages.Package, error) `json:"-"`
	// KeepGoPathAfterRun is passed straight through to rpcshield.DriverOptions.KeepGoPathAfterRun.
	KeepGoPathAfterRun bool
	// ServiceRegistryProvider supplies the service list and outbound-client-type-to-service
	// mapping used to build the Driver's AllServices and ServiceMapper. Nil (the OSS default)
	// constructs serviceregistry.DefaultServiceRegistryProvider wired to a *grail.Grail client
	// using GrailUSSOToken/FetchUSSOToken -- i.e. today's exact Grail+FxScanner pipeline,
	// unchanged. Callers without Uber's Grail registry or codebase-specific Fx-scanning
	// conventions can supply their own ServiceRegistryProvider instead.
	ServiceRegistryProvider serviceregistry.ServiceRegistryProvider `json:"-"`
}

const _numRenameWorkers = 16

// Run is the entrypoint for running whole program analysis mode of rpcshield.
func Run(options Options) (rpcshield.Result, error) {
	if options.CPUProfile != "" {
		f, err := os.Create(options.CPUProfile)
		if err != nil {
			return rpcshield.Result{}, fmt.Errorf("open CPU profile file: %w", err)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			return rpcshield.Result{}, fmt.Errorf("start CPU profile: %w", err)
		}
		defer pprof.StopCPUProfile()
	}
	if options.AllocsProfile != "" {
		defer func() {
			f, err := os.Create(options.AllocsProfile)
			if err != nil {
				return
			}
			defer f.Close()
			if prof := pprof.Lookup("allocs"); prof != nil {
				prof.WriteTo(f, 0)
			}
		}()
	}

	// Enable mutex profiling if requested
	if options.MutexProfile != "" {
		runtime.SetMutexProfileFraction(1)
		defer func() {
			f, err := os.Create(options.MutexProfile)
			if err != nil {
				return
			}
			defer f.Close()
			if prof := pprof.Lookup("mutex"); prof != nil {
				prof.WriteTo(f, 0)
			}
		}()
	}

	// Enable block profiling if requested
	if options.BlockProfile != "" {
		runtime.SetBlockProfileRate(1)
		defer func() {
			f, err := os.Create(options.BlockProfile)
			if err != nil {
				return
			}
			defer f.Close()
			if prof := pprof.Lookup("block"); prof != nil {
				prof.WriteTo(f, 0)
			}
		}()
	}
	logger, err := common.BuildLogger(options.LogLevel)
	if err != nil {
		return rpcshield.Result{}, fmt.Errorf("build logger: %w", err)
	}

	if err := setMemoryLimit(options.FractionOfDRAM, logger); err != nil {
		return rpcshield.Result{}, fmt.Errorf("set memory limit: %w", err)
	}

	redacted := options
	redacted.GrailUSSOToken = "<REDACTED>"
	redacted.GenAIAPIUSSOToken = "<REDACTED>"
	logger.Infow("Running WPA", "options", redacted)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runner := utils.OSRunner{}
	renamer := bazel.NewFSRenamer(utils.OSFileSystem{}, _numRenameWorkers, logger)
	cfg := config.Config{
		SourcegraphURLTemplate:           options.SourcegraphURLTemplate,
		CodePrefix:                       options.CodePrefix,
		RepoNameForCSV:                   options.RepoNameForCSV,
		TerrablobFileURLTemplate:         options.TerrablobFileURLTemplate,
		MoneyIntegrationGogoprotoPath:    options.MoneyIntegrationGogoprotoPath,
		CodebasePkgPrefix:                options.CodebasePkgPrefix,
		AdditionalHTTPClientTypes:        options.AdditionalHTTPClientTypes,
		ExtraExcludePackagePatterns:      options.ExtraExcludePackagePatterns,
		KafkaConsumerProxyPkgPath:        options.KafkaConsumerProxyPkgPath,
		InfraPkgPrefixes:                 options.InfraPkgPrefixes,
		KnownErrorConstructorFuncs:       options.KnownErrorConstructorFuncs,
		SafeGoPkgPath:                    options.SafeGoPkgPath,
		GraphDisableContextRelaxServices: options.GraphDisableContextRelaxServices,
		BazelLoaderServices:              options.BazelLoaderServices,
		GrailHost:                        options.GrailHost,
		GrailRPCServiceName:              options.GrailRPCServiceName,
		GenAIBaseURL:                     options.GenAIBaseURL,
		GenAIModel:                       options.GenAIModel,
		GenAIOrgID:                       options.GenAIOrgID,
	}
	gp := bazel.NewGoPathWrapper(options.Workspace, options.Service, options.OutputDir, logger, renamer, cfg)

	registryProvider := options.ServiceRegistryProvider
	if registryProvider == nil {
		if options.GrailUSSOToken == "" {
			if options.FetchUSSOToken == nil {
				return rpcshield.Result{}, errors.New("GrailUSSOToken not set and no FetchUSSOToken configured")
			}
			var err error
			options.GrailUSSOToken, err = options.FetchUSSOToken(options.GrailHost, logger)
			if err != nil {
				return rpcshield.Result{}, fmt.Errorf("fetch Grail USSO token: %w", err)
			}
		}
		grailClient, err := grail.New(&grail.Options{
			Host:           options.GrailHost,
			RPCServiceName: options.GrailRPCServiceName,
			Logger:         logger,
			USSOToken:      options.GrailUSSOToken,
		})
		if err != nil {
			return rpcshield.Result{}, fmt.Errorf("create grail client: %w", err)
		}
		registryProvider = &serviceregistry.DefaultServiceRegistryProvider{
			Grail:                      grailClient,
			Workspace:                  options.Workspace,
			Logger:                     logger,
			CachedGrailAllServicesJSON: options.CachedGrailAllServicesJSON,
			CachedFxMappingsJSON:       options.CachedFxMappingsJSON,
			CodebasePkgPrefix:          options.CodebasePkgPrefix,
		}
	}
	registry, err := registryProvider.Provide(ctx)
	if err != nil {
		return rpcshield.Result{}, fmt.Errorf("provide service registry: %w", err)
	}
	allServices := registry.Services

	// Apply tier overrides if provided.
	if len(options.TierOverrides) > 0 {
		for i := range allServices {
			if overrideTier, ok := options.TierOverrides[allServices[i].Name]; ok {
				logger.Warnw("Overriding service tier due to -tier-overrides flag",
					"service", allServices[i].Name,
					"from_tier", allServices[i].Tier,
					"to_tier", overrideTier,
				)
				allServices[i].Tier = overrideTier
			}
		}
	}

	// Get list of packages to keep during analysis either from cached JSON (if provided) or generate it.
	recreatedKeepPkgs := func() (map[string]bool, error) {
		// TODO: fetch from the configured object storage backend when available.
		logger.Infow("Keep IB Pkgs list fetching logic not implemented, returning empty list")
		return make(map[string]bool), nil
	}
	keepIBPkgs, err := common.FetchFromCache(options.CachedKeepIBPkgsJSON, filepath.Join(options.Workspace, "build", "rpcshield", fmt.Sprintf("%s_keep_ib_pkgs.json", options.Service)), recreatedKeepPkgs, logger)
	if err != nil {
		return rpcshield.Result{}, fmt.Errorf("fetch keep packages: %w", err)
	}
	logger.Infow("List of packages to keep in inbound detection", "pkg_count", len(keepIBPkgs))

	serviceMapper := servicemapping.New(allServices, registry.ClientTypeMapping, logger, options.CodebasePkgPrefix)

	recreateProductionTrafficRecords := options.FetchProductionTrafficRecords
	if recreateProductionTrafficRecords == nil {
		recreateProductionTrafficRecords = func() ([]query.ProdServiceTrafficRecord, error) {
			return nil, nil
		}
	}

	productionTrafficRecords, err := common.FetchFromCache(options.CachedProdTrafficRecordsJSON, filepath.Join(options.Workspace, "build", "rpcshield", "cached_prod_service_traffic_records.json"), recreateProductionTrafficRecords, logger)
	if err != nil {
		return rpcshield.Result{}, fmt.Errorf("fetch production service traffic: %w", err)
	}

	if options.GenAIBaseURL == "" {
		options.GenAIBaseURL = genai.BaseURL
	}
	if options.GenAIModel != "" {
		genai.Model = options.GenAIModel
	}
	if options.GenAIOrgID != "" {
		genai.OrgID = options.GenAIOrgID
	}
	if options.GenAIAPIUSSOToken == "" {
		if options.FetchUSSOToken == nil {
			return rpcshield.Result{}, errors.New("GenAIAPIUSSOToken not set and no FetchUSSOToken configured")
		}
		var err error
		options.GenAIAPIUSSOToken, err = options.FetchUSSOToken(strings.TrimSuffix(options.GenAIBaseURL, "/v1"), logger)
		if err != nil {
			return rpcshield.Result{}, fmt.Errorf("fetch GenAI API USSO token: %w", err)
		}
	}
	driverOpts := rpcshield.DriverOptions{
		SkipOBTierFilter:        options.SkipOBTierFilter,
		SkipProdTrafficFilter:   options.SkipProdTrafficFilter,
		Report:                  options.Report,
		Analyzers:               options.Analyzers,
		GitSHA:                  options.GitSHA,
		CSV:                     options.CSV,
		HTML:                    options.HTML,
		OutputDir:               options.OutputDir,
		Timestamp:               options.Timestamp,
		DisableSCCPAnalysis:     options.DisableSCCPAnalysis,
		NilOtherSourcesAfterSrc: options.NilOtherSourcesAfterSrc,
		RTAFlavor:               options.RTAFlavor,
		RTANumWorkers:           options.RTANumWorkers,
		DisableParallelCallTree: options.DisableParallelCallTree,
		CanonicalEdgeOrder:      options.CanonicalEdgeOrder,
		CGConstructionOnly:      options.CGConstructionOnly,
		RTABenchFlavors:         options.RTABenchFlavors,
		RTABenchNumWorkers:      options.RTABenchNumWorkers,
		CheckIsomorphism:        options.CheckIsomorphism,
		PermutationThreshold:    options.PermutationThreshold,
		ForceLoaderMode:         options.ForceLoaderMode,
		KeepIBPkgs:              keepIBPkgs,
		KeepGoPathAfterRun:      options.KeepGoPathAfterRun,
		BazelLoader:             options.BazelLoader,
		Config:                  cfg,
	}
	if options.Difftime {
		driverOpts.SGLinkRemoteHash = true
		driverOpts.ShortCallerName = true
		driverOpts.BaseSHA = options.BaseSHA
	}
	driver := rpcshield.NewDriver(options.Workspace, runner, gp, serviceMapper, genai.New(options.GenAIBaseURL, options.GenAIAPIUSSOToken), allServices, productionTrafficRecords, logger, driverOpts)

	result, err := driver.Run(ctx, options.Service)
	values := getStatsMetrics(result, options, err)
	logger.Infow("wpa_metrics", zap.Any("metrics", values))

	if options.ReportMetrics && options.ReportResult == nil {
		logger.Warnw("ReportMetrics is set but no ReportResult configured, skipping reporting")
	}
	if options.ReportMetrics && options.ReportResult != nil {
		logger.Infow("reporting result via LDA", "service", options.Service)
		// Add additional meta metrics of the run to the result metrics.
		values := map[string]string{
			"datestr":        options.Timestamp,
			"service":        options.Service,
			"buildkite_url":  os.Getenv("BUILDKITE_BUILD_URL"),
			"status":         string(result.Status),
			"csv_file_path":  result.CSVFilePath,
			"html_file_path": result.HTMLFilePath,
		}
		if err != nil {
			values["error"] = err.Error()
		}
		for _, metrics := range []map[string]float64{result.RunMetrics, result.GraphMetrics, result.FailnessMetrics} {
			for name, v := range metrics {
				// Format it as an integer and get rid of rounding errors.
				if math.Abs(v-math.Round(v)) < 1e-5 {
					values[name] = strconv.Itoa(int(v))
				} else {
					values[name] = strconv.FormatFloat(v, 'g', -1, 64)
				}
			}
		}

		if options.Difftime {
			// for diff time analysis, we only report the stats
			reportErr := options.ReportResult("rpcshield-diff-wpa-stats", values, logger)
			err = errors.Join(err, reportErr)
		} else {
			reportErr := options.ReportResult("rpcshield", values, logger)
			err = errors.Join(err, reportErr)
			// Report analyzer results via LDA.
			for _, m := range result.AnalyzerMetrics {
				reportErr = options.ReportResult("rpcshield-analyzers", m, logger)
				err = errors.Join(err, reportErr)
			}

			// Report inbound-outbound results via LDA.
			base := map[string]string{"run_timestamp": options.Timestamp, "analyzed_service": options.Service}
			for _, m := range result.Inbounds {
				ibValues := maps.Clone(base)
				ibValues["kind"] = "inbound"
				ibValues["canonical_name"] = m.CanonicalName
				ibValues["service_name"] = m.Service.Name
				ibValues["service_tier"] = strconv.Itoa(m.Service.Tier)
				ibValues["package_path"] = m.Pkg.PkgPath
				ibValues["function_name"] = m.Func.Name()
				ibValues["type"] = string(m.Type)
				reportErr := options.ReportResult("rpcshield-inbounds-outbounds", ibValues, logger)
				err = errors.Join(err, reportErr)
			}
			for _, m := range result.Outbounds {
				obValues := maps.Clone(base)
				obValues["kind"] = "outbound"
				obValues["canonical_name"] = m.CanonicalName
				obValues["service_name"] = m.Service.Name
				obValues["service_tier"] = strconv.Itoa(m.Service.Tier)
				obValues["has_overcommit"] = strconv.FormatBool(m.Service.HasOvercommit)
				obValues["break_before_make_burst_strategy"] = m.Service.BreakBeforeMakeBurstStrategy
				obValues["make_before_break_burst_strategy"] = m.Service.MakeBeforeBreakBurstStrategy
				obValues["package_path"] = m.Pkg.PkgPath
				funcName, formatErr := asthelper.FormatExpr(m.Call.Fun, m.Pkg.Fset)
				if formatErr != nil {
					funcName = fmt.Sprintf("<failed to format: %v>", formatErr)
				}
				obValues["function_name"] = funcName
				obValues["type"] = string(m.Type)
				reportErr := options.ReportResult("rpcshield-inbounds-outbounds", obValues, logger)
				err = errors.Join(err, reportErr)
			}
			for _, m := range result.ResolvedHTTPOutbounds {
				obValues := maps.Clone(base)
				obValues["kind"] = "http_outbound"
				obValues["canonical_name"] = m.CanonicalName
				obValues["service_name"] = m.Service.Name
				obValues["service_tier"] = strconv.Itoa(m.Service.Tier)
				obValues["package_path"] = m.Pkg.PkgPath
				reportErr := options.ReportResult("rpcshield-inbounds-outbounds-http", obValues, logger)
				err = errors.Join(err, reportErr)
			}
		}
	}

	return result, err
}

func getStatsMetrics(result rpcshield.Result, options Options, err error) map[string]string {
	values := map[string]string{
		"datestr":        options.Timestamp,
		"service":        options.Service,
		"buildkite_url":  os.Getenv("BUILDKITE_BUILD_URL"),
		"status":         string(result.Status),
		"csv_file_path":  result.CSVFilePath,
		"html_file_path": result.HTMLFilePath,
	}
	if err != nil {
		values["error"] = err.Error()
	}
	for _, metrics := range []map[string]float64{result.RunMetrics, result.GraphMetrics} {
		for name, v := range metrics {
			// Format it as an integer and get rid of rounding errors.
			if math.Abs(v-math.Round(v)) < 1e-5 {
				values[name] = strconv.Itoa(int(v))
			} else {
				values[name] = strconv.FormatFloat(v, 'g', -1, 64)
			}
		}
	}
	return values
}
