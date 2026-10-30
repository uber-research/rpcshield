// Command rpcshield is the thin OSS entrypoint wiring the wpa and json sub-commands. The Uber
// monorepo's fuller cmd/rpcshield/main.go additionally wires audit/idl-map/diff/shard/etc. modes
// and Uber-specific plugins (USSO token fetching, LDA metrics reporting, Bazel-query package
// loading) into wpamode.Options -- see that file for the fuller reference implementation.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/uber-research/rpcshield/go/cmd/rpcshield/common"
	"github.com/uber-research/rpcshield/go/cmd/rpcshield/jsonmode"
	"github.com/uber-research/rpcshield/go/cmd/rpcshield/wpamode"
	"github.com/uber-research/rpcshield/go/constant"
	"github.com/uber-research/rpcshield/go/genai"
	"go.uber.org/zap"
)

func parseAnalyzerOptions(analyzersStr string) map[constant.AnalyzerKind]bool {
	analyzers := make(map[constant.AnalyzerKind]bool)
	if analyzersStr == "all" {
		analyzers[constant.CacheAnalyzerKind] = true
		analyzers[constant.Predefined] = true
		analyzers[constant.SCCP] = true
		analyzers[constant.SSA] = true
		analyzers[constant.AST] = true
		analyzers[constant.LLM] = true
	} else {
		for _, analyzer := range strings.Split(analyzersStr, ",") {
			analyzers[constant.AnalyzerKind(strings.TrimSpace(analyzer))] = true
		}
	}
	return analyzers
}

func parseTierOverrides(s string) (map[string]int, error) {
	if s == "" {
		return nil, nil
	}
	overrides := make(map[string]int)
	for _, entry := range strings.Split(s, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid tier override entry %q: expected format service:tier", entry)
		}
		svcName := strings.TrimSpace(parts[0])
		tier, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return nil, fmt.Errorf("invalid tier value in %q: %w", entry, err)
		}
		overrides[svcName] = tier
	}
	return overrides, nil
}

func main() {
	help := "Usage: <json|wpa> [options]"

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, help)
		os.Exit(1)
	}

	switch mode := os.Args[1]; mode {
	case "json":
		opts := &jsonmode.Options{}
		jsonFlags := flag.NewFlagSet("json", flag.ExitOnError)
		jsonFlags.StringVar(&opts.Workspace, "workspace", os.Getenv("WORKSPACE_ROOT"), "source code location, default is $WORKSPACE_ROOT")
		jsonFlags.StringVar(&opts.InputFile, "input", "", "path of input json file")
		jsonFlags.StringVar(&opts.OutputDir, "outdir", "", "output directory (default is a temp folder)")
		jsonFlags.StringVar(&opts.UserName, "user", "", "user name")
		jsonFlags.StringVar(&opts.ConduitToken, "conduitToken", "", "conduitToken value")
		jsonFlags.BoolVar(&opts.Debug, "debug", false, "debug dump intermediate files")
		jsonFlags.BoolVar(&opts.NeedsProgramSlice, "pslice", false, "do the program slicing")
		jsonFlags.Var(&opts.LogLevel, "logmode", "the log level")
		jsonFlags.StringVar(&opts.Language, "language", "go", "language of the source code")
		jsonFlags.BoolVar(&opts.HTMLReport, "htmlReport", false, "generate html report")
		genaiBaseURL := jsonFlags.String("genai-base-url", genai.BaseURL, "the GenAI-compatible API base URL")
		genaiToken := jsonFlags.String("genai-token", os.Getenv("GENAI_TOKEN"), "the GenAI API token, default is $GENAI_TOKEN")

		if err := jsonFlags.Parse(os.Args[2:]); err != nil {
			fmt.Println("Usage of the program:")
			jsonFlags.PrintDefaults()
			return
		}

		aiclient := genai.New(*genaiBaseURL, *genaiToken)
		if err := jsonmode.Run(opts, aiclient); err != nil {
			log.Fatal(err)
		}
	case "wpa":
		wpaFlags := flag.NewFlagSet("wpa", flag.ExitOnError)
		service := wpaFlags.String("service", "", "name of the service to analyze")
		workspace := wpaFlags.String("workspace", os.Getenv("WORKSPACE_ROOT"), "source code location, default is $WORKSPACE_ROOT")
		report := wpaFlags.Bool("report", false, "determines whether to report rpcshield's findings")
		cpuProfile := wpaFlags.String("cpuprofile", "", "the path to write the CPU profile to, disabled if not specified")
		allocsProfile := wpaFlags.String("allocsprofile", "", "the path to write the allocs profile to, disabled if not specified")
		mutexProfile := wpaFlags.String("mutexprofile", "", "the path to write the mutex profile to, disabled if not specified")
		blockProfile := wpaFlags.String("blockprofile", "", "the path to write the block profile to, disabled if not specified")
		logLevel := zap.InfoLevel
		wpaFlags.Var(&logLevel, "loglevel", "log level (debug|info|warn|error)")
		noOBClipByTier := wpaFlags.Bool("no-ob-clip-by-tier", false, "disable ob-tier clipping, default is false")
		disableSCCPAnalysis := wpaFlags.Bool("disable-sccp-analysis", false, "disable SCCP (Sparse Conditional Constant Propagation) analysis, default is false")
		nilOtherSourcesAfterSrc := wpaFlags.Bool("nil-other-sources-after-src", false, "set OtherSources to Nil when they are after Src in the CFG, default is false")
		cachedGrailAllServicesJSON := wpaFlags.String("use-cached-grail-all-services-json", "auto", "the path to the cached Grail all services JSON file, `auto` or `refresh`")
		cachedFxMappingsJSON := wpaFlags.String("use-cached-fx-mappings-json", "auto", "the path to the cached Fx mapping JSON file, `auto` or `refresh`")
		cachedProdTrafficRecordsJSON := wpaFlags.String("use-cached-prod-traffic-records-json", "auto", "the path to the cached production service traffic records JSON file, `auto` or `refresh`")
		cachedKeepIBPkgsJSON := wpaFlags.String("use-cached-keep-ib-pkgs-json", "auto", "the path to the allowlist of packages to keep")
		analyzers := wpaFlags.String("analyzers", "SSA,AST", "comma-separated list of one or more analyzers (SSA, AST, LLM) to run for fail-ness detection or 'all' to run all analyzers")
		gitSHA := wpaFlags.String("git-sha", "", "the git SHA of the commit being analyzed")
		csv := wpaFlags.Bool("csv", true, "write the report to a CSV file")
		html := wpaFlags.Bool("html", true, "write the report to an HTML file")
		outputDir := wpaFlags.String("output-dir", os.TempDir(), "the directory to write the report to, default is the system temp directory")
		timestamp := wpaFlags.String("timestamp", time.Now().UTC().Format(time.RFC3339), "timestamp to be used in the report, default is the current time")
		fractionOfDRAM := wpaFlags.Float64("mem-fraction", 0.9, "fraction of DRAM to use as memory limit")
		grailUSSOToken := wpaFlags.String("grail-usso-token", os.Getenv("GRAIL_USSO_TOKEN"), "the Grail USSO token, defaults to $GRAIL_USSO_TOKEN")
		grailHost := wpaFlags.String("grail-host", "", "the Grail-compatible service registry host, required unless -service-registry-provider is supplied programmatically")
		grailRPCServiceName := wpaFlags.String("grail-rpc-service-name", "", "the value sent in the RPC-Service header on every Grail request, empty omits the header")
		genaiToken := wpaFlags.String("genai-token", os.Getenv("GENAI_TOKEN"), "the GenAI API token, default is $GENAI_TOKEN")
		genaiBaseURL := wpaFlags.String("genai-base-url", genai.BaseURL, "the GenAI-compatible API base URL")
		genaiModel := wpaFlags.String("genai-model", "", "the LLM model used for chat completion requests, defaults to genai.Model if empty")
		genaiOrgID := wpaFlags.String("genai-org-id", "", "the organization ID sent with chat completion requests, empty sends none")
		rtaFlavor := wpaFlags.String("rta-flavor", "prta_kumo_nonblocking", "RTA implementation flavor: srta, srta_opt, srta_kumo, srta_kumo_random, prta_naive, prta_nonblocking, prta_kumo, prta_kumo_nonblocking, stdlib, or cha")
		rtaNumWorkers := wpaFlags.String("rta-num-workers", strconv.Itoa(runtime.GOMAXPROCS(0)), "number of workers for parallel RTA flavors")
		disableParallelCallTree := wpaFlags.Bool("disable-parallel-calltree", false, "disable parallel call tree computation, default is false")
		canonicalEdgeOrder := wpaFlags.Bool("canonical-edge-order", false, "sort call-graph outgoing edges deterministically before path exploration so convergence pruning does not depend on package load order")
		permutationThreshold := wpaFlags.Int64("permutation-threshold", 100, "number of times the same function-set hash must be observed reaching a sink before permutation detection triggers (0 to disable)")
		tierOverridesRaw := wpaFlags.String("tier-overrides", os.Getenv("TIER_OVERRIDES"), "comma-separated list of service:tier overrides (e.g., svc1:0,svc2:1)")

		if err := wpaFlags.Parse(os.Args[2:]); err != nil || *service == "" || *workspace == "" {
			fmt.Println("Usage of the program:")
			wpaFlags.PrintDefaults()
			return
		}

		grailServiceCacheOption := common.CacheOption(*cachedGrailAllServicesJSON)
		if err := grailServiceCacheOption.CheckValid(); err != nil {
			log.Fatalf("invalid cache option for use-cached-grail-all-services-json: %v", err)
		}
		fxMappingsCacheOption := common.CacheOption(*cachedFxMappingsJSON)
		if err := fxMappingsCacheOption.CheckValid(); err != nil {
			log.Fatalf("invalid cache option for use-cached-fx-mappings-json: %v", err)
		}
		prodTrafficRecordsCacheOption := common.CacheOption(*cachedProdTrafficRecordsJSON)
		if err := prodTrafficRecordsCacheOption.CheckValid(); err != nil {
			log.Fatalf("invalid cache option for use-cached-prod-traffic-records-json: %v", err)
		}
		keepIBPkgsJSONOption := common.CacheOption(*cachedKeepIBPkgsJSON)
		if err := keepIBPkgsJSONOption.CheckValid(); err != nil {
			log.Fatalf("invalid cache option for use-cached-keep-ib-pkgs-json: %v", err)
		}

		tierOverrides, err := parseTierOverrides(*tierOverridesRaw)
		if err != nil {
			log.Fatalf("invalid tier overrides: %v", err)
		}

		analyzersMap := parseAnalyzerOptions(*analyzers)

		opts := wpamode.Options{
			Service:                      *service,
			Workspace:                    *workspace,
			LogLevel:                     logLevel,
			Report:                       *report,
			CachedGrailAllServicesJSON:   grailServiceCacheOption,
			CachedFxMappingsJSON:         fxMappingsCacheOption,
			CachedProdTrafficRecordsJSON: prodTrafficRecordsCacheOption,
			CachedKeepIBPkgsJSON:         keepIBPkgsJSONOption,
			CPUProfile:                   *cpuProfile,
			AllocsProfile:                *allocsProfile,
			MutexProfile:                 *mutexProfile,
			BlockProfile:                 *blockProfile,
			NoOBClipByTier:               *noOBClipByTier,
			GitSHA:                       *gitSHA,
			CSV:                          *csv,
			HTML:                         *html,
			OutputDir:                    *outputDir,
			Timestamp:                    *timestamp,
			FractionOfDRAM:               *fractionOfDRAM,
			GrailUSSOToken:               *grailUSSOToken,
			GrailHost:                    *grailHost,
			GrailRPCServiceName:          *grailRPCServiceName,
			GenAIAPIUSSOToken:            *genaiToken,
			GenAIBaseURL:                 *genaiBaseURL,
			GenAIModel:                   *genaiModel,
			GenAIOrgID:                   *genaiOrgID,
			DisableSCCPAnalysis:          *disableSCCPAnalysis,
			NilOtherSourcesAfterSrc:      *nilOtherSourcesAfterSrc,
			RTAFlavor:                    *rtaFlavor,
			RTANumWorkers:                *rtaNumWorkers,
			DisableParallelCallTree:      *disableParallelCallTree,
			CanonicalEdgeOrder:           *canonicalEdgeOrder,
			PermutationThreshold:         *permutationThreshold,
			TierOverrides:                tierOverrides,
			Analyzers:                    analyzersMap,
		}
		if _, err := wpamode.Run(opts); err != nil {
			log.Fatalf("Error running WPA: %v", err)
		}
	default:
		fmt.Fprintln(os.Stderr, help)
		os.Exit(1)
	}
}
