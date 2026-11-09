// Command oss_pipeline_bench runs rpcshield's real fail-close/fail-open analysis pipeline (not
// just RTA-benchmarking, see ../../rta/evaluation_scripts/cmd/oss_rta_bench) against a single
// open-source Go project, using Driver.RunOnPackages -- an entrypoint purpose-built for callers
// that have already loaded packages and want to skip Bazel-target discovery, GoPathWrapper, and
// the Grail service registry entirely (see driver.go's RunOnPackages doc comment).
//
// The binary is built once inside the monorepo and then invoked against cloned OSS source trees,
// exactly like oss_rta_bench. packages.Config.Dir directs go/packages' driver to the dataset's
// own go.mod, so the dataset's transitive deps resolve against its module graph rather than the
// monorepo's.
//
// Driver: ../run_oss_pipeline_sweep.sh loops over targets.csv.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	rpcshield "github.com/uber-research/rpcshield/go"
	"github.com/uber-research/rpcshield/go/common/utils"
	"github.com/uber-research/rpcshield/go/config"
	"github.com/uber-research/rpcshield/go/constant"
	"github.com/uber-research/rpcshield/go/finder/servicemapping"
	"github.com/uber-research/rpcshield/go/grail"
	rpcshieldgraph "github.com/uber-research/rpcshield/go/graph"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/tools/go/packages"
)

var stdout = log.New(os.Stdout, "", log.LstdFlags)

func Infof(format string, a ...any)  { stdout.Printf("INFO  "+format, a...) }
func Fatalf(format string, a ...any) { stdout.Printf("FATAL "+format, a...); os.Exit(1) }

// noopGoPathWrapper implements bazel.GoPathWrapper but is never actually invoked: RunOnPackages
// always sets Driver.opts.PackageSource, and driver.go's package-loading branch only falls
// through to GoPathWrapper.LiftGoPath when PackageSource is nil (see driver.go's target-loading
// branch, around the "else" after the BazelLoader check).
type noopGoPathWrapper struct{}

func (noopGoPathWrapper) LiftGoPath(utils.Runner, string) (string, []string, error) {
	panic("LiftGoPath not implemented for the OSS pipeline harness -- RunOnPackages should never reach this")
}

// ossServiceMapper is a minimal ServiceMapper for OSS repos, which have no real service registry
// to consult. InferService always returns a non-nil synthetic *grail.Service so that
// gogoprotoThriftOutbound/genericGRPCThriftOutbound's skip-on-nil path and cadenceOutbound's
// panic-on-nil path are both provably unreachable.
type ossServiceMapper struct{}

func (ossServiceMapper) InferService(t servicemapping.FullyQualifiedType) *grail.Service {
	name := t.PkgPath
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	return &grail.Service{Name: name}
}

func (ossServiceMapper) RankCachedServices([]*packages.Package) {}

// loadProgram loads targetPkg from datasetRoot/targetDir via go/packages, mirroring
// oss_rta_bench/main.go's loadProgram (see its comment for why cfg.Dir is load-bearing).
//
// If fixtureFile is non-empty, its contents are overlaid (via packages.Config.Overlay) as the
// sole file of a new virtual package at fixturePkgDir (relative to targetDir), and that virtual
// package -- not targetPkg -- becomes the load pattern. This lets a known-answer fixture (see
// ../fixtures/) reuse a real dataset's generated types/deps without writing to the checkout, and
// gives RTA a real main() root when the dataset itself has none reachable (see README's
// "Gotchas" section).
func loadProgram(datasetRoot, dir, pkg, fixtureFile, fixturePkgDir string) ([]*packages.Package, *packages.Package, error) {
	absRoot, err := filepath.Abs(datasetRoot)
	if err != nil {
		return nil, nil, fmt.Errorf("resolving dataset-root: %w", err)
	}
	loadDir := filepath.Join(absRoot, dir)
	if st, err := os.Stat(loadDir); err != nil || !st.IsDir() {
		return nil, nil, fmt.Errorf("target dir not a directory: %s", loadDir)
	}

	cfg := &packages.Config{
		Mode: packages.NeedName |
			packages.NeedFiles |
			packages.NeedCompiledGoFiles |
			packages.NeedImports |
			packages.NeedDeps |
			packages.NeedTypes |
			packages.NeedSyntax |
			packages.NeedTypesInfo |
			packages.NeedTypesSizes,
		Dir:   loadDir,
		Tests: false,
	}

	loadPattern := pkg
	if fixtureFile != "" {
		content, err := os.ReadFile(fixtureFile)
		if err != nil {
			return nil, nil, fmt.Errorf("reading fixture-file: %w", err)
		}
		virtualPath := filepath.Join(loadDir, fixturePkgDir, filepath.Base(fixtureFile))
		cfg.Overlay = map[string][]byte{virtualPath: content}
		loadPattern = "./" + fixturePkgDir
		Infof("Overlaying fixture %s at %s", fixtureFile, virtualPath)
	}

	Infof("Loading package %s from %s", loadPattern, loadDir)
	pkgs, err := packages.Load(cfg, loadPattern)
	if err != nil {
		return nil, nil, fmt.Errorf("packages.Load: %w", err)
	}
	pkgErrCount := 0
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		pkgErrCount += len(p.Errors)
	})
	Infof("Loaded %d top-level packages (%d package errors, non-fatal)", len(pkgs), pkgErrCount)

	var entryPkg *packages.Package
	var allPkgs []*packages.Package
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		allPkgs = append(allPkgs, p)
	})
	for _, p := range pkgs {
		if p.Name == "main" {
			entryPkg = p
			break
		}
	}
	if entryPkg == nil && len(pkgs) > 0 {
		entryPkg = pkgs[0]
	}
	if entryPkg == nil {
		return nil, nil, fmt.Errorf("no packages loaded for %s", loadPattern)
	}
	return allPkgs, entryPkg, nil
}

// mustLogger returns a real (not no-op) zap logger for the harness -- unlike the production CLI,
// the harness's whole purpose is diagnosing what the pipeline did/didn't find on OSS code, so its
// driver logs should always be visible. Defaults to Info: the SSA/SCCP analyzer (graph/constprop.go)
// emits a Debug line per instruction visited, which is impractical on anything beyond small
// fixtures -- e.g. it produced tens of millions of lines analyzing etcd's full server binary,
// enough to make the process look hung. Pass -debug for Debug-level output on small targets.
func mustLogger(debug bool) *zap.SugaredLogger {
	cfg := zap.NewProductionConfig()
	cfg.Encoding = "console"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	if debug {
		cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	}
	l, err := cfg.Build()
	if err != nil {
		Fatalf("building logger: %v", err)
	}
	return l.Sugar()
}

func main() {
	var (
		datasetRoot         = flag.String("dataset-root", "", "absolute path to the directory containing cloned OSS repos")
		targetName          = flag.String("target-name", "", "label for this target (used in log messages and default service name)")
		targetDir           = flag.String("target-dir", "", "subdir of -dataset-root containing the project's go.mod")
		targetPkg           = flag.String("target-pkg", ".", "package path relative to target-dir to analyze (e.g., ./cmd/foo)")
		serviceName         = flag.String("service-name", "", "grail.Service.Name to use; defaults to -target-name")
		outputDir           = flag.String("output-dir", "", "directory to write CSV/HTML reports to")
		csvOut              = flag.Bool("csv", true, "write a CSV report")
		htmlOut             = flag.Bool("html", true, "write an HTML report")
		fixtureFile         = flag.String("fixture-file", "", "path to a known-answer fixture .go file to overlay (see ../fixtures/); when set, this replaces -target-pkg as the load pattern")
		fixturePkgDir       = flag.String("fixture-pkg-dir", "oss_pipeline_bench_fixture", "virtual directory (relative to target-dir) the fixture file is overlaid at")
		detectOnly          = flag.Bool("detect-only", false, "stop after inbound/outbound detection (no call graph, path exploration or analyzers); writes <service>_result.json with Inbounds/Outbounds only")
		registrationIBs     = flag.Bool("registration-inbounds", true, "also find RPC handlers from the calls that register them with a server (see config.Config.DisableRegistrationInboundDetection); -registration-inbounds=false leaves only the other inbound rules")
		debug               = flag.Bool("debug", false, "enable Debug-level driver logging (very verbose -- the SSA/SCCP analyzer logs per-instruction; only practical on small fixtures)")
		codebasePrefix      = flag.String("codebase-pkg-prefix", "", "import-path prefix of the target's own code, required to scope outbound-call scanning to the service under test; without it, finder.Outbound's f.codebasePkgPrefix check (an empty-string prefix matches everything) scans every transitive dependency's own internals too, e.g. matching grpc-go's own ClientConn-holding structs as false-positive outbound clients")
		dropExcludePatterns = flag.String("drop-exclude-package-patterns", "", "comma-separated exact entries to remove from graph.DefaultExcludePackagePatterns before analyzing this target (see config.Config.ExcludePackagePatterns). Needed when the target's own module path matches one of those default entries -- e.g. analyzing jaegertracing/jaeger itself requires dropping \"^github.com/jaegertracing(/.*)?$\", since that pattern assumes jaegertracing/jaeger is always a *dependency*, never the analyzed target, and otherwise the target's entire codebase is silently excluded from the call graph before analysis starts")
	)
	flag.Parse()

	if *datasetRoot == "" || *targetName == "" || *targetDir == "" || *outputDir == "" || *codebasePrefix == "" {
		Fatalf("dataset-root, target-name, target-dir, codebase-pkg-prefix, and output-dir are required")
	}
	svcName := *serviceName
	if svcName == "" {
		svcName = *targetName
	}
	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		Fatalf("creating output-dir: %v", err)
	}

	Infof("target=%s dir=%s pkg=%s service=%s", *targetName, *targetDir, *targetPkg, svcName)

	allPkgs, entryPkg, err := loadProgram(*datasetRoot, *targetDir, *targetPkg, *fixtureFile, *fixturePkgDir)
	if err != nil {
		Fatalf("loading program: %v", err)
	}

	// findPackageFromTarget (driver.go) only strips a literal "//src/" prefix -- this exact
	// shape is load-bearing, see driver.go's findPackageFromTarget.
	target := "//src/" + entryPkg.PkgPath + ":oss"

	cfg := config.Config{EnableGenericGRPCThriftDetection: true, DisableRegistrationInboundDetection: !*registrationIBs, CodebasePkgPrefix: *codebasePrefix}
	if *dropExcludePatterns != "" {
		drop := make(map[string]bool)
		for _, p := range strings.Split(*dropExcludePatterns, ",") {
			drop[strings.TrimSpace(p)] = true
		}
		var kept []string
		for _, p := range rpcshieldgraph.DefaultExcludePackagePatterns {
			if !drop[p] {
				kept = append(kept, p)
			}
		}
		cfg.ExcludePackagePatterns = kept
	}
	// Matches the monorepo's own `-analyzers all` default (cmd/rpcshield/main.go's
	// parseAnalyzerOptions), minus constant.LLM: LLM requires a GenAI backend that this harness has
	// no client for (aiClient is passed as nil to NewDriver below), so it's deliberately excluded
	// rather than silently no-op'd. Every other
	// analyzer (CacheAnalyzerKind, Predefined, SCCP, SSA, AST) is plain SSA/AST logic with no
	// monorepo-internal dependency, so all are safe and expected to run here, same as production.
	opts := rpcshield.DriverOptions{
		Analyzers: map[constant.AnalyzerKind]bool{
			constant.CacheAnalyzerKind: true,
			constant.Predefined:        true,
			constant.SCCP:              true,
			constant.SSA:               true,
			constant.AST:               true,
		},
		GitSHA:     "oss",
		CSV:        *csvOut,
		HTML:       *htmlOut,
		OutputDir:  *outputDir,
		Timestamp:  time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		RTAFlavor:  "srta",
		Config:     cfg,
		DetectOnly: *detectOnly,
	}

	svc := grail.Service{Name: svcName, Tier: -1}
	driver := rpcshield.NewDriver(
		filepath.Join(*datasetRoot, *targetDir),
		utils.OSRunner{},
		noopGoPathWrapper{},
		ossServiceMapper{},
		nil, /* aiClient: LLM analyzer not enabled */
		[]grail.Service{svc},
		nil, /* prodServiceTrafficRecords */
		mustLogger(*debug),
		opts,
	)

	result, err := driver.RunOnPackages(context.Background(), svc, []string{target}, allPkgs)
	if err != nil {
		Fatalf("RunOnPackages: %v", err)
	}

	metrics := map[string]any{
		"status":          string(result.Status),
		"num_inbounds":    len(result.Inbounds),
		"num_outbounds":   len(result.Outbounds),
		"num_reports":     len(result.Reports),
		"failness_counts": result.FailnessMetrics,
	}
	payload, _ := json.Marshal(metrics)
	stdout.Printf("INFO  oss_pipeline_metrics\t%s", payload)

	if len(result.Inbounds) == 0 {
		Infof("WARNING: zero inbounds detected -- check target-pkg and EnableGenericGRPCThriftDetection")
	}
	if len(result.Outbounds) == 0 {
		Infof("WARNING: zero outbounds detected -- check target-pkg and EnableGenericGRPCThriftDetection")
	}

	if result.Status == rpcshield.Error {
		Fatalf("run did not succeed: status=%s error=%s", result.Status, result.ErrorMsg)
	}

	Infof("Finished OSS pipeline evaluation")
}
