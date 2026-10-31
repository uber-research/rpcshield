package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/uber-research/rpcshield/go/common/utils"
	"github.com/uber-research/rpcshield/go/rta"
	"github.com/uber-research/rpcshield/go/rta/prta_kumo"
	"github.com/uber-research/rpcshield/go/rta/prta_kumo_nonblocking"
	"github.com/uber-research/rpcshield/go/rta/prta_naive"
	"github.com/uber-research/rpcshield/go/rta/prta_nonblocking"
	"github.com/uber-research/rpcshield/go/rta/srta"
	"github.com/uber-research/rpcshield/go/rta/srta_kumo"
	"github.com/uber-research/rpcshield/go/rta/srta_opt"
	"github.com/uber-research/rpcshield/go/rta/srta_struct"
	"github.com/uber-research/rpcshield/go/rta/vta"
	vtacore "github.com/uber-research/rpcshield/go/vta"
	"go.uber.org/zap"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	rtapkg "golang.org/x/tools/go/callgraph/rta"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// DefaultSerialGraphConfig returns a Config for serial (stdlib) RTA.
func DefaultSerialGraphConfig() Config {
	return Config{
		RTAFlavor:     FlavorStdlib,
		RTANumWorkers: 1,
	}
}

// DefaultParallelGraphConfig returns a Config for parallel RTA (prta_kumo_nonblocking with GOMAXPROCS workers).
func DefaultParallelGraphConfig() Config {
	return Config{
		RTAFlavor:     FlavorPRTAKumoNonblocking,
		RTANumWorkers: runtime.GOMAXPROCS(0),
	}
}

// RTAFlavor represents a call graph construction algorithm variant.
type RTAFlavor int

const (
	// FlavorSRTA is the serial RTA implementation.
	FlavorSRTA RTAFlavor = iota
	// FlavorSRTAOpt is the serial RTA with a memoized method-value lookup
	// (utils.LookupMethodSeq + MethodValueFast). Same algorithm as FlavorSRTA.
	FlavorSRTAOpt
	// FlavorSRTAStruct is the serial RTA baseline ([srta]) with one targeted
	// change: presence-only sets that were `map[K]bool` are now `map[K]struct{}`.
	// Isolates the contribution of the value-type shrink from the other srta_opt
	// optimizations.
	FlavorSRTAStruct
	// FlavorSRTAKumo is the serial RTA with Kumo optimizations.
	FlavorSRTAKumo
	// FlavorSRTAKumoRandom is the serial RTA with Kumo optimizations and random method selection.
	FlavorSRTAKumoRandom
	// FlavorPRTANaive is the naive parallel RTA implementation.
	FlavorPRTANaive
	// FlavorPRTANonblocking is the parallel RTA with non-blocking synchronization.
	FlavorPRTANonblocking
	// FlavorPRTAKumo is the parallel RTA with Kumo optimizations.
	FlavorPRTAKumo
	// FlavorPRTAKumoNonblocking is the parallel RTA with Kumo optimizations and non-blocking synchronization.
	FlavorPRTAKumoNonblocking
	// FlavorStdlib is the standard library RTA implementation from golang.org/x/tools.
	FlavorStdlib
	// FlavorCHA is the Class Hierarchy Analysis implementation.
	FlavorCHA
	// FlavorVTA is Variable Type Analysis, seeded by prta_kumo_nonblocking.
	// Unlike the RTA flavors it is flow-based, so it resolves an interface
	// call only to implementations that reach that receiver.
	FlavorVTA
	// FlavorVTAStrict is FlavorVTA with the seed fallback disabled. It may
	// have false negatives where reflection is involved and exists to
	// measure how much of VTA's edge reduction is genuine precision rather
	// than the soundness fallback. Not for production use.
	FlavorVTAStrict
)

// AllFlavors contains all known RTA flavors.
var AllFlavors = []RTAFlavor{
	FlavorSRTA,
	FlavorSRTAOpt,
	FlavorSRTAStruct,
	FlavorSRTAKumo,
	FlavorSRTAKumoRandom,
	FlavorPRTANaive,
	FlavorPRTANonblocking,
	FlavorPRTAKumo,
	FlavorPRTAKumoNonblocking,
	FlavorStdlib,
	FlavorCHA,
	FlavorVTA,
	FlavorVTAStrict,
}

var flavorNames = [...]string{
	FlavorSRTA:                "srta",
	FlavorSRTAOpt:             "srta_opt",
	FlavorSRTAStruct:          "srta_struct",
	FlavorSRTAKumo:            "srta_kumo",
	FlavorSRTAKumoRandom:      "srta_kumo_random",
	FlavorPRTANaive:           "prta_naive",
	FlavorPRTANonblocking:     "prta_nonblocking",
	FlavorPRTAKumo:            "prta_kumo",
	FlavorPRTAKumoNonblocking: "prta_kumo_nonblocking",
	FlavorStdlib:              "stdlib",
	FlavorCHA:                 "cha",
	FlavorVTA:                 "vta",
	FlavorVTAStrict:           "vta_strict",
}

var flavorByName map[string]RTAFlavor

func init() {
	flavorByName = make(map[string]RTAFlavor, len(flavorNames))
	for i, name := range flavorNames {
		flavorByName[name] = RTAFlavor(i)
	}
}

// String returns the string representation of the flavor.
func (f RTAFlavor) String() string {
	if int(f) < len(flavorNames) {
		return flavorNames[f]
	}
	return fmt.Sprintf("unknown(%d)", int(f))
}

// isFlowBased reports whether the flavor resolves a call site from the values
// that actually reach it, rather than from a global pool of instantiated
// types. Flow-based flavors resolve an injected interface to the single
// implementation the container supplied — usually a wrapper — where the
// type-based ones additionally report a direct edge to everything else that
// implements the interface. Pruning has to account for the difference (see
// spliceDelegators).
func (f RTAFlavor) isFlowBased() bool {
	return f == FlavorVTA || f == FlavorVTAStrict
}

// ParseRTAFlavor parses a single flavor string into an RTAFlavor.
func ParseRTAFlavor(s string) (RTAFlavor, error) {
	s = strings.TrimSpace(s)
	if f, ok := flavorByName[s]; ok {
		return f, nil
	}
	names := make([]string, len(flavorNames))
	copy(names, flavorNames[:])
	return 0, fmt.Errorf("invalid RTA flavor %q, valid flavors: %v", s, names)
}

// IsSequential returns true if this flavor uses a single worker.
func (f RTAFlavor) IsSequential() bool {
	switch f {
	case FlavorSRTA, FlavorSRTAOpt, FlavorSRTAStruct, FlavorSRTAKumo, FlavorSRTAKumoRandom, FlavorStdlib, FlavorCHA:
		return true
	default:
		return false
	}
}

// NewImpl creates the RTA implementation and any extra analyze options for the flavor.
// Returns (nil, nil) for FlavorStdlib and FlavorCHA which are handled separately.
func (f RTAFlavor) NewImpl() (rta.RTA, []rta.AnalyzeOption) {
	switch f {
	case FlavorSRTA:
		return srta.New(), nil
	case FlavorSRTAOpt:
		return srta_opt.New(), nil
	case FlavorSRTAStruct:
		return srta_struct.New(), nil
	case FlavorSRTAKumo:
		return srta_kumo.New(), nil
	case FlavorSRTAKumoRandom:
		return srta_kumo.New(), []rta.AnalyzeOption{rta.WithMethodSelectionStrategy(rta.RandomMethodStrategy)}
	case FlavorPRTANaive:
		return prta_naive.New(), nil
	case FlavorPRTANonblocking:
		return prta_nonblocking.New(), nil
	case FlavorPRTAKumo:
		return prta_kumo.New(), nil
	case FlavorPRTAKumoNonblocking:
		return prta_kumo_nonblocking.New(), nil
	case FlavorVTA:
		return vta.New(), nil
	case FlavorVTAStrict:
		return vta.New(vtacore.WithStrict()), nil
	default:
		return nil, nil
	}
}

// ParseRTAFlavors parses a comma-separated RTA flavors string into a slice of RTAFlavor.
// Supports "all" for all available flavors. Returns all flavors if input is empty.
func ParseRTAFlavors(flavorsStr string) ([]RTAFlavor, error) {
	flavorsStr = strings.TrimSpace(flavorsStr)
	if flavorsStr == "" || flavorsStr == "all" {
		result := make([]RTAFlavor, len(AllFlavors))
		copy(result, AllFlavors)
		return result, nil
	}

	parts := strings.Split(flavorsStr, ",")
	flavors := make([]RTAFlavor, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		f, err := ParseRTAFlavor(part)
		if err != nil {
			return nil, err
		}
		flavors = append(flavors, f)
	}

	if len(flavors) == 0 {
		result := make([]RTAFlavor, len(AllFlavors))
		copy(result, AllFlavors)
		return result, nil
	}

	return flavors, nil
}

// ParseRTANumWorkers parses a comma-separated worker counts string into a slice of ints.
// Default is []int{64} if empty.
func ParseRTANumWorkers(numWorkersStr string) ([]int, error) {
	defaultWorkers := []int{64}

	numWorkersStr = strings.TrimSpace(numWorkersStr)
	if numWorkersStr == "" {
		return defaultWorkers, nil
	}

	parts := strings.Split(numWorkersStr, ",")
	workers := make([]int, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		num, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid worker count %q: %w", part, err)
		}
		if num <= 0 {
			return nil, fmt.Errorf("worker count must be positive, got %d", num)
		}
		workers = append(workers, num)
	}

	if len(workers) == 0 {
		return defaultWorkers, nil
	}

	return workers, nil
}

// getRTAEntryFunctions collects the entry point functions (main + init) for RTA analysis,
// plus any inbound SSA functions.
func (b *builderImpl) getRTAEntryFunctions() ([]*ssa.Function, error) {
	entry := []*ssa.Function{}
	for f, ok := range ssautil.AllFunctions(b.ssaProg) {
		if !ok || (f.Signature != nil && f.Signature.Recv() != nil) {
			continue
		}
		if f.Name() == "main" || f.Name() == "init" {
			entry = append(entry, f)
		}
	}
	if len(entry) == 0 {
		b.logger.Warn("main function not found in SSA packages")
		return nil, errors.New("main function not found in SSA packages")
	}
	for _, ib := range b.inboundsSSA {
		entry = append(entry, ib.function)
	}
	return entry, nil
}

// runSingleFlavor runs a single RTA flavor with a given worker count and collects all metrics.
// It returns the resulting callgraph.
func (b *builderImpl) runSingleFlavor(entry []*ssa.Function, flavor RTAFlavor, numWorkers int) (*callgraph.Graph, error) {
	// Get baseline memory before this run
	runtime.GC()
	var memStatsBefore runtime.MemStats
	runtime.ReadMemStats(&memStatsBefore)
	baselineHeapInuse := memStatsBefore.HeapInuse

	// Track peak memory in a goroutine
	var peakHeapInuse atomic.Uint64
	peakHeapInuse.Store(baselineHeapInuse)
	stopMemTracker := make(chan struct{})
	memTrackerDone := make(chan struct{})
	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "memory tracker panicked: %v\n", r)
			}
		}()
		defer close(memTrackerDone)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopMemTracker:
				return
			case <-ticker.C:
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				for {
					old := peakHeapInuse.Load()
					if m.HeapInuse <= old {
						break
					}
					if peakHeapInuse.CompareAndSwap(old, m.HeapInuse) {
						break
					}
				}
			}
		}
	}()

	var rusageBefore syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &rusageBefore)

	start := time.Now()
	flavorStr := flavor.String()
	b.logger.Infof("Running RTA flavor: %s with %d workers", flavorStr, numWorkers)

	var cgResult *callgraph.Graph

	// Run stdlib/cha directly; use NewImpl for custom flavors
	switch flavor {
	case FlavorStdlib:
		res := rtapkg.Analyze(entry, true)
		if res != nil {
			cgResult = res.CallGraph
		}
	case FlavorCHA:
		cgResult = cha.CallGraph(b.ssaProg)
	default:
		rtaImpl, rtaOpts := flavor.NewImpl()
		if rtaImpl == nil {
			close(stopMemTracker)
			<-memTrackerDone
			return nil, fmt.Errorf("unknown RTA flavor: %s", flavorStr)
		}
		opts := append([]rta.AnalyzeOption{rta.WithNumWorkers(numWorkers)}, rtaOpts...)
		res := rtaImpl.Analyze(entry, true, opts...)
		if res != nil {
			cgResult = res.GetCallGraph()
			b.collectRTAMetrics(res, flavorStr, numWorkers)
		}
	}

	// Stop all measurements immediately after analysis completes.
	duration := time.Since(start)

	var rusageAfter syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &rusageAfter)
	cpuTimeMs := float64(
		(rusageAfter.Utime.Sec-rusageBefore.Utime.Sec)*1000 +
			int64(rusageAfter.Utime.Usec-rusageBefore.Utime.Usec)/1000 +
			(rusageAfter.Stime.Sec-rusageBefore.Stime.Sec)*1000 +
			int64(rusageAfter.Stime.Usec-rusageBefore.Stime.Usec)/1000,
	)

	// Stop memory tracker and get final reading
	close(stopMemTracker)
	<-memTrackerDone
	var memStatsAfter runtime.MemStats
	runtime.ReadMemStats(&memStatsAfter)
	finalHeap := memStatsAfter.HeapInuse
	for {
		old := peakHeapInuse.Load()
		if finalHeap <= old {
			break
		}
		if peakHeapInuse.CompareAndSwap(old, finalHeap) {
			break
		}
	}

	peakDelta := int64(peakHeapInuse.Load()) - int64(baselineHeapInuse)
	if peakDelta < 0 {
		peakDelta = 0
	}
	peakDeltaMB := float64(peakDelta) / (1024 * 1024)

	// Cumulative allocations during this flavor's run (excludes other
	// flavors and the loader): runtime.MemStats accumulates TotalAlloc
	// and Mallocs for the lifetime of the process, so delta isolates
	// this run. These reveal whether transient garbage is what's
	// inflating peak vs the data structures the run leaves behind.
	allocBytesDelta := memStatsAfter.TotalAlloc - memStatsBefore.TotalAlloc
	allocObjectsDelta := memStatsAfter.Mallocs - memStatsBefore.Mallocs
	allocBytesMB := float64(allocBytesDelta) / (1024 * 1024)

	// Record timing/memory metrics
	b.metrics[fmt.Sprintf("rta_duration_secs_%s_%d_workers", flavorStr, numWorkers)] = duration.Seconds()
	b.metrics[fmt.Sprintf("rta_cpu_time_ms_%s_%d_workers", flavorStr, numWorkers)] = cpuTimeMs
	b.metrics[fmt.Sprintf("rta_peak_heap_delta_mb_%s_%d_workers", flavorStr, numWorkers)] = peakDeltaMB
	b.metrics[fmt.Sprintf("rta_alloc_bytes_total_mb_%s_%d_workers", flavorStr, numWorkers)] = allocBytesMB
	b.metrics[fmt.Sprintf("rta_alloc_objects_total_%s_%d_workers", flavorStr, numWorkers)] = float64(allocObjectsDelta)

	b.logger.Infof("RTA %s with %d workers took %v, cpu time: %.0f ms, peak heap delta: %.2f MB, total allocated: %.2f MB / %d objects",
		flavorStr, numWorkers, duration, cpuTimeMs, peakDeltaMB, allocBytesMB, allocObjectsDelta)

	// Callgraph-level metrics (not timed — computed after measurements stop)
	if cgResult != nil {
		b.metrics[fmt.Sprintf("rta_callgraph_nodes_%s_%d_workers", flavorStr, numWorkers)] = float64(len(cgResult.Nodes))
		edgeCount := 0
		for _, node := range cgResult.Nodes {
			edgeCount += len(node.Out)
		}
		b.metrics[fmt.Sprintf("rta_callgraph_edges_%s_%d_workers", flavorStr, numWorkers)] = float64(edgeCount)
	}

	return cgResult, nil
}

// collectRTAMetrics extracts all available metrics from an RTA result.
func (b *builderImpl) collectRTAMetrics(res rta.Result, flavorStr string, numWorkers int) {
	if ic, ok := res.(rta.ImplementsCounter); ok {
		b.metrics[fmt.Sprintf("rta_implements_calls_%s_%d_workers", flavorStr, numWorkers)] = float64(ic.ImplementsCallCount())
	}

	if tc, ok := res.(rta.TypeCounter); ok {
		b.metrics[fmt.Sprintf("rta_concrete_types_%s_%d_workers", flavorStr, numWorkers)] = float64(tc.NumConcreteTypes())
		b.metrics[fmt.Sprintf("rta_interface_types_%s_%d_workers", flavorStr, numWorkers)] = float64(tc.NumInterfaceTypes())
	}

	if sf, ok := res.(rta.ImplementsSuccessFailCounter); ok {
		b.metrics[fmt.Sprintf("rta_implements_success_%s_%d_workers", flavorStr, numWorkers)] = float64(sf.ImplementsSuccessCount())
		b.metrics[fmt.Sprintf("rta_implements_fail_%s_%d_workers", flavorStr, numWorkers)] = float64(sf.ImplementsFailCount())
	}

	if sc, ok := res.(rta.ImplementsSourceCounter); ok {
		b.metrics[fmt.Sprintf("rta_checks_from_interfaces_%s_%d_workers", flavorStr, numWorkers)] = float64(sc.ChecksFromInterfaces())
		b.metrics[fmt.Sprintf("rta_checks_from_implementations_%s_%d_workers", flavorStr, numWorkers)] = float64(sc.ChecksFromImplementations())
	}

	if ie, ok := res.(rta.InvokeLookupCounter); ok {
		b.metrics[fmt.Sprintf("rta_invoke_lookups_from_visit_invoke_%s_%d_workers", flavorStr, numWorkers)] = float64(ie.InvokeLookupsFromVisitInvoke())
		b.metrics[fmt.Sprintf("rta_invoke_lookups_from_add_runtime_type_%s_%d_workers", flavorStr, numWorkers)] = float64(ie.InvokeLookupsFromAddRuntimeType())
	}

	if dc, ok := res.(rta.ImplementsDirectionCounter); ok {
		b.metrics[fmt.Sprintf("rta_fails_from_interfaces_%s_%d_workers", flavorStr, numWorkers)] = float64(dc.FailsFromInterfaces())
		b.metrics[fmt.Sprintf("rta_success_from_interfaces_%s_%d_workers", flavorStr, numWorkers)] = float64(dc.SuccessFromInterfaces())
		b.metrics[fmt.Sprintf("rta_fails_from_implementations_%s_%d_workers", flavorStr, numWorkers)] = float64(dc.FailsFromImplementations())
		b.metrics[fmt.Sprintf("rta_success_from_implementations_%s_%d_workers", flavorStr, numWorkers)] = float64(dc.SuccessFromImplementations())
	}

	if cs, ok := res.(rta.CallSiteCounter); ok {
		b.metrics[fmt.Sprintf("rta_static_call_sites_%s_%d_workers", flavorStr, numWorkers)] = float64(cs.StaticCallSites())
		b.metrics[fmt.Sprintf("rta_indirect_call_sites_%s_%d_workers", flavorStr, numWorkers)] = float64(cs.IndirectCallSites())
		b.metrics[fmt.Sprintf("rta_invoke_call_sites_%s_%d_workers", flavorStr, numWorkers)] = float64(cs.InvokeCallSites())
		b.metrics[fmt.Sprintf("rta_total_call_sites_%s_%d_workers", flavorStr, numWorkers)] = float64(cs.TotalCallSites())
	}

	if dt, ok := res.(rta.DedupTiming); ok {
		b.metrics[fmt.Sprintf("rta_pre_dedup_duration_ms_%s_%d_workers", flavorStr, numWorkers)] = dt.PreDedupDurationMs()
		b.metrics[fmt.Sprintf("rta_post_dedup_duration_ms_%s_%d_workers", flavorStr, numWorkers)] = dt.PostDedupDurationMs()
		b.metrics[fmt.Sprintf("rta_pre_dedup_heap_delta_mb_%s_%d_workers", flavorStr, numWorkers)] = dt.PreDedupHeapDeltaMB()
		b.metrics[fmt.Sprintf("rta_post_dedup_heap_delta_mb_%s_%d_workers", flavorStr, numWorkers)] = dt.PostDedupHeapDeltaMB()
		b.metrics[fmt.Sprintf("rta_duplicated_edges_%s_%d_workers", flavorStr, numWorkers)] = float64(dt.DuplicatedEdgeCount())
	}

	if is, ok := res.(rta.IndexStats); ok {
		mc := is.MCBucketSizePercentiles()
		mi := is.MIBucketSizePercentiles()
		for _, p := range []struct {
			name string
			val  int
		}{
			{"p50", mc.P50}, {"p90", mc.P90}, {"p95", mc.P95}, {"p99", mc.P99}, {"p100", mc.P100},
		} {
			b.metrics[fmt.Sprintf("rta_mc_bucket_%s_%s_%d_workers", p.name, flavorStr, numWorkers)] = float64(p.val)
		}
		for _, p := range []struct {
			name string
			val  int
		}{
			{"p50", mi.P50}, {"p90", mi.P90}, {"p95", mi.P95}, {"p99", mi.P99}, {"p100", mi.P100},
		} {
			b.metrics[fmt.Sprintf("rta_mi_bucket_%s_%s_%d_workers", p.name, flavorStr, numWorkers)] = float64(p.val)
		}
		bucketLabels := [8]string{"1", "2", "4", "8", "16", "32", "64", "gt64"}
		buckets := is.InterfaceMethodCountBuckets()
		for i, label := range bucketLabels {
			b.metrics[fmt.Sprintf("rta_frac_iface_methods_le%s_%s_%d_workers", label, flavorStr, numWorkers)] = buckets[i]
		}
	}

	if ms, ok := res.(rta.MethodStats); ok {
		mpc := ms.MethodsPerConcretePercentiles()
		mpi := ms.MethodsPerInterfacePercentiles()
		for _, p := range []struct {
			name       string
			cval, ival int
		}{
			{"p50", mpc.P50, mpi.P50}, {"p95", mpc.P95, mpi.P95}, {"p99", mpc.P99, mpi.P99}, {"p100", mpc.P100, mpi.P100},
		} {
			b.metrics[fmt.Sprintf("rta_methods_per_concrete_%s_%s_%d_workers", p.name, flavorStr, numWorkers)] = float64(p.cval)
			b.metrics[fmt.Sprintf("rta_methods_per_interface_%s_%s_%d_workers", p.name, flavorStr, numWorkers)] = float64(p.ival)
		}
		concBucketLabels := [8]string{"1", "2", "4", "8", "16", "32", "64", "gt64"}
		concBuckets := ms.ConcreteMethodCountBuckets()
		for i, label := range concBucketLabels {
			b.metrics[fmt.Sprintf("rta_frac_concrete_methods_le%s_%s_%d_workers", label, flavorStr, numWorkers)] = concBuckets[i]
		}
	}
}

// computeNeighborHash computes a per-node neighbor fingerprint for graph equivalence checking.
func (b *builderImpl) computeNeighborHash(cgResult *callgraph.Graph, flavorStr string, numWorkers int) {
	var graphXOR [32]byte
	for fn, node := range cgResult.Nodes {
		if fn == nil {
			continue
		}
		callees := make([]string, 0, len(node.Out))
		for _, edge := range node.Out {
			if edge.Callee != nil && edge.Callee.Func != nil {
				callees = append(callees, edge.Callee.Func.String())
			}
		}
		sort.Strings(callees)
		h := sha256.New()
		h.Write([]byte(fn.String()))
		for _, c := range callees {
			h.Write([]byte(c))
		}
		nodeHash := h.Sum(nil)
		for i := range graphXOR {
			graphXOR[i] ^= nodeHash[i]
		}
	}
	b.metrics[fmt.Sprintf("rta_callgraph_neighbor_hash_%s_%d_workers", flavorStr, numWorkers)] = 0 // placeholder for JSON
	b.logger.Infof("RTA %s neighbor_hash=%s", flavorStr, hex.EncodeToString(graphXOR[:]))
}

// ensureStdlibFirst returns a copy of flavors with FlavorStdlib as the first element.
// If FlavorStdlib is already present, it is moved to the front.
// If not present, it is prepended.
func ensureStdlibFirst(flavors []RTAFlavor) []RTAFlavor {
	result := make([]RTAFlavor, 0, len(flavors)+1)
	result = append(result, FlavorStdlib)
	for _, f := range flavors {
		if f != FlavorStdlib {
			result = append(result, f)
		}
	}
	return result
}

// buildCGOnlySweep implements the BuildCGOnly logic: sweeps across all configured
// flavors and worker counts, collecting metrics. This is only used for benchmarking.
func (b *builderImpl) buildCGOnlySweep() (map[string]float64, error) {
	runtime.GC()
	defer runtime.GC()

	b.computeCodebaseMetrics()

	b.logger.Infof("Setting SSA inbounds and outbounds")
	if err := b.setSSAInOutBounds(); err != nil {
		b.logger.Errorf("Error setting SSA inbounds and outbounds")
		return nil, err
	}
	b.metrics[_inboundNeeded] = float64(len(b.inbounds))
	b.metrics[_inboundFound] = float64(len(b.inboundsSSA))
	b.metrics[_outboundNeeded] = float64(len(b.outbounds))
	b.metrics[_outboundFound] = float64(len(b.outboundsSSA))

	b.logger.Infow("Inbounds and ssaInbounds", "num_inbounds", len(b.inbounds), "num_ssaInbounds", len(b.inboundsSSA))
	b.logger.Infow("Outbounds and ssaOutbounds", "num_outbounds", len(b.outbounds), "num_ssaOutbounds", len(b.outboundsSSA))

	entry, err := b.getRTAEntryFunctions()
	if err != nil {
		return nil, err
	}

	usage := utils.GetMaxUsedDram()
	b.logger.Infow("rta_construction", "rss_before_rta_construction", usage)
	b.metrics["rss_before_rta_construction"] = float64(usage)

	// Ensure stdlib runs first when isomorphism checking is enabled.
	flavors := b.config.RTABenchFlavors
	if b.config.CheckIsomorphism {
		flavors = ensureStdlibFirst(flavors)
	}

	var stdlibGraph *callgraph.Graph
	var firstResult *callgraph.Graph
	allIsoPassed := true

	for flavorIdx, flavor := range flavors {
		workersToRun := b.config.RTABenchNumWorkers
		if flavor.IsSequential() {
			workersToRun = []int{1}
		}

		for workerIdx, numWorkers := range workersToRun {
			b.logger.Infof("Running RTA flavor %d/%d, worker config %d/%d: %s with %d workers",
				flavorIdx+1, len(flavors), workerIdx+1, len(workersToRun), flavor, numWorkers)

			cg, err := b.runSingleFlavor(entry, flavor, numWorkers)
			if err != nil {
				b.logger.Errorf("Error running RTA flavor %s: %v", flavor, err)
				return nil, err
			}

			if firstResult == nil && cg != nil {
				firstResult = cg
			}

			// Save stdlib result for isomorphism baseline.
			if flavor == FlavorStdlib && stdlibGraph == nil {
				stdlibGraph = cg
			}

			// Inline isomorphism check against stdlib.
			if b.config.CheckIsomorphism && flavor != FlavorStdlib && cg != nil && stdlibGraph != nil {
				flavorStr := flavor.String()
				b.logger.Infof("Isomorphism check: stdlib vs %s (%d workers)", flavorStr, numWorkers)
				isIso, diff := CompareCallGraphs(stdlibGraph, cg, b.logger)
				if isIso {
					b.logger.Infof("ISOMORPHISM CHECK PASSED: stdlib vs %s (%d workers)", flavorStr, numWorkers)
					b.metrics[fmt.Sprintf("isomorphism_check_%s_%d_workers_passed", flavorStr, numWorkers)] = 1
				} else {
					b.logger.Errorf("ISOMORPHISM CHECK FAILED (stdlib vs %s %d workers): %s", flavorStr, numWorkers, diff)
					b.metrics[fmt.Sprintf("isomorphism_check_%s_%d_workers_passed", flavorStr, numWorkers)] = 0
					allIsoPassed = false
				}
			}

			runtime.GC()
		}
	}

	// Release stdlib graph now that all isomorphism checks are done.
	stdlibGraph = nil
	runtime.GC()

	if b.config.CheckIsomorphism {
		if allIsoPassed {
			b.logger.Info("ALL ISOMORPHISM CHECKS PASSED")
			b.metrics["isomorphism_check_passed"] = 1
		} else {
			b.metrics["isomorphism_check_passed"] = 0
			return nil, errors.New("one or more isomorphism checks failed")
		}
	}

	usage = utils.GetMaxUsedDram()
	b.logger.Infow("rta_construction", "rss_after_rta_construction", usage)
	b.metrics["rss_after_rta_construction"] = float64(usage)

	if firstResult == nil {
		return nil, errors.New("RTA call graph is nil")
	}

	b.logger.Infof("Analyzing raw call graph")
	gs := b.logGraphStats(firstResult, _maxCGNodesToLog, zap.InfoLevel)
	b.addGraphStatsToMetrics(gs, "rawGraph")

	b.logAvailableInboundsOutbounds(firstResult, "raw_graph")

	return maps.Clone(b.metrics), nil
}

// CompareCallGraphs checks if two callgraphs are isomorphic.
// Two callgraphs are isomorphic if they have the same nodes (by function identity)
// and the same edges (caller -> callee relationships).
// Returns (isIsomorphic, differences) where differences describes any mismatches.
func CompareCallGraphs(cg1, cg2 *callgraph.Graph, logger *zap.SugaredLogger) (bool, string) {
	if cg1 == nil && cg2 == nil {
		return true, ""
	}
	if cg1 == nil || cg2 == nil {
		return false, "one graph is nil"
	}

	if len(cg1.Nodes) != len(cg2.Nodes) {
		return false, fmt.Sprintf("node count mismatch: %d vs %d", len(cg1.Nodes), len(cg2.Nodes))
	}

	edges1 := make(map[string]int)
	edges2 := make(map[string]int)

	for fn, node := range cg1.Nodes {
		if fn == nil {
			continue
		}
		for _, edge := range node.Out {
			if edge.Callee != nil && edge.Callee.Func != nil {
				key := fn.String() + " -> " + edge.Callee.Func.String()
				edges1[key]++
			}
		}
	}

	for fn, node := range cg2.Nodes {
		if fn == nil {
			continue
		}
		for _, edge := range node.Out {
			if edge.Callee != nil && edge.Callee.Func != nil {
				key := fn.String() + " -> " + edge.Callee.Func.String()
				edges2[key]++
			}
		}
	}

	totalEdges1 := 0
	for _, count := range edges1 {
		totalEdges1 += count
	}
	totalEdges2 := 0
	for _, count := range edges2 {
		totalEdges2 += count
	}

	if totalEdges1 != totalEdges2 {
		return false, fmt.Sprintf("total edge count mismatch: %d vs %d", totalEdges1, totalEdges2)
	}

	if len(edges1) != len(edges2) {
		return false, fmt.Sprintf("unique edge count mismatch: %d vs %d", len(edges1), len(edges2))
	}

	var missingIn2 []string
	var missingIn1 []string
	var countMismatch []string

	for edge, count1 := range edges1 {
		if count2, ok := edges2[edge]; !ok {
			missingIn2 = append(missingIn2, edge)
		} else if count1 != count2 {
			countMismatch = append(countMismatch, fmt.Sprintf("%s: %d vs %d", edge, count1, count2))
		}
	}

	for edge := range edges2 {
		if _, ok := edges1[edge]; !ok {
			missingIn1 = append(missingIn1, edge)
		}
	}

	if len(missingIn2) > 0 || len(missingIn1) > 0 || len(countMismatch) > 0 {
		var diffs []string
		if len(missingIn2) > 0 {
			diffs = append(diffs, fmt.Sprintf("edges in cg1 but not cg2 (%d): %v", len(missingIn2), missingIn2[:min(5, len(missingIn2))]))
		}
		if len(missingIn1) > 0 {
			diffs = append(diffs, fmt.Sprintf("edges in cg2 but not cg1 (%d): %v", len(missingIn1), missingIn1[:min(5, len(missingIn1))]))
		}
		if len(countMismatch) > 0 {
			diffs = append(diffs, fmt.Sprintf("edge count mismatches (%d): %v", len(countMismatch), countMismatch[:min(5, len(countMismatch))]))
		}
		return false, strings.Join(diffs, "; ")
	}

	logger.Infof("Graphs are isomorphic: %d nodes, %d unique edges, %d total edges",
		len(cg1.Nodes), len(edges1), totalEdges1)
	return true, ""
}
