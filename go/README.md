# RPCShield

[![build-test](https://github.com/uber-research/rpcshield/actions/workflows/ci.yml/badge.svg)](https://github.com/uber-research/rpcshield/actions/workflows/ci.yml)
[![lint](https://github.com/uber-research/rpcshield/actions/workflows/lint.yml/badge.svg)](https://github.com/uber-research/rpcshield/actions/workflows/lint.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/uber-research/rpcshield/go.svg)](https://pkg.go.dev/github.com/uber-research/rpcshield/go)
[![Go Report Card](https://goreportcard.com/badge/github.com/uber-research/rpcshield/go)](https://goreportcard.com/report/github.com/uber-research/rpcshield/go)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

RPCShield is a whole-program static analyzer for Go microservices (the `go/` incarnation of the
broader RPCShield approach) that determines, for each dependency a service makes on another,
whether a failure of the downstream dependency also causes the calling service to fail —
**fail-close**, where it does, or **fail-open**, where it does not. It builds a call graph
for a service using a custom Rapid Type Analysis (RTA) implementation, then for every outbound call
site (RPC/DB client) it finds, walks the call chain
**back up toward** each inbound entry point (HTTP/gRPC/Thrift handler) that can reach it, analyzing
one caller/callee hop at a time, and emits CSV/HTML reports of which inbound/outbound pairs fail
open. A single fail-open hop anywhere on a path makes that whole path fail-open; conversely, a
single fail-close path is enough to call the whole inbound/outbound pair fail-close, even if other
paths between the same two points fail open. This applies to any dependency, but by default
RPCShield scopes its analysis to **cross-tier** outbound dependencies (a more-critical service
calling a less-critical one, `DriverOptions.SkipOBTierFilter` lifts this scoping), because that's
where a downstream failure causing an upstream failure is most consequential: it couples a critical
service's own availability to a dependency that wasn't built to the same reliability bar.

## How it works

1. **Load** — the target service's packages are loaded via `golang.org/x/tools/go/packages` and
   built into an SSA program.
2. **Call graph** — a whole-program call graph is constructed using this repo's own Rapid Type
   Analysis implementation (`rta/`), which scales to far larger codebases than the standard
   `golang.org/x/tools/go/callgraph/rta`. See [`rta/README.md`](rta/README.md).
3. **Find call sites** — inbound entry points (HTTP handlers, gRPC/Thrift servers) and outbound
   call sites (RPC/DB clients) are located (`finder/`); outbound sites belonging to a
   lower-criticality-tier dependency than the calling service are the ones kept for analysis.
4. **Analyze** — for each outbound call site's path(s) back to an inbound entry point, an SSA/SCCP
   (Sparse Conditional Constant Propagation) analyzer walks the path one caller/callee hop at a
   time, from the outbound call back toward the inbound, determining whether each hop propagates or
   swallows the downstream error. See [`graph/SCCP_Design.md`](graph/SCCP_Design.md) and
   [`staticanalyzer/ssaanal/README.md`](staticanalyzer/ssaanal/README.md).
5. **Report** — results are assembled into CSV/HTML reports (`output/`, `reporting/`).

## Architecture

### End-to-end pipeline

```
 ┌───────────┐   ┌───────────┐   ┌───────────┐   ┌───────────┐   ┌───────────┐   ┌───────────┐
 │ 1. Load   │──▶│ 2. Build  │──▶│ 3. Find   │──▶│ 4. Build  │──▶│ 5. Analyze│──▶│ 6. Report │
 │ packages  │   │ call graph│   │ inbound/  │   │ call paths│   │ each hop  │   │ + metrics │
 │ (bazel/,  │   │ (rta/)    │   │ outbound  │   │ (graph/)  │   │(static /  │   │ (output/, │
 │  loader/) │   │           │   │ (finder/) │   │           │   │ LLM)      │   │ reporting/)│
 └───────────┘   └───────────┘   └───────────┘   └───────────┘   └───────────┘   └───────────┘
```

`driver.go`'s `Driver.Run`/`Driver.RunOnPackages` wires these six stages together. Each is a plain
Go package behind a narrow interface, so the pipeline runs both as a library
(`RunOnPackages`, used by `pipeline_evaluation_scripts/` against arbitrary OSS repos) and as the
full CLI (`cmd/rpcshield/`).

### 1. Loading a Bazel monorepo target as plain Go packages (`bazel/`, `loader/`)

`go/packages` needs an on-disk GOPATH-style tree; a Bazel target is neither that nor buildable in
isolation once a service depends on DI-framework-generated code. `bazel.LiftGoPath` (`bazel.go`)
bridges the two: it parses the `//pkg:target` label, patches that target's `BUILD.bazel` in place
(via `buildozer`) to add a transient `go_path` rule depending on the target, `bazel build`s that
rule to materialize a real GOPATH tree under `bazel-bin`, then reverts the `BUILD.bazel` patch. A
second pass (`rename.go`) rewrites the materialized tree: DI-framework-generated `glue_*.go` files
are moved out of a synthetic `glue/decorator/...` package into their real source package (stripping
the self-import that would otherwise create an import cycle), and any resulting name clash is
resolved with an `_rpcshield` suffix (`New` → `New_rpcshield`). The result is an ordinary,
`go/packages`-loadable module tree — everything downstream of this stage is Bazel-agnostic. See
[`bazel/README`](bazel/README).

### 2. Whole-program call-graph construction (`rta/`)

```
 roots (main, inbound handlers)
        │
        ▼
 RTA worklist: reachable functions + live types  ◀── method-set fingerprint (CRC32 bitmask)
        │ discovers a new (concrete type, interface) pair    rejects non-implementing pairs
        ▼                                                     in O(1), before calling the
 inverted method index ("Kumo"): interface → candidate         expensive types.Implements
 concrete types sharing its rarest method (not a full scan)
        │
        ▼
 callgraph.Graph edges
```

The standard `golang.org/x/tools/go/callgraph/rta` is correct but does an O(C×I) implements-check
between every concrete type C and every interface I, single-threaded — this doesn't scale past a
few thousand types. `rta/` re-implements RTA behind a common `rta.RTA`/`rta.Result` interface with
8 selectable "flavors" (`srta`, `srta_kumo`, `prta_naive`, `prta_nonblocking`, `prta_kumo`,
`prta_kumo_nonblocking`, plus ablations) that independently add sequential-vs-parallel worklist
processing and a plain scan vs. the inverted "Kumo" method index. Every flavor is checked against
the stdlib RTA's own output for correctness (`rtatest.AssertMatchesStdlib`) — the optimizations are
only allowed to change *speed*, never the resulting graph. See [`rta/README.md`](rta/README.md).

### 3. Inbound/outbound call-site discovery and API-to-implementation mapping (`finder/`)

`finder/` walks the loaded AST/`go/types` info (not SSA) looking for known **inbound** shapes —
YARPC gRPC/Thrift server interfaces, generic `google.golang.org/grpc`
`Register*Server(ServiceRegistrar, ...)` calls, Apache Thrift processors, TChannel servers, Kafka
consumer-proxy handlers, and HTTP handlers (gin, gorilla/mux) — and known **outbound** shapes —
gRPC/Thrift clients, Cadence/Temporal workflow clients, and HTTP clients (`net/http.Client` plus
configurable additional client types). Detection matches on package path + type name against each
shape's `types.Object`, e.g. an embedded client struct field or a `Register*Server` call's second
argument type — new frameworks are added by teaching `finder/` one more shape, not by changing
anything downstream.

For **outbound** call sites specifically, `finder/servicemapping.ServiceMapper.InferService` then
answers "which service actually implements this RPC client interface?" — the API-to-implementation
mapping. It combines a client-package-path → service table with `fx_scanner.go` (statically finds
which `fx.Provide` wiring concretely supplies a given client interface) and `config_resolver.go`
(resolves service names out of YARPC/config declarations), with `name_match.go` doing fuzzy
tie-breaking when more than one candidate service matches.

### 4. Graph enrichment and call-path construction (`graph/`)

```
 base callgraph (rta/, or cha for a cheaper mode)
        │
        ▼
 enrichers add edges the base graph misses:
   cffenricher.go      — CFF codegen: enqueue call → enqueued task function
   errgroupenricher.go — any type with Go/TryGo + Wait() error: .Wait() → each .Go(fn)
   safegoenricher.go   — fire-and-forget goroutine spawn: call site → spawned closure
   modelfx/            — fx.Provide/Invoke wiring → DI-mediated call edges
        │
        ▼
 per-inbound concurrent call tree (cct.go): built forward from each inbound root, following
 real callgraph edges outward, non-recursive, no function repeats on a path, terminating
 at outbound leaves
        │
        ▼
 CallPath{Inbound, Outbound, Edges} — one per inbound→outbound path found in the tree
```

Path *discovery* walks forward, inbound→outbound (`buildCallTree` starts from each inbound root and
recurses along real callgraph edges until it hits an outbound leaf) — but the *analysis* in step 6
below walks each discovered path in reverse, outbound→inbound, since the question being asked
("does this downstream error survive back to the entry point?") is naturally posed from the
downstream call site's point of view.

Everything above contributes into one `callgraph.Graph` rather than each mechanism getting its own
bespoke path-finder, so "is there a path from this inbound to that outbound" stays a single
graph-reachability question regardless of whether the connection is a direct call, a DI-wired call,
a goroutine, or a CFF stage. Two fanout/depth safety valves bound the traversal on pathological
graphs: `PermutationThreshold` (default 100) trips once the same function-set reaches a sink that
many times, and `MaxFunctionVisits` (default 1000) caps re-exploration of any one function's
subtree, beyond which it's marked a "convergence point" and skipped rather than re-walked.

### 5. Infeasible-path elimination (`graph/constprop.go`, `graph/lattice.go`)

Before a `CallPath` is handed to an analyzer, `graph/`'s own SCCP pass (Wegman & Zadeck's Sparse
Conditional Constant Propagation) evaluates the branch conditions actually guarding that specific
path's edges. If a condition would provably never take the branch the path relies on — e.g. a
feature-flag check that's a compile-time constant, or a type switch whose case the path's concrete
type can never hit — the whole path is dropped as infeasible before any per-hop error-handling
analysis runs on it. This is graph-level, whole-path pruning, distinct from (and cheaper than) the
per-hop SCCP in `staticanalyzer/ssaanal/` described next; its yield is tracked directly in metrics
(`constpropCandidatePaths`/`FeasiblePaths`/`InfeasiblePaths`).

### 6. Hop-by-hop fail-close analysis (`staticanalyzer/`)

```
 CallPath = [ inbound ── edge ── fn₁ ── edge ── fn₂ ── edge ── outbound (RPC call) ]
                                  ▲                ▲
                        one hop = one caller/callee edge, analyzed independently

 for each hop, in sequence from the outbound call back toward the inbound:
   is the callee's error reachable, non-suppressed, and attributed to
   a `return` in the caller (fail-close), or dropped (fail-open)?
        │
        ▼
 per-hop verdicts stitched into one AggregatedStatus for the whole path
```

The unit of analysis is always one caller/callee edge, not the whole path or the whole program: for
each hop, `ssaanal.AnalyzeCallBySCCPWithOptions` (falling back to the simpler `ssaanal.AnalyzeCall`,
then AST heuristics) runs a fresh interprocedural SCCP scoped to that hop's caller function and that
one call site — extended with a Go-type lattice alongside the usual value lattice, and tuple-aware
so multi-value returns and comma-ok type assertions are first-class lattice elements instead of
being flattened. This is what lets the analyzer see through multi-source error merging,
short-circuit guards, and deferred named-return mutation instead of only matching the textbook
`if err != nil { return err }` shape. See [`graph/SCCP_Design.md`](graph/SCCP_Design.md) and
[`staticanalyzer/ssaanal/README.md`](staticanalyzer/ssaanal/README.md) for the full lattice/fixed-point
definition.

**Aggregating hops into a path, and paths into a finding.** Each hop yields one of a fixed set of
statuses (`FailOpen`, `FailClose`, `FailCloseSuppressed`, `FailUnknown`, and two `FailUnknown`
variants). Two different merge rules apply at two different levels:

- **Within one path, hops merge toward `FailOpen`**: if any single hop along the path swallows the
  error, the whole path is `FailOpen` — one broken link is enough to break the chain, regardless of
  how well the other hops handle it.
- **Across the paths of one inbound/outbound pair, paths merge toward `FailClose`**: if at least one
  path successfully propagates the error end-to-end, the pair as a whole is reported `FailClose` —
  the tool's goal is to catch inbound/outbound pairs where **no** path gets the error through, not
  to flag every imperfect path once a working one exists.

This is also where the criticality-tier framing from the intro matters: `FailClose` is the correct,
desired outcome in general. RPCShield only bothers analyzing outbound calls to a **lower**
criticality tier than the calling service in the first place (`DriverOptions.SkipOBTierFilter` gates
this filtering) — because a tier-0 service propagating (`FailClose`) a failure from a
less-critical, less-reliably-operated downstream is exactly the scenario where correct error
handling still produces an availability problem: the critical service's own uptime becomes coupled
to a dependency that isn't held to the same bar. `FailOpen` findings are the direct bugs; the
tier scoping is what makes the surrounding `FailClose` cases worth reporting on at all.

### Static-analysis variants and fallback chain (`constant.AnalyzerKind`)

Each hop is resolved by trying, in order, only the kinds enabled in `DriverOptions.Analyzers`,
falling through whenever a stage returns "unknown" rather than a verdict:

1. **Cache** — reuse a previously computed verdict for an identical (caller, callee) pair.
2. **Predefined** — a hardcoded rule table for well-known idioms.
3. **SCCP** — the interprocedural SCCP analyzer (§6, the default and most precise static mode).
4. **SSA** — a cheaper, non-interprocedural SSA pattern-matcher, when SCCP is disabled or too slow.
5. **AST** — AST-context heuristics, for code shapes that don't lower to analyzable SSA.
6. **LLM** — `genai/` prompts a model with a code "skeleton" (`skeletonize/`) around the call site,
   as a last resort for cases the static stages can't classify confidently — supplementary, not a
   replacement for the deterministic/explainable static stages above it.

### Reporting and metrics (`output/`, `reporting/`)

Findings are written as CSV (one row per inbound/outbound pair — service/tier/endpoint on both
sides, path count, a JSON blob of per-path reports, and a JIRA-readiness flag) and as HTML,
including a per-report flamegraph SVG visualizing the call paths contributing to that finding. A
single structured `wpa_metrics` JSON log line per run reports: inbound/outbound discovery counts,
the constant-propagation pruning yield (§5), per-analyzer status/duration breakdowns across the
fallback chain (§ above), RTA call-graph build statistics, and call-tree exploration diagnostics
(convergence points/skips, permutation-threshold hits) — this is the data
[`pipeline_evaluation_scripts/`](pipeline_evaluation_scripts/README.md) and the baseline-vs-ported
comparison harness both key off of to detect regressions.

## Getting started

```bash
# Build and test with Bazel -- the only supported way to run this repo's tests.
bazel build //...
bazel test //...
```

Plain `go build ./...`/`go vet ./...` also work as a quick sanity check, but plain `go test` does
not: several packages (e.g. the root `driver_test.go`) import mocks generated by Bazel's gomock
rule into a GOPATH-style `mock/github.com/...` path that only exists inside Bazel's sandbox/runfiles
tree, so `go test` fails with `package mock/... is not in std` even though nothing is actually
broken -- always verify with `bazel test`, not `go test`.

To run the analyzer end-to-end against a real open-source Go service (not just unit tests), see
[`pipeline_evaluation_scripts/README.md`](pipeline_evaluation_scripts/README.md) — a standalone
harness that drives the same detection/analysis pipeline against real OSS repositories (etcd,
temporal, thanos, vitess, jaeger, and others) with known-answer fixtures to validate correctness.

## Repository layout

| Path | Purpose |
| --- | --- |
| `driver.go` | Top-level pipeline orchestrator (`Driver.Run`/`Driver.RunOnPackages`). |
| `rta/` | Custom Rapid Type Analysis call-graph construction. See [`rta/README.md`](rta/README.md). |
| `staticanalyzer/` | The fail-close/fail-open detection core (SCCP + control-flow analysis). See [`graph/SCCP_Design.md`](graph/SCCP_Design.md). |
| `graph/` | Call-graph construction/enrichment, constant propagation, package filtering. |
| `finder/` | Locates inbound (handler) and outbound (client) call sites. |
| `modelfx/` | Detects `go.uber.org/fx` dependency-injection wiring so DI-mediated call edges are traced. |
| `skeletonize/` | Extracts a minimal code "skeleton" around a call site for reports. |
| `output/`, `reporting/` | CSV/HTML report generation. |
| `cmd/rpcshield/` | The CLI entry point. |
| `pipeline_evaluation_scripts/` | Harness for running the full pipeline against real OSS Go services. See its own [README](pipeline_evaluation_scripts/README.md). |
| `exampleapps/` | Small standalone Go programs used as golden test fixtures. |

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for build/test/lint instructions.

## Contributors

Ordered alphabetically by last name.

- Milind Chabbi
- Sonal Mahajan
- Elton Pinto
- Yuxin Wang
- Yufan Xu

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).
