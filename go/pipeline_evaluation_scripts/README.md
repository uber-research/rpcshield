# OSS Pipeline Evaluation Harness

Runs rpcshield's *real* fail-close/fail-open analysis pipeline (finder, RTA/call-graph
construction, SSA/SCCP analyzer, CSV/HTML reporting) -- not just RTA construction, see
`../rta/evaluation_scripts` for that -- against open-source Go projects that use standard
`google.golang.org/grpc` and/or `github.com/apache/thrift`, rather than internal YARPC-over-protobuf
conventions. This is the harness for validating the `Config.EnableGenericGRPCThriftDetection`
detection added to `finder/outbound.go` and `finder/inbound.go`.

## Why a standalone binary rather than `rpcshield wpa`

Same rationale as `../rta/evaluation_scripts`: `rpcshield wpa` assumes a large internal monorepo (Bazel
`go_path` lifting, Grail service registry, RPC IDL discovery). This harness instead drives
`Driver.RunOnPackages` -- an entrypoint purpose-built for callers that have already loaded packages
via `golang.org/x/tools/go/packages` and want to skip Bazel-target discovery, `GoPathWrapper`, and
the Grail service registry entirely. `rpcshield` itself is unchanged by this harness; only
`finder/outbound.go`, `finder/inbound.go`, `finder/finder.go`, and `config/config.go` gained new,
additive, flag-gated code (`EnableGenericGRPCThriftDetection`, default `false`).

## Layout

```
pipeline_evaluation_scripts/
├── README.md                    # this file
├── targets.csv                  # OSS manifest (CSV w/ header)
├── clone_datasets.sh            # shallow clone + go mod download (copy of ../rta/evaluation_scripts's)
├── run_oss_pipeline_sweep.sh    # driver, one target per targets.csv row
├── check_fixture.sh             # known-answer correctness check (see below)
├── fixtures/
│   └── grpc_failopen/
│       └── fixture.go           # known-answer fail-open/fail-close fixture
└── cmd/oss_pipeline_bench/
    ├── BUILD.bazel
    └── main.go                  # single-target pipeline-run binary
```

## End-to-end usage

```bash
# 1. (one-time) Clone the OSS targets and pre-populate their module caches.
./clone_datasets.sh                       # uses ./datasets by default

# 2. (one-time, also auto-runs from the sweep script) Build the harness binary.
bazel build //pipeline_evaluation_scripts/cmd/oss_pipeline_bench:oss_pipeline_bench

# 3. Run the known-answer fixture check -- proves *correct* classification, not just "doesn't crash".
./check_fixture.sh

# 4. Run the full sweep across targets.csv (real, non-fixture code).
./run_oss_pipeline_sweep.sh -output /tmp/oss_pipeline_$(date +%Y%m%d)
```

## Current sweep status (all 11 `targets.csv` rows)

Last full run: 2026-07-24, `oss_pipeline_bench` built from `~/rpcshield/go` at HEAD. All 11 targets
completed without crashing or timing out (`run_oss_pipeline_sweep.sh` summary: `total: 11, ok: 11,
failed: 0, timed out: 0`).

| target | inbounds (found/expected) | outbounds (found/expected) | reports | status |
| --- | --- | --- | --- | --- |
| etcd-server | 36/36 | 353/356 | 39 | success |
| temporal-server | 152/152 | 732/770 | 72 | success |
| thanos | 3 | 53 | 0 | success_no_call_paths |
| argo-server | 40 | 154 | 0 | success_no_call_paths |
| vitess-vtgate | 8/8 | 76/76 | 29 | success |
| cortex | 16/16 | 63/63 | 9 | success |
| vitess-vttablet | 103/103 | 142/142 | 98 | success |
| trillian-log-server | 20 | 4 | 0 | success_no_call_paths |
| loki | 29/29 | 70/71 | 24 | success |
| jaeger-collector | 20 | 16/29 | 9 | success |
| jaeger-remote-storage | 14/14 | 14/19 | 9 | success |

Notes:
- `success_no_call_paths` (thanos, argo-server, trillian-log-server) means the driver ran to
  completion but found no inbound-to-outbound call path for the detected entry points/outbounds on
  that entrypoint package -- not a crash or regression, just no findings for the current detection
  shapes on that target's `pkg`.
- `jaeger-collector`'s outbound count (16 found vs. 29 expected) reflects one inbound
  (`GRPCHandler.Capabilities`) that RTA marks reachable via a plugin-only dynamic dispatch it can't
  resolve in this binary; `graph.go`'s `synthesizeMissingInboundNodes` gives it an isolated
  call-graph node (logged as `num_synthesized: 1`) instead of aborting the whole run, which is why
  the target still completes with `status: success` and produces 9 reports for its other paths.
- "found/expected" is omitted (single number only) for targets where `expected` wasn't separately
  tracked in the driver log for that inbound/outbound count.

## Direct binary invocation (single target, useful for smoke tests)

```bash
bazel-bin/.../oss_pipeline_bench \
    -dataset-root=$PWD/datasets \
    -target-name=etcd-kv-grpc \
    -target-dir=etcd/api \
    -target-pkg=./... \
    -codebase-pkg-prefix=go.etcd.io/etcd \
    -output-dir=/tmp/oss_pipeline_smoke
```

Or with the known-answer fixture overlaid instead of `-target-pkg`:

```bash
bazel-bin/.../oss_pipeline_bench \
    -dataset-root=$PWD/datasets \
    -target-name=fixture-check \
    -target-dir=etcd/api \
    -target-pkg=./... \
    -codebase-pkg-prefix=go.etcd.io/etcd \
    -fixture-file=$PWD/fixtures/grpc_failopen/fixture.go \
    -output-dir=/tmp/oss_pipeline_fixture
```

Expected completion line: `INFO  Finished OSS pipeline evaluation`, preceded by a JSON
`oss_pipeline_metrics` line with `status`, `num_inbounds`, `num_outbounds`, `num_reports`, and
`failness_counts`.

## Known-answer fixture

`fixtures/grpc_failopen/fixture.go` is a small `package main` file that is never built/run for
real; it is merged into a real dataset module via `packages.Config.Overlay` (see
`cmd/oss_pipeline_bench/main.go`'s `-fixture-file`/`-fixture-pkg-dir` flags), reusing the target
module's *real* generated gRPC types rather than inventing lookalikes. It defines two servers
implementing the same real gRPC service interface (`etcdserverpb.KVServer`), each of which calls a
downstream client of that same interface (`etcdserverpb.KVClient`) from inside its own handler
method:

- `kvServerFailOpen.Put` swallows the downstream error -- expected: `FailOpen`
- `kvServerFailClose.Put` propagates the downstream error -- expected: `FailClose`

`check_fixture.sh` runs the harness against this fixture and asserts the output CSV contains both
expected classifications, so a passing run demonstrates *correct* detection on real generated code,
not just a crash-free pipeline run.

Why the inbound handler makes its own downstream call, rather than delegating to a separate,
disconnected helper function called only from `main()`: rpcshield's RTA implementation
(`rta/srta/impl.go`) only creates a `callgraph.Node` for a function when it appears as a caller or
callee of some edge. An inbound "root" function (passed to RTA as an explicit root because
`finder.Inbound` found it) that makes no calls of its own is never found in the constructed call
graph (see `graph/cct.go`'s `buildCallTreeNode`), even though it's a valid RTA root -- so a fixture
whose handler and downstream call are structurally disconnected produces a hard `RunOnPackages`
error (`... function not found in the call graph`) rather than a fail-open/fail-close result.

Why etcd (`go.etcd.io/etcd/api/v3/etcdserverpb`), not yarpc-go, is the type source: see "Gotchas"
below.

## Targets manifest format

`targets.csv`, a standard CSV with a header row and one target per row. Columns:

| column | meaning |
| --- | --- |
| `name` | unique label, used for the per-target output subdirectory |
| `repo` | git URL passed to `git clone` |
| `tag`  | git tag passed to `git clone --branch` |
| `dir`  | path under `${DATASETS_ROOT}` containing the `go.mod` for the project (may include subdirs for nested-module repos, e.g. `etcd/api`) |
| `pkg`  | package path passed to `packages.Load`, relative to `dir` (e.g. `./...`, `.`) |
| `service_name` | `grail.Service.Name` used in the driver run and reports; defaults to `name` if blank |
| `codebase_pkg_prefix` | import-path prefix identifying the target's *own* code (e.g. `go.etcd.io/etcd`). Required -- see "Gotchas" below. |
| `drop_exclude_package_patterns` | optional, comma-separated exact entries to remove from `graph.DefaultExcludePackagePatterns` for this target only (see "Gotchas" below). Blank for most targets; needed when the target's own module path matches one of the default patterns. |

## Gotchas

- **Monorepo `go` wrapper.** Same as `../rta/evaluation_scripts`: `<workspace>/bin/go`
  hardcodes `GO111MODULE=off`, which breaks `packages.Load` against OSS checkouts. Both
  `clone_datasets.sh` and `run_oss_pipeline_sweep.sh`/`check_fixture.sh` prepend `$(go env
  GOROOT)/bin` to `PATH` and set `GO111MODULE=on`. Do the same in your shell before invoking the
  binary directly.
- **`-codebase-pkg-prefix` is required and load-bearing.** `finder.Outbound` scopes its AST scan to
  packages matching `Config.CodebasePkgPrefix` (an empty prefix -- the zero value -- matches every
  package path). Without setting this to the target's own module prefix, the scan also walks every
  transitive dependency's *own* internals, e.g. matching `google.golang.org/grpc`'s own
  `addrConn`/`ClientConn` structs (which genuinely have a `*grpc.ClientConn`-typed field, just as a
  parent back-pointer, not as an outbound client) as false-positive "generic gRPC clients". Seen in
  practice: unscoped, a two-call-site fixture produced 81 "outbound" detections, mostly grpc-go's
  own plumbing; scoped to the target's own prefix, exactly 2.
- **`graph.DefaultExcludePackagePatterns` collides with some candidate OSS targets.**
  `graph/pkgfilter.go`'s default exclude list treats several popular RPC/tracing/DI libraries as
  generic "framework plumbing" to drop from call-graph construction --
  `^go.uber.org/yarpc(/.*)?$`, `^github.com/yarpc/yarpc-go(/.*)?$`,
  `^github.com/uber/tchannel-go(/.*)?$`, `^github.com/apache/thrift(/.*)?$`,
  `^go.opentelemetry.io(/.*)?$`, `^github.com/jaegertracing(/.*)?$`, and others (see the variable's
  full list). That's correct when one of those is a *dependency* of the service under analysis, but
  it silently excludes the entire target (and its generated types) from the call graph when the
  *target itself* is one of those libraries' own repos. This is why yarpc-go (an earlier candidate
  for this harness, since its `internal/crossdock` package makes real `grpc-go` calls) doesn't
  work as a target: its own package path is excluded by default, so no fixture or real code under
  `go.uber.org/yarpc/...` ever appears as a call-graph node, regardless of what
  `EnableGenericGRPCThriftDetection` does.

  The harness's `-drop-exclude-package-patterns` flag (`targets.csv`'s
  `drop_exclude_package_patterns` column) addresses this per-target: it removes the named exact
  entries from `graph.DefaultExcludePackagePatterns` before building `config.Config`, via
  `config.Config.ExcludePackagePatterns` (there's still no `config.Config` knob to edit the base
  list in place; the harness computes the filtered list itself and passes it as an explicit
  override). `jaeger-collector`/`jaeger-remote-storage` use this to drop
  `^github.com/jaegertracing(/.*)?$`, since both analyze `jaegertracing/jaeger` itself. yarpc-go
  was never retried with this flag -- pick targets whose module path doesn't collide with
  `graph.DefaultExcludePackagePatterns`, or set `drop_exclude_package_patterns` for ones that do;
  etcd (`go.etcd.io/etcd/...`) needs no override.
- `packages.PrintErrors > 0` is common -- OSS projects gate code behind build tags. The harness
  logs the error count but only aborts if `driver.go`'s stricter per-package SSA-availability check
  (`dumpPackageDiagnostics`) finds packages with no corresponding SSA package at all.
- `Driver.Run`/`RunOnPackages` hard-fails a target if either inbound or outbound points are zero
  across the whole run (by design -- see `driver.go`'s post-detection check). Targets with real
  gRPC/Thrift generated types but no reachable `main()` calling into a server registration (e.g.
  `etcd/api` alone, which is just the generated pb.go definitions with no `main()`) will fail this
  way; that's expected for library-only modules and is why the fixture overlay brings its own
  `main()`.
- `go mod download` is run at clone time so the sweep can run offline.

## Reference

Files modeled against `../rta/evaluation_scripts`:
- `run_oss_rta_sweep.sh` -- driver shape (`run_oss_pipeline_sweep.sh`)
- `clone_datasets.sh` -- copied verbatim (already generic)
- `cmd/oss_rta_bench/main.go` -- `loadProgram`/`Infof`/`Fatalf` pattern
- `driver.go`'s `RunOnPackages` doc comment -- the extension point this harness drives
