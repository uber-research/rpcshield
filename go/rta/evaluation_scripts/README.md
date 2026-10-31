# OSS RTA Evaluation Harness

Runs the RTA (Rapid Type Analysis) algorithm flavors from
`github.com/uber-research/rpcshield/go/rta` against open-source Go
projects cloned from GitHub. The output shape mirrors what
`../run_rta_sweep.sh` produces for monorepo services, so downstream parsers keyed
on the `Running RTA flavor: <flavor> with <N> workers`, `RTA <flavor> with
<N> workers took ...`, and `Finished CG construction-only evaluation` log
lines continue to work without change.

## Why a standalone binary rather than `rpcshield wpa`

`rpcshield wpa` assumes a large internal monorepo: Bazel `go_path` lifting, Grail
service-registry JSON, the `src/example.internal/...` package prefix, and
RPC IDL discovery for inbound entrypoints. None of that exists for a GitHub
checkout. Rather than mock all of those layers (a large lift), this harness
imports the 8 flavor packages directly and drives them via
`golang.org/x/tools/go/packages` + SSA — the same pattern the older
`~/prta_oss/kumo` harness used. `rpcshield` itself is unchanged.

## Layout

```
evaluation_scripts/
├── README.md                         # this file
├── targets.csv                       # 27-row OSS manifest (CSV w/ header)
├── clone_datasets.sh                 # shallow clone + go mod download
├── run_oss_rta_sweep.sh              # driver (mirrors run_rta_sweep.sh)
└── cmd/oss_rta_bench/
    ├── BUILD.bazel
    └── main.go                       # single-target sweep binary
```

## End-to-end usage

```bash
# 1. (one-time) Clone the 14 OSS targets and pre-populate their module caches.
./clone_datasets.sh                       # uses ./datasets by default
# or: ./clone_datasets.sh /scratch/oss_datasets

# 2. (one-time, also auto-runs from the sweep script) Build the harness binary.
bazel build //src/github.com/uber-research/rpcshield/go/rta/evaluation_scripts/cmd/oss_rta_bench:oss_rta_bench

# 3. Run the sweep.
./run_oss_rta_sweep.sh -output /tmp/oss_rta_$(date +%Y%m%d)

# Smaller subset:
./run_oss_rta_sweep.sh \
    -targets <(grep -E '^name,|^(nats-server|caddy),' targets.csv) \
    -flavors srta,prta_kumo_nonblocking \
    -workers 1,8 \
    -output /tmp/oss_smoke
```

Output is one `<output>/<target-name>.log` per target.

## Direct binary invocation (single target, useful for smoke tests)

```bash
bazel-bin/.../oss_rta_bench \
    -dataset-root=$PWD/datasets \
    -target-name=nats-server \
    -target-dir=nats-server \
    -target-pkg=. \
    -flavors=srta,prta_kumo_nonblocking \
    -workers=1,8
```

Expected log line sequence:

```
INFO target=nats-server dir=nats-server pkg=. flavors=... workers=...
INFO Loading package . from .../datasets/nats-server
INFO Loaded N top-level packages in ... (X package errors, non-fatal)
INFO SSA build complete in ... (M ssa packages)
INFO Total roots (main + init functions): R (mains: 1)
INFO Running RTA flavor: srta with 1 workers
INFO rta_duration_secs_srta_1_workers=...
INFO rta_cpu_time_ms_srta_1_workers=...
INFO rta_peak_heap_delta_mb_srta_1_workers=...
INFO rta_alloc_bytes_total_mb_srta_1_workers=...
INFO rta_alloc_objects_total_srta_1_workers=...
INFO RTA srta with 1 workers took ..., cpu time: ... ms, peak heap delta: ... MB, total allocated: ... MB / ... objects
INFO rta_callgraph_nodes_srta_1_workers=...
INFO rta_callgraph_edges_srta_1_workers=...
INFO rta_reachable_funcs_srta_1_workers=...
INFO Running RTA flavor: prta_kumo_nonblocking with 8 workers
...
INFO Finished CG construction-only evaluation
```

## Targets manifest format

`targets.csv`, a standard CSV with a header row and one target per row.
Columns:

| column | meaning |
| --- | --- |
| `name` | unique label, used for the per-target log filename |
| `repo` | git URL passed to `git clone` |
| `tag`  | git tag passed to `git clone --branch` |
| `dir`  | path under `${DATASETS_ROOT}` containing the `go.mod` for the project. Multiple targets may share the top-level dir (kubernetes-kubelet and kubernetes-apiserver both use `kubernetes`). The dir may include subdirs for nested-module repos (`etcd/server`). |
| `pkg`  | package path passed to `packages.Load`, relative to `dir` (e.g., `./cmd/kubelet`, `.`) |

## Flavors

| flavor | type |
| --- | --- |
| `srta` | sequential |
| `srta_opt` | sequential |
| `srta_kumo` | sequential |
| `srta_kumo_random` | sequential (ablation) |
| `prta_naive` | parallel |
| `prta_nonblocking` | parallel |
| `prta_kumo` | parallel |
| `prta_kumo_nonblocking` | parallel |

Sequential flavors ignore the `-workers` list and always run with `1` worker
(matches `rpcshield/graph/rtaeval.go:runSingleFlavor`). `stdlib` / `cha` are
not supported by this harness (out of scope for v1; would require
re-implementing the isomorphism baseline outside of `rpcshield/graph`).

## Output / metrics

Each per-target log contains, per (flavor, workers) iteration:

- `rta_duration_secs_<flavor>_<N>_workers`
- `rta_cpu_time_ms_<flavor>_<N>_workers`
- `rta_peak_heap_delta_mb_<flavor>_<N>_workers`
- `rta_alloc_bytes_total_mb_<flavor>_<N>_workers`
- `rta_alloc_objects_total_<flavor>_<N>_workers`
- `rta_callgraph_nodes_<flavor>_<N>_workers`
- `rta_callgraph_edges_<flavor>_<N>_workers`
- `rta_reachable_funcs_<flavor>_<N>_workers`
- Optional counters (`rta_implements_calls_...`, `rta_concrete_types_...`,
  `rta_interface_types_...`, `rta_implements_success_...`,
  `rta_implements_fail_...`, `rta_checks_from_interfaces_...`,
  `rta_checks_from_implementations_...`) when the flavor's `Result`
  implementation satisfies the corresponding optional interface in
  `rta/lib.go`.

The metric key shape and the summary `RTA ... took ... cpu time ... peak heap
delta ... total allocated ... / ... objects` line are byte-equivalent to what
`rpcshield/graph/rtaeval.go:259-394` emits, so the same `prta_stats_review`
parsers can ingest both monorepo and OSS sweeps.

## Gotchas

- **Monorepo `go` wrapper.** `<workspace>/bin/go` (the wrapper on
  `$PATH` inside this checkout) hardcodes `GO111MODULE=off` and sources a
  per-project `tools/common/env.sh`, which breaks `packages.Load` against
  OSS checkouts (the loader silently treats the target as a GOPATH-mode
  directory and never builds the main function). Both `clone_datasets.sh`
  and `run_oss_rta_sweep.sh` prepend `$(go env GOROOT)/bin` to `PATH` and
  set `GO111MODULE=on` to bypass the wrapper. If you invoke the binary
  directly, do the same in your shell first.
- **Kubernetes** SSA build is the heaviest; expect 30–60 GB RSS. Set
  `GOMEMLIMIT=80GiB` or similar before running. The default per-target
  `-timeout 5400` (90 min) is likely too short for k8s on the full
  flavor × worker matrix; bump it or trim flavors when sweeping k8s.
- **etcd** is a nested-module repo from v3.5 on: the `main` package lives
  in `etcd/server`, so the manifest uses `dir=etcd/server`, `pkg=.`. The
  clone still goes to `${DATASETS_ROOT}/etcd`.
- `packages.PrintErrors > 0` is common — OSS projects gate code behind
  build tags (Windows-only, cgo-off, etc.). The harness logs the error
  count but does not abort; it only fails if no main function is found in
  the loaded program.
- `go mod download` is run at clone time so the sweep can run offline; if
  you populate `datasets/` by some other means, run `go mod download`
  manually in each project before sweeping.
- One binary per target by design — process exit reliably returns memory to
  the OS between targets. Within a target, `runtime.GC()` between
  iterations is the best we can do.

## Reference

Files modeled against:
- `../run_rta_sweep.sh` — driver shape
- `rpcshield/graph/rtaeval.go:259-397` — per-flavor metric capture and log lines
- `rpcshield/rtabench.go:60` — completion marker
- `../lib.go:93-104` — `rta.RTA` interface contract (`ssa.InstantiateGenerics` mandatory)
- `~/prta_oss/kumo/rta_test.go` — original OSS load + SSA + roots pattern
- `~/prta_oss/kumo/scripts/clone_datasets.sh` — original dataset URLs and tags
