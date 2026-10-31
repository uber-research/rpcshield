// Package config holds Uber-specific settings (hosts, tokens, service allowlists) that
// rpcshield packages depend on at runtime instead of hardcoding them.
package config

// Config carries the Uber-specific values that packages in this repo would otherwise hardcode.
// The monorepo fork populates this with real values; an open-source fork can leave fields at
// their zero value to disable the corresponding integration.
type Config struct {
	// SourcegraphURLTemplate is the URL template used to link a call site to its source in a
	// Sourcegraph-like code search tool. It contains the placeholders {GitSHA}, {filepath}, and
	// {line}. Empty disables Sourcegraph links.
	SourcegraphURLTemplate string
	// CodePrefix is the path prefix used to normalize a sandboxed/absolute file path back to its
	// repo-relative form (e.g. "src/example.internal") before building a source link. Empty
	// disables the normalization heuristic, leaving file paths as-is.
	CodePrefix string
	// RepoNameForCSV is the repo name recorded in the "repo" column of CSV reports.
	RepoNameForCSV string
	// TerrablobFileURLTemplate is the URL template for an uploaded HTML report, containing the
	// placeholders {repo}, {service_name}, and {timestamp}. Empty disables the link.
	TerrablobFileURLTemplate string
	// MoneyIntegrationGogoprotoPath is the repo-relative path (under a lifted GOPATH root) of a
	// gogoproto-generated directory that a specific Uber-internal proto package mis-generates,
	// requiring a one-off rename fixup after lifting. Empty disables the fixup. See
	// bazel.patchIncorrectMoneyIntegrationGogoprotoDir.
	MoneyIntegrationGogoprotoPath string
	// CodebasePkgPrefix is the package-path prefix used to distinguish the analyzed
	// organization's own code from third-party/stdlib dependencies -- e.g. finder's
	// inbound/outbound scanning and graph's codebase-size metrics only consider packages under
	// this prefix. Empty matches every package (no filtering), which is the right default for a
	// single-module OSS checkout with no internal/external package-path convention to exploit.
	// The monorepo fork sets this to "example.internal".
	CodebasePkgPrefix string
	// AdditionalHTTPClientTypes lists extra "pkgpath.TypeName" strings recognized as wrapped
	// HTTP clients for outbound detection, on top of the always-recognized "net/http.Client".
	// Empty recognizes only "net/http.Client". The monorepo fork adds
	// "example.internal/go-common.git/x/net/xhttp.Client".
	AdditionalHTTPClientTypes []string
	// ExtraExcludePackagePatterns lists additional graph.Config.ExcludePackagePatterns-style
	// regexes (matched against a package's full import path) to exclude from call-graph
	// construction and traversal, on top of graph.DefaultExcludePackagePatterns. Empty adds
	// nothing (only the generic OSS defaults apply). The monorepo fork populates this with its
	// own internal framework/glue/generated-code package-path patterns -- see
	// graph.Config.ExcludePackagePatterns's doc comment for the merge semantics.
	ExtraExcludePackagePatterns []string
	// ExcludePackagePatterns, when non-nil, fully replaces graph.DefaultExcludePackagePatterns as
	// the base exclude list (ExtraExcludePackagePatterns is still appended on top of whichever
	// base is in effect). nil (the default) leaves the base list as
	// graph.DefaultExcludePackagePatterns, unchanged. This exists because that base list assumes
	// the pattern's own package is always a *dependency* of the analyzed code, never the analyzed
	// code itself -- which breaks when the target under analysis IS one of those projects. For
	// example, jaegertracing/jaeger's own module path matches the base list's
	// "^github.com/jaegertracing(/.*)?$" entry, so analyzing Jaeger itself with the unmodified
	// base list silently drops its entire codebase from the call graph before analysis starts (no
	// crash, just an empty result) -- the same failure mode diagnosed for yarpc-go earlier in this
	// harness's development. A caller analyzing such a target should pass
	// graph.DefaultExcludePackagePatterns with the offending entry (entries) filtered out, not an
	// arbitrary hand-picked list, so every other exclusion the default list provides still applies.
	ExcludePackagePatterns []string
	// KafkaConsumerProxyPkgPath is the fully qualified package path of a Kafka consumer proxy
	// client's MessageHandlerFunc type, used by finder to detect Kafka message handlers as
	// inbound points. Empty disables Kafka handler detection.
	KafkaConsumerProxyPkgPath string
	// InfraPkgPrefixes lists package-path prefixes to skip when finding inbounds -- e.g. packages
	// owned by infra teams that are available to (and thus technically implement inbound
	// interfaces in) almost every service, making violations there non-actionable for individual
	// service owners. Empty skips nothing.
	InfraPkgPrefixes []string
	// KnownErrorConstructorFuncs lists fully qualified function names (e.g. "pkgpath.FuncName")
	// treated by the SCCP fail-close analyzer as definitely constructing a non-nil error, on top
	// of its built-in detection heuristics. Empty adds nothing.
	KnownErrorConstructorFuncs []string
	// SafeGoPkgPath is the fully qualified import path of a "safego"-shaped package (a Go(func())
	// fire-and-forget goroutine helper) that graph's safego enricher should recognize, on top of
	// its own features/safego test fixture. Empty uses graph.DefaultSafeGoPkgPath -- see
	// graph.Config.SafeGoPkgPath's doc comment for the wrapper-package recipe a company-internal
	// fork would use to point this at its own real internal safego-equivalent package.
	SafeGoPkgPath string
	// EnableGenericGRPCThriftDetection turns on detection of standard google.golang.org/grpc
	// (protoc-gen-go-grpc) and Apache Thrift (github.com/apache/thrift) client/server shapes, in
	// addition to the always-on YARPC-over-protobuf ("gogoproto/*") and YARPC/TChannel Thrift
	// ("thriftrw/*") detection. False (the default) leaves the monorepo fork's YARPC-based
	// detection byte-for-byte unchanged; an OSS fork analyzing repos that use vanilla grpc-go or
	// apache/thrift instead of YARPC should set this true.
	EnableGenericGRPCThriftDetection bool
	// GraphDisableContextRelaxServices lists service names for which graph.Config's "relaxed
	// context" call-tree feature should be force-disabled, as a workaround for services whose call
	// graph is large/complex enough that the feature causes analysis timeouts. Empty disables it
	// for no services (the feature runs everywhere it's otherwise enabled) -- the right OSS
	// default, since this is purely a per-service performance workaround, not a correctness
	// requirement. The monorepo fork populates this with the specific real service names it has
	// observed timing out.
	GraphDisableContextRelaxServices []string
	// BazelLoaderServices lists service names that should use DriverOptions.BazelLoader's fast
	// package-loading path instead of the default bazel.LiftGoPath path. Empty routes every
	// service through LiftGoPath (the right OSS default: BazelLoader is nil unless a caller
	// explicitly configures one, so this list only matters when BazelLoader is set). The monorepo
	// fork populates this with the specific real service names for which the fast path is known to
	// produce correct results (LiftGoPath remains the default/fallback for every other service).
	BazelLoaderServices []string
	// GrailHost is the base URL of the Grail-compatible service registry queried for the list of
	// all services/tiers and network groups. Empty is the right OSS default -- grail.New returns
	// an error if it isn't supplied, the same way it already requires USSOToken, rather than
	// silently defaulting to a real Uber host. The monorepo fork sets this to its real internal
	// Grail endpoint.
	GrailHost string
	// GrailRPCServiceName is the value sent in the "RPC-Service" header on every Grail request,
	// identifying which internal service Grail should authorize the request against. Empty (the
	// OSS default) omits the header entirely. The monorepo fork sets this to its real internal
	// Grail-frontend service identity.
	GrailRPCServiceName string
	// GenAIBaseURL is the OpenAI-compatible base URL used for the LLM analyzer. Empty leaves
	// genai.BaseURL's own default (a public OpenAI-compatible endpoint) in effect. The monorepo
	// fork sets this to its real internal GenAI gateway.
	GenAIBaseURL string
	// GenAIModel is the model name sent with chat completion requests. Empty leaves genai.Model's
	// own default (a public OpenAI model) in effect. The monorepo fork sets this to its real
	// internal Michelangelo GenAI model route.
	GenAIModel string
	// GenAIOrgID is the organization ID sent with chat completion requests. Empty (the OSS
	// default) sends no organization ID, appropriate for a plain OpenAI-compatible endpoint. The
	// monorepo fork sets this to its real internal org ID.
	GenAIOrgID string
	// DelegatorPackagePatterns lists regexps (regexp syntax, matched against a package's full
	// import path) identifying generated delegator packages: packages whose functions do nothing
	// but forward to the implementation they wrap (e.g. generated decorators or interceptors).
	// Such packages are typically also excluded from reported paths. Under a flow-based call-graph
	// flavor (vta, vta_strict) the delegator is the only callee the analysis resolves, so dropping
	// it would sever the path; the graph builder instead splices the delegator's callers to what
	// it delegates to (see graph.Config.DelegatorPackagePatterns). Empty (the OSS default) disables
	// splicing; type-based flavors never need it.
	DelegatorPackagePatterns []string
}

// Default returns a Config with the zero-value (all integrations disabled) settings.
func Default() Config {
	return Config{}
}
