package grail

import (
	"bytes"
	"context"
	_ "embed" // Required for embedfs to work.
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"go.uber.org/zap"
)

//go:embed query_all.txt
var query []byte

//go:embed query_active_go.txt
var queryActiveGo []byte

//go:embed query_network_group.txt
var queryNetworkGroup []byte

//go:embed query_namespace_burst_strategy.txt
var queryNamespaceBurstStrategy []byte

const (
	// GoCodeGitURI is the git URI for the Go monorepo.
	GoCodeGitURI = "gitolite@example.internal:go-code"
	// JavaCodeGitURI is the git URI for the Java monorepo.
	JavaCodeGitURI = "gitolite@example.internal:java-code"
	// OvercommitStr is the string for the overcommit namespace.
	OvercommitStr = "OVERCOMMIT"
	// BreakBeforeMakeStr is the string for the break before make burst strategy.
	BreakBeforeMakeStr = "BURST_STRATEGY_BREAK_BEFORE_MAKE"
	// BreakBeforeMakeStr is the string for the break before make burst strategy.
	MakeBeforeBreakStr = "BURST_STRATEGY_MAKE_BEFORE_BREAK"
	// BurstStrategyAllEnvironments is the string for the all environments burst strategy.
	BurstStrategyAllEnvironments = "_ALL_ENVIRONMENTS"
	// BurstStrategySomeEnvironments is the string for some environments burst strategy.
	BurstStrategySomeEnvironments = "_SOME_ENVIRONMENTS"
	// BurstStrategyNoEnvironment is the string for the no environment burst strategy.
	BurstStrategyNoEnvironment = "_NO_ENVIRONMENT"
)

// Options is the configuration for the Grail client.
type Options struct {
	// Host is the host of the Grail service. Required -- New returns an error if it's empty,
	// since there is no generic default Grail-compatible host to fall back to.
	Host string
	// RPCServiceName is the value sent in the "RPC-Service" header on every request, identifying
	// which internal service Grail should authorize the request against. Empty omits the header.
	RPCServiceName string
	// Logger is the optional logger.
	Logger *zap.SugaredLogger
	// USSOToken is the USSO token to authenticate with Grail.
	USSOToken string
	// GitURI is the git URI (e.g. "gitolite@example.internal:go-code") that AllActiveGoServices
	// filters on to find services deployed from this monorepo. Required only for
	// AllActiveGoServices -- New does not validate it, since other Grail queries don't need it.
	GitURI string
}

// Grail is the client for the Grail service.
type Grail struct {
	opts Options
}

// New creates a new Grail client.
func New(opts *Options) (*Grail, error) {
	if opts == nil {
		opts = &Options{}
	}
	if opts.Host == "" {
		return nil, fmt.Errorf("missing Grail host")
	}
	if opts.Logger == nil {
		opts.Logger = zap.NewNop().Sugar()
	}
	if opts.USSOToken == "" {
		return nil, fmt.Errorf("missing USSO token")
	}
	return &Grail{opts: *opts}, nil
}

// Service contains the name and its affiliated information.
type Service struct {
	// Name is the service name.
	Name string `json:"name"`
	// Tier is the tier of the service (1-5).
	Tier int `json:"tier"`
	// GitURI is the git URI that this service is deployed from.
	GitURI string `json:"git_uri"`
	// HasOvercommit indicates if any environment for this service has namespace=overcommit.
	HasOvercommit bool `json:"has_overcommit"`
	// BreakBeforeMakeBurstStrategy indicates the status of BURST_STRATEGY_BREAK_BEFORE_MAKE burst strategy for this service.
	BreakBeforeMakeBurstStrategy string `json:"break_before_make_burst_strategy"`
	// MakeBeforeBreakBurstStrategy indicates the status of BURST_STRATEGY_MAKE_BEFORE_BREAK burst strategy for this service.
	MakeBeforeBreakBurstStrategy string `json:"make_before_break_burst_strategy"`
}

// AllServices returns the list of all services with namespace and burst_strategy information enriched.
func (g *Grail) AllServices(ctx context.Context) ([]Service, error) {
	services, err := doRequest[[]Service](ctx, g.opts.Host, g.opts.RPCServiceName, g.opts.USSOToken, query)
	if err != nil {
		return nil, fmt.Errorf("query grail: %w", err)
	}
	g.opts.Logger.Infow("Fetched Go services from Grail", "num_services", len(services))

	// cff-demo is our dummy service in test code, which is not really deployed in production.
	// For testing purposes we add a fake high tier to it such that all of its outbound calls will
	// be considered cross-tier.
	services = append(services, Service{Name: "cff-demo", Tier: -1})

	// Enrich services with namespace and burst_strategy information
	enrichedServices, err := g.enrichWithNamespaceBurstStrategy(ctx, services)
	if err != nil {
		g.opts.Logger.Warnw("Failed to enrich services with namespace burst strategy, continuing with non-enriched data", "error", err)
		return services, nil
	}
	return enrichedServices, nil
}

// AllActiveGoServices returns the list of all active Go services.
// Active Go services are those that are deployed in production with active compute capacity.
func (g *Grail) AllActiveGoServices(ctx context.Context) ([]Service, error) {
	if g.opts.GitURI == "" {
		return nil, fmt.Errorf("missing Grail git URI")
	}
	q := bytes.Replace(queryActiveGo, []byte("{{GIT_URI}}"), []byte(g.opts.GitURI), 1)
	services, err := doRequest[[]Service](ctx, g.opts.Host, g.opts.RPCServiceName, g.opts.USSOToken, q)
	if err != nil {
		return nil, fmt.Errorf("query grail active go services: %w", err)
	}
	g.opts.Logger.Infow("Fetched active Go services from Grail", "num_services", len(services))
	return services, nil
}

// NetworkGroup marks the network groups and their affiliated service names.
type NetworkGroup struct {
	// Group is the network group name.
	Group string `json:"group"`
	// ServiceNames is the list of service names in the network group.
	ServiceNames []string `json:"service_names"`
}

// AllNetworkGroups returns the list of all network groups.
func (g *Grail) AllNetworkGroups(ctx context.Context) ([]NetworkGroup, error) {
	groups, err := doRequest[[]NetworkGroup](ctx, g.opts.Host, g.opts.RPCServiceName, g.opts.USSOToken, queryNetworkGroup)
	if err != nil {
		return nil, fmt.Errorf("query grail network groups: %w", err)
	}
	// The grail query for network group returns the group id in the form of
	// "swn::trafficgroup:xxx", or "swn::discovery:xxx", since it is not easy to directly do
	// cleanups in the Grail query. Here we do a post-processing to clean up the group id.
	for i := range groups {
		groups[i].Group = groups[i].Group[strings.LastIndex(groups[i].Group, ":")+1:]
	}
	g.opts.Logger.Infow("Fetched network groups from Grail", "num_groups", len(groups))
	return groups, nil
}

// namespaceBurstStrategyRecord represents a single record from the namespace/burst_strategy query.
type namespaceBurstStrategyRecord struct {
	ServiceName     string `json:"service_name"`
	EnvironmentName string `json:"environment_name"`
	EnvironmentType string `json:"environment_type"`
	Namespace       string `json:"namespace"`
	BurstStrategy   string `json:"burst_strategy"`
}

// enrichWithNamespaceBurstStrategy enriches the provided services with HasOvercommit and HasBreakBeforeMake flags.
// It queries Grail for namespace and burst_strategy information across all environments for each service.
func (g *Grail) enrichWithNamespaceBurstStrategy(ctx context.Context, services []Service) ([]Service, error) {
	// Fetch raw data from Grail
	records, err := doRequest[[]namespaceBurstStrategyRecord](ctx, g.opts.Host, g.opts.RPCServiceName, g.opts.USSOToken, queryNamespaceBurstStrategy)
	if err != nil {
		return nil, fmt.Errorf("query grail namespace burst strategy: %w", err)
	}
	g.opts.Logger.Infow("Fetched namespace burst strategy data from Grail", "num_records", len(records))

	// Build a map of service name to its namespace/burst_strategy flags
	serviceFlags := make(map[string]struct {
		hasOvercommit                bool
		breakBeforeMakeBurstStrategy string
		makeBeforeBreakBurstStrategy string
	})

	serviceBurstStrategiesMap := make(map[string][]string)
	for _, record := range records {
		// Get the current flags for the service if it exists, all flags are false by default.
		flags := serviceFlags[record.ServiceName]
		if strings.ToUpper(record.Namespace) == OvercommitStr {
			flags.hasOvercommit = true
		}

		// Collect all the burst strategies for each service across all environments.
		// Strategy explicitly marked as make-before-break should be treated as make-before-break,
		// everything else should be treated as break-before-make.
		strategy := BreakBeforeMakeStr
		if strings.ToUpper(record.BurstStrategy) == MakeBeforeBreakStr {
			strategy = MakeBeforeBreakStr
		}
		serviceBurstStrategiesMap[record.ServiceName] = append(serviceBurstStrategiesMap[record.ServiceName], strategy)
		serviceFlags[record.ServiceName] = flags
	}

	// Handle the burst strategy based for a service across all environments on the following rules:
	// 1. If same burst strategy X (where X is MBB or BBM) is set for all environments of a service, then set the burst strategy to X_ALL_ENVIRONMENTS.
	// 2. If different burst strategy X and Y are set for different environments of a service, then set the burst strategy to X_SOME_ENVIRONMENTS and Y_SOME_ENVIRONMENTS.
	// 3. If X burst strategy is not set for a service, then set the burst strategy to X_NO_ENVIRONMENT.
	for serviceName, burstStrategies := range serviceBurstStrategiesMap {
		makeBeforeBreakCount := 0
		breakBeforeMakeCount := 0
		for _, strategy := range burstStrategies {
			if strategy == MakeBeforeBreakStr {
				makeBeforeBreakCount++
			} else {
				breakBeforeMakeCount++
			}
		}

		flags, ok := serviceFlags[serviceName]
		if !ok {
			// This should never happen, but we add a check to be safe.
			return nil, fmt.Errorf("service %s not found in serviceFlags", serviceName)
		}

		if makeBeforeBreakCount == len(burstStrategies) {
			flags.makeBeforeBreakBurstStrategy = MakeBeforeBreakStr + BurstStrategyAllEnvironments
		} else if breakBeforeMakeCount == len(burstStrategies) {
			flags.breakBeforeMakeBurstStrategy = BreakBeforeMakeStr + BurstStrategyAllEnvironments
		}
		if makeBeforeBreakCount > 0 && makeBeforeBreakCount < len(burstStrategies) {
			flags.makeBeforeBreakBurstStrategy = MakeBeforeBreakStr + BurstStrategySomeEnvironments
		}
		if breakBeforeMakeCount > 0 && breakBeforeMakeCount < len(burstStrategies) {
			flags.breakBeforeMakeBurstStrategy = BreakBeforeMakeStr + BurstStrategySomeEnvironments
		}
		if makeBeforeBreakCount == 0 {
			flags.makeBeforeBreakBurstStrategy = MakeBeforeBreakStr + BurstStrategyNoEnvironment
		}
		if breakBeforeMakeCount == 0 {
			flags.breakBeforeMakeBurstStrategy = BreakBeforeMakeStr + BurstStrategyNoEnvironment
		}
		serviceFlags[serviceName] = flags
	}

	// Enrich the services with the flags
	enrichedServices := make([]Service, len(services))
	for i, service := range services {
		enrichedServices[i] = service
		if flags, ok := serviceFlags[service.Name]; ok {
			enrichedServices[i].HasOvercommit = flags.hasOvercommit
			enrichedServices[i].BreakBeforeMakeBurstStrategy = flags.breakBeforeMakeBurstStrategy
			enrichedServices[i].MakeBeforeBreakBurstStrategy = flags.makeBeforeBreakBurstStrategy
		}
	}

	g.opts.Logger.Infow("Enriched services with namespace burst strategy flags",
		"num_services_with_overcommit", countServicesWithFlag(enrichedServices, func(s Service) bool { return s.HasOvercommit }),
		"num_services_with_break_before_make_all_environments", countServicesWithFlag(enrichedServices, func(s Service) bool {
			return s.BreakBeforeMakeBurstStrategy == BreakBeforeMakeStr+BurstStrategyAllEnvironments
		}),
		"num_services_with_make_before_break_all_environments", countServicesWithFlag(enrichedServices, func(s Service) bool {
			return s.MakeBeforeBreakBurstStrategy == MakeBeforeBreakStr+BurstStrategyAllEnvironments
		}),
		"num_services_with_break_before_make_some_environments", countServicesWithFlag(enrichedServices, func(s Service) bool {
			return s.BreakBeforeMakeBurstStrategy == BreakBeforeMakeStr+BurstStrategySomeEnvironments
		}),
		"num_services_with_make_before_break_some_environments", countServicesWithFlag(enrichedServices, func(s Service) bool {
			return s.MakeBeforeBreakBurstStrategy == MakeBeforeBreakStr+BurstStrategySomeEnvironments
		}),
		"num_services_with_break_before_make_no_environment", countServicesWithFlag(enrichedServices, func(s Service) bool {
			return s.BreakBeforeMakeBurstStrategy == BreakBeforeMakeStr+BurstStrategyNoEnvironment
		}),
		"num_services_with_make_before_break_no_environment", countServicesWithFlag(enrichedServices, func(s Service) bool {
			return s.MakeBeforeBreakBurstStrategy == MakeBeforeBreakStr+BurstStrategyNoEnvironment
		}))

	return enrichedServices, nil
}

func countServicesWithFlag(services []Service, predicate func(Service) bool) int {
	count := 0
	for _, s := range services {
		if predicate(s) {
			count++
		}
	}
	return count
}

func doRequest[T any](ctx context.Context, host string, rpcServiceName string, ussoToken string, query []byte) (T, error) {
	var zeroT T

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/api/compute/yql", host), bytes.NewBuffer(query))
	if err != nil {
		return zeroT, fmt.Errorf("create grail http request: %w", err)
	}

	if rpcServiceName != "" {
		req.Header.Set("RPC-Service", rpcServiceName)
	}
	req.Header.Set("RPC-Caller", "rpcshield")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+ussoToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return zeroT, fmt.Errorf("send grail request: %w", err)
	}
	defer resp.Body.Close()

	return decodeGrailResponse[T](resp.Body)
}

// decodeGrailResponse decodes the grail response from the reader.
func decodeGrailResponse[T any](reader io.Reader) (T, error) {
	var zeroT T

	var data struct {
		Result T `json:"result"`
	}
	if err := json.NewDecoder(reader).Decode(&data); err != nil {
		return zeroT, fmt.Errorf("decodeGrailResponse grail services: %w", err)
	}

	return data.Result, nil
}
