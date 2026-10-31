package graph

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

func TestEGEnrich(t *testing.T) {
	t.Parallel()

	pathSlice := []string{"exampleapps", "errgroup", "errgroup-anal"}
	loadPath := "github.com/uber-research/rpcshield/go/exampleapps/errgroup"

	b, _, ssaProg := loadAndInitBuilder(t, pathSlice, loadPath)

	// Set b.hasMain = true to get RTA graph.
	b.hasMain = true
	// find CodeUnderTest function using ssautil
	codeUnderTest := map[*ssa.Function]struct{}{}

	for fn := range ssautil.AllFunctions(ssaProg) {
		if strings.HasPrefix(fn.Name(), "AUniqueName") && !strings.Contains(fn.Name(), "$") {
			codeUnderTest[fn] = struct{}{}
		}
	}

	type callInfo struct {
		goCalls   int
		waitCalls int
	}

	expected := map[string]map[string]callInfo{
		"AUniqueNameOneEg": {
			"v1": callInfo{
				goCalls:   3,
				waitCalls: 1},
		},
		"AUniqueNameOneEgStatic": {
			"v1": callInfo{
				goCalls:   2,
				waitCalls: 1,
			},
		},
		"AUniqueNameOneEgNonStatic": {},
		"AUniqueNameMissingWait":    {},
		"AUniqueNameMissingGo":      {},
		"AUniqueNameBranching": {
			"v1": callInfo{
				goCalls:   2,
				waitCalls: 1,
			},
		},
		"AUniqueNamePhi":       {},
		"AUniqueNameOverwrite": {},

		"AUniqueNameTwoEg": {
			"v1": callInfo{
				goCalls:   1,
				waitCalls: 1,
			},
			"v2": callInfo{
				goCalls:   2,
				waitCalls: 1,
			},
		},

		"AUniqueNameReturnEscape": {},

		"AUniqueNameChanEscape": {},
		"AUniqueNameMapEscape":  {},
		"AUniqueNameSafeGroup": {
			"v1": callInfo{
				goCalls:   1,
				waitCalls: 1,
			},
		},
		"AUniqueNameWorkGroup": {
			"v1": callInfo{
				goCalls:   1,
				waitCalls: 1,
			},
		},
		"AUniqueNameCEWorkGroup2": {
			"v1": callInfo{
				goCalls:   1,
				waitCalls: 1,
			},
		},
		"AUniqueNameOPWorkGroup": {
			"v1": callInfo{
				goCalls:   1,
				waitCalls: 1,
			},
		},
		"AUniqueNameThrottledEG": {
			"v1": callInfo{
				goCalls:   1,
				waitCalls: 1,
			},
		},
		"AUniqueNameTPPSafeErrGroup": {
			"v1": callInfo{
				goCalls:   1,
				waitCalls: 1,
			},
		},
		"AUniqueNameU4BEG": {
			"v1": callInfo{
				goCalls:   1,
				waitCalls: 1,
			},
		},
		"AUniqueNameTimedGroup": {
			"v1": callInfo{
				goCalls:   1,
				waitCalls: 1,
			},
		},
		"AUniqueNameLocationStore": {}, // Todo: add WaitContext from example.internal/rt/service-0026/util
		"AUniqueNameViaInterface": {
			"v1": callInfo{
				goCalls:   1,
				waitCalls: 1,
			},
		},
	}
	// Get callgraph
	cg, err := b.getCG()
	require.NoError(t, err)
	errGroupTypes, errGroupPkgs := b.discoverAllErrgroupTypes(b.ssaProg)
	for f := range codeUnderTest {
		observed, _ := b.getSafeErrGroupUsageInfo(f, errGroupTypes, errGroupPkgs)
		expected := expected[f.Name()]
		require.Equal(t, len(expected), len(observed))
		// Each observed should be in one of the expected values
		for _, usage := range observed {
			found := false
			for _, e := range expected {
				if len(usage.goCalls) == e.goCalls && len(usage.waitCalls) == e.waitCalls {
					found = true
					break
				}
			}
			require.True(t, found, "Expected %v, got %v", expected, usage)
		}
	}

	// Now enrich the call graph.
	err = b.enrichCallGraphWithErrgroup(cg)
	require.NoError(t, err)
	cgChecker(cg, true, true)
}
