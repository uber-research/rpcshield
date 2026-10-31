package constant

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAnalyzerKind_Codec(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		raw      string
		expected AnalyzerKind
	}{
		{raw: "Unknown", expected: Unknown},
		{raw: "AST", expected: AST},
		{raw: "SSA", expected: SSA},
		{raw: "LLM", expected: LLM},
	}
	for _, tc := range testcases {
		t.Run(tc.raw, func(t *testing.T) {
			t.Parallel()

			var analyzerKind AnalyzerKind
			err := json.Unmarshal([]byte(`"`+tc.raw+`"`), &analyzerKind)
			require.NoError(t, err)
			require.Equal(t, tc.expected, analyzerKind)
		})
	}
}

func TestAnalyzerKind_Invalid(t *testing.T) {
	t.Parallel()

	invalids := []string{"invalid", "xyz"}

	for _, invalid := range invalids {
		t.Run(invalid, func(t *testing.T) {
			t.Parallel()

			var analyzerKind AnalyzerKind
			err := json.Unmarshal([]byte(`"`+invalid+`"`), &analyzerKind)
			require.Error(t, err)
		})
	}
}

func TestFailness_Codec(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		raw      string
		expected Failness
	}{
		{raw: "FailUnknown", expected: FailUnknown},
		{raw: "FailOpen", expected: FailOpen},
		{raw: "FailClose", expected: FailClose},
	}

	for _, tc := range testcases {
		t.Run(tc.raw, func(t *testing.T) {
			t.Parallel()

			var failness Failness
			err := json.Unmarshal([]byte(`"`+tc.raw+`"`), &failness)
			require.NoError(t, err)
			require.Equal(t, tc.expected, failness)
		})
	}
}

func TestFailness_Invalid(t *testing.T) {
	t.Parallel()

	invalids := []string{"invalid", ""}
	for _, invalid := range invalids {
		t.Run(invalid, func(t *testing.T) {
			t.Parallel()

			var failness Failness
			err := json.Unmarshal([]byte(`"`+invalid+`"`), &failness)
			require.Error(t, err)
		})
	}
}

func TestIsRPCGeneratedPkg(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		pkgPath  string
		expected bool
	}{
		{pkgPath: "github.com/uber-research/rpcshield/go", expected: false},
		{pkgPath: "gogoproto/github.com/uber-research/rpcshield/go/constant", expected: true},
		{pkgPath: "thriftrw/github.com/uber-research/rpcshield/go/finder/servicemapping", expected: true},
	}

	for _, tc := range testcases {
		t.Run(tc.pkgPath, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tc.expected, IsRPCGeneratedPkg(tc.pkgPath))
		})
	}
}

// TestIsThriftSubpackage tests the IsThriftSubpackage function
func TestIsThriftSubpackage(t *testing.T) {
	tests := []struct {
		name    string
		pkgPath string
		want    bool
	}{
		{
			name:    "thriftrw package with client suffix",
			pkgPath: "thriftrw/some/package/client",
			want:    true,
		},
		{
			name:    "thriftrw package with server suffix",
			pkgPath: "thriftrw/some/package/server",
			want:    true,
		},
		{
			name:    "thriftrw package with fx suffix",
			pkgPath: "thriftrw/some/package/fx",
			want:    true,
		},
		{
			name:    "thriftrw package without valid suffix",
			pkgPath: "thriftrw/some/package",
			want:    false,
		},
		{
			name:    "non-thriftrw package with client suffix",
			pkgPath: "other/some/package/client",
			want:    false,
		},
		{
			name:    "empty package path",
			pkgPath: "",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := IsThriftSubpackage(tt.pkgPath); got != tt.want {
				t.Errorf("IsThriftSubpackage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildTBFileURL(t *testing.T) {
	t.Parallel()

	const tmpl = "https://terrablob-gateway.example.com/prod/progsys/rpcshield/{repo}/{service_name}/{timestamp}/"

	got := BuildTBFileURL(tmpl, "example-repo", "ads-gateway", "2025-04-10T00:02:57Z")
	want := "https://terrablob-gateway.example.com/prod/progsys/rpcshield/example-repo/ads-gateway/2025-04-10T00%3A02%3A57Z/"
	require.Equal(t, want, got)
}

func TestBuildTBFileURL_EmptyTemplateDisabled(t *testing.T) {
	t.Parallel()

	require.Equal(t, "", BuildTBFileURL("", "example-repo", "ads-gateway", "2025-04-10T00:02:57Z"))
}
