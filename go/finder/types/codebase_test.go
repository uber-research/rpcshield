package types

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/uber-research/rpcshield/go/rpcshieldtest"
	"go.uber.org/zap"
	"golang.org/x/tools/go/packages"
)

func TestFindCodebasePkgs(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop().Sugar()

	pkg := rpcshieldtest.LoadrpcshieldDemoPackages()
	codebase, err := NewCodebase(logger, pkg.Entry, pkg.All, map[string]bool{})
	require.NoError(t, err)
	require.NotNil(t, codebase)
}

// Tests requiring Go SDK in runtime need a real `go` binary on PATH -- see
// finder/inbound_test.go's goSDKBinDir for the pattern this mirrors.
func TestMain(m *testing.M) {
	goBin := goSDKBinDir()
	os.Setenv("PATH", goBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if os.Getenv("GOCACHE") == "" {
		if dir, err := os.MkdirTemp("", "finder-types-gocache"); err == nil {
			os.Setenv("GOCACHE", dir)
		}
	}
	os.Exit(m.Run())
}

func goSDKBinDir() string {
	runfilesRoot := os.Getenv("RUNFILES_DIR")
	if runfilesRoot == "" {
		runfilesRoot = os.Getenv("TEST_SRCDIR")
	}
	if runfilesRoot != "" {
		if goBin := filepath.Join(runfilesRoot, "go_sdk", "bin", "go"); fileExists(goBin) {
			return filepath.Dir(goBin)
		}
	}
	return filepath.Join(runtime.GOROOT(), "bin")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func TestDedupPackages(t *testing.T) {
	t.Parallel()

	const (
		fooPath = "example.internal/example/foo"
		barPath = "example.internal/example/bar"
	)

	tests := []struct {
		name    string
		pkgs    []*packages.Package
		wantIDs []string
		wantErr string
	}{
		{
			name: "distinct packages are all kept",
			pkgs: []*packages.Package{
				{ID: "//example/foo:go_default_library", PkgPath: fooPath},
				{ID: "//example/bar:go_default_library", PkgPath: barPath},
			},
			wantIDs: []string{"//example/foo:go_default_library", "//example/bar:go_default_library"},
		},
		{
			name: "canonical target replaces an already-seen variant",
			pkgs: []*packages.Package{
				{ID: "//example/foo:sdui_trampoline_library", PkgPath: fooPath},
				{ID: "//example/foo:go_default_library", PkgPath: fooPath},
			},
			wantIDs: []string{"//example/foo:go_default_library"},
		},
		{
			name: "already-seen canonical target wins over a later variant",
			pkgs: []*packages.Package{
				{ID: "//example/foo:go_default_binary", PkgPath: fooPath},
				{ID: "//example/foo:sdui_trampoline_library", PkgPath: fooPath},
			},
			wantIDs: []string{"//example/foo:go_default_binary"},
		},
		{
			name: "two non-canonical duplicates are a genuine error",
			pkgs: []*packages.Package{
				{ID: "//example/foo:variant_a", PkgPath: fooPath},
				{ID: "//example/foo:variant_b", PkgPath: fooPath},
			},
			wantErr: `duplicate package found: "example.internal/example/foo" (//example/foo:variant_a vs //example/foo:variant_b)`,
		},
		{
			name: "two canonical duplicates are a genuine error",
			pkgs: []*packages.Package{
				{ID: "//example/foo:go_default_library", PkgPath: fooPath},
				{ID: "//other/foo:go_default_library", PkgPath: fooPath},
			},
			wantErr: `duplicate package found: "example.internal/example/foo"`,
		},
		{
			name: "non-_go_proto variant replaces already-seen _go_proto variant",
			pkgs: []*packages.Package{
				{ID: "//example/foo:foo_go_proto", PkgPath: fooPath},
				{ID: "//example/foo:foo", PkgPath: fooPath},
			},
			wantIDs: []string{"//example/foo:foo"},
		},
		{
			name: "already-seen non-_go_proto variant wins over a later _go_proto variant",
			pkgs: []*packages.Package{
				{ID: "//example/foo:foo", PkgPath: fooPath},
				{ID: "//example/foo:foo_go_proto", PkgPath: fooPath},
			},
			wantIDs: []string{"//example/foo:foo"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			deduped, pkgMap, err := DedupPackages(zap.NewNop().Sugar(), tt.pkgs)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				require.Nil(t, deduped)
				require.Nil(t, pkgMap)
				return
			}
			require.NoError(t, err)

			gotIDs := make([]string, 0, len(deduped))
			for _, pkg := range deduped {
				gotIDs = append(gotIDs, pkg.ID)
			}
			require.Equal(t, tt.wantIDs, gotIDs)

			require.Len(t, pkgMap, len(tt.wantIDs))
			for _, pkg := range deduped {
				require.Same(t, pkg, pkgMap[pkg.PkgPath])
			}
		})
	}
}
